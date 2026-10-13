// SPDX-License-Identifier: GPL-2.0-only
/*
 * kexec_file loader for EFI images (EFI stub kernels, EFI zboot images, ...)
 *
 * Instead of jumping to the raw kernel entry point, run the image's PE/COFF
 * entry point at load time under a minimal EFI boot services implementation
 * (the efiloader crate, see kexec_efi_glue.rs), up to the point where it calls
 * ExitBootServices(). At that point, the image's register state is captured,
 * and at kexec reboot time, the image is resumed as if ExitBootServices()
 * returned successfully, so that it can proceed to enter the new kernel.
 *
 * All memory that the EFI image may allocate from is carved out of a single
 * physically contiguous region that is allocated at load time, and identity
 * mapped while the image runs. This region remains untouched until the kexec
 * reboot, so no relocation is needed: the kexec image has no segments, only
 * an entry point, which is a trampoline inside the region.
 */

#define pr_fmt(fmt)	"kexec_efi: " fmt

#include <linux/acpi.h>
#include <linux/efi.h>
#include <linux/gfp.h>
#include <linux/kexec.h>
#include <linux/kthread.h>
#include <linux/libfdt.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/pe.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include <asm/cacheflush.h>
#include <asm/cpufeature.h>
#include <asm/daifflags.h>
#include <asm/kexec_efi.h>
#include <asm/mmu_context.h>
#include <asm/neon.h>
#include <asm/sysreg.h>
#include <asm/virt.h>

/* Keep in sync with kexec_efi_glue.rs */
#define EFI_KEXEC_REGION_ALLOCATABLE	BIT(0)

struct efi_kexec_region {
	u64	base;
	u64	size;
	u64	attr;
	u32	type;
	u32	flags;
};

struct efi_kexec_cfgtable {
	efi_guid_t	guid;
	u64		table;
};

struct efi_kexec_params {
	const void	*image;
	unsigned long	image_size;
	const void	*initrd;
	unsigned long	initrd_size;
	const char	*cmdline;
	unsigned long	cmdline_size;

	const struct efi_kexec_region	*regions;
	unsigned long			nr_regions;
	const struct efi_kexec_cfgtable	*tables;
	unsigned long			nr_tables;

	u64		fw_runtime;
	u64		stack_top;
	u64		systab;
};

/*
 * Per-image state, hung off kimage::image_loader_data. The region is laid out
 * as follows:
 *
 *   [ stack | page tables | resume block, trampoline, tables |
 *     memory managed by EFI ... ]
 */
struct kexec_efi_data {
	struct page		*pages;
	unsigned long		nr_pages;
	phys_addr_t		base;
	size_t			size;

	/* the stack the image runs on at load time and after resume */
	phys_addr_t		stack_top;

	/* bump allocator for page tables, following the stack */
	phys_addr_t		pt_next;
	phys_addr_t		pt_end;
	phys_addr_t		ttbr0;

	/* start of the memory that the EFI runtime may allocate from */
	phys_addr_t		alloc_start;

	struct efi_kexec_resume	*resume;	/* linear map alias */
	phys_addr_t		resume_pa;
	phys_addr_t		trampoline_pa;
};

#define PT_POOL_SIZE		SZ_64K
#define RESUME_AREA_SIZE	SZ_4K

/* The image being loaded - kexec_file_load() calls are serialized */
static struct kexec_efi_data *efi_kexec_cur;

void *efi_kexec_resume_block(void)
{
	return efi_kexec_cur->resume;
}

/*
 * Rust heap for the efiloader crate. GFP_ATOMIC is used because the EFI
 * runtime runs with preemption disabled. kmalloc() returns naturally aligned
 * memory for power-of-2 sizes, which takes care of larger alignments.
 */
static size_t efiloader_alloc_size(size_t size, size_t align)
{
	if (align > ARCH_KMALLOC_MINALIGN)
		size = roundup_pow_of_two(max(size, align));
	return size;
}

void *efiloader_alloc(size_t size, size_t align, bool zero)
{
	return kmalloc(efiloader_alloc_size(size, align),
		       GFP_ATOMIC | (zero ? __GFP_ZERO : 0));
}

void *efiloader_realloc(void *ptr, size_t new_size, size_t align)
{
	return krealloc(ptr, efiloader_alloc_size(new_size, align), GFP_ATOMIC);
}

void efiloader_free(void *ptr)
{
	kfree(ptr);
}

/*
 * Identity map of the region: 4 KiB granule, 48-bit input addresses, 4 levels,
 * using 2 MiB blocks. The tables live in the region so that they are still
 * available at resume time. Memory attribute indexes follow the kernel's MAIR
 * layout, which is installed again at resume time.
 */
#define IDMAP_VA_BITS		48
#define IDMAP_ENTRIES		(SZ_4K / sizeof(u64))

#define DESC_VALID		BIT(0)
#define DESC_TABLE		(BIT(1) | DESC_VALID)
#define DESC_BLOCK		DESC_VALID
#define DESC_ATTRIDX(i)		((u64)(i) << 2)
#define DESC_AP1		BIT(6)
#define DESC_SH_INNER		(3UL << 8)
#define DESC_AF			BIT(10)
#define DESC_NG			BIT(11)

/*
 * While the image runs, the kernel's MMU configuration is in effect, which may
 * use permission indirection (FEAT_S1PIE) and LPA2 (where descriptor bits
 * [9:8] hold output address bits rather than the shareability). So derive the
 * block descriptor attributes from the kernel's own PAGE_KERNEL_EXEC, but
 * without the BTI guarded page attribute: the image was not necessarily built
 * with BTI landing pads, and will not run from guarded pages after resume.
 */
static u64 idmap_block_attrs(void)
{
	return (pgprot_val(PAGE_KERNEL_EXEC) &
		~(PTE_TYPE_MASK | PTE_ADDR_HIGH | PTE_GP)) |
	       PMD_TYPE_SECT | PTE_NG;
}

static u64 *pt_alloc(struct kexec_efi_data *d, phys_addr_t *pa)
{
	u64 *p;

	if (d->pt_next >= d->pt_end)
		return NULL;

	*pa = d->pt_next;
	d->pt_next += SZ_4K;
	p = phys_to_virt(*pa);
	memset(p, 0, SZ_4K);
	return p;
}

static u64 *pt_next_level(struct kexec_efi_data *d, u64 *entry)
{
	phys_addr_t pa;
	u64 *p;

	if (*entry & DESC_VALID)
		return phys_to_virt(*entry & GENMASK_ULL(47, 12));

	p = pt_alloc(d, &pa);
	if (p)
		*entry = pa | DESC_TABLE;
	return p;
}

/* Map [start, end) with 2 MiB blocks - both must be 2 MiB aligned */
static int idmap_map_range(struct kexec_efi_data *d, u64 start, u64 end)
{
	u64 *pgd = phys_to_virt(d->ttbr0);

	for (u64 addr = start; addr < end; addr += SZ_2M) {
		u64 *pud, *pmd;

		pud = pt_next_level(d, &pgd[(addr >> 39) % IDMAP_ENTRIES]);
		if (!pud)
			return -ENOMEM;
		pmd = pt_next_level(d, &pud[(addr >> 30) % IDMAP_ENTRIES]);
		if (!pmd)
			return -ENOMEM;
		pmd[(addr >> 21) % IDMAP_ENTRIES] = addr | idmap_block_attrs();
	}
	return 0;
}

/*
 * Once the image is done running under the kernel's MMU configuration, rewrite
 * the block descriptors for the configuration used at resume time, which uses
 * neither permission indirection nor LPA2: normal memory, inner shareable,
 * accessed, read/write and executable. If resuming at EL2 without VHE, where
 * there is only a single privilege level, AP[1] is RES1.
 */
static void idmap_prepare_for_resume(struct kexec_efi_data *d)
{
	u64 attrs = DESC_BLOCK | DESC_ATTRIDX(MT_NORMAL) | DESC_SH_INNER |
		    DESC_AF | DESC_NG | (is_hyp_nvhe() ? DESC_AP1 : 0);

	for (phys_addr_t pa = d->ttbr0; pa < d->pt_next; pa += SZ_4K) {
		u64 *t = phys_to_virt(pa);

		for (int i = 0; i < IDMAP_ENTRIES; i++)
			if ((t[i] & (BIT(1) | DESC_VALID)) == DESC_BLOCK)
				t[i] = (t[i] & GENMASK_ULL(47, 21)) | attrs;
	}
}

static u64 idmap_ips(void)
{
	u64 mmfr0 = read_sanitised_ftr_reg(SYS_ID_AA64MMFR0_EL1);
	u64 parange = cpuid_feature_extract_unsigned_field(mmfr0,
				ID_AA64MMFR0_EL1_PARANGE_SHIFT);

	/* the identity map only covers 48 bits of input address space */
	return min_t(u64, parange, ID_AA64MMFR0_EL1_PARANGE_48);
}

/*
 * TCR values for the resume trampoline. The image may have signed return
 * addresses at load time, and the position of the PAC field in those depends on
 * T0SZ and TBI0. So these must match the load time configuration: the identity
 * map is installed with the same T0SZ, and TBI0 is set, like in the kernel's
 * own TCR value.
 */

/* TCR value in the EL1 layout, which is also used by EL2 with HCR_EL2.E2H set */
static u64 idmap_tcr_el1(void)
{
	return TCR_T0SZ(IDMAP_VA_BITS) | TCR_IRGN0_WBWA | TCR_ORGN0_WBWA |
	       TCR_SH0_INNER | TCR_TG0_4K | TCR_EPD1_MASK | TCR_TBI0 |
	       (idmap_ips() << TCR_IPS_SHIFT);
}

/* TCR_EL2 value in the non-VHE layout */
static u64 idmap_tcr_el2(void)
{
	return TCR_T0SZ(IDMAP_VA_BITS) | TCR_IRGN0_WBWA | TCR_ORGN0_WBWA |
	       TCR_SH0_INNER | TCR_TG0_4K | TCR_EL2_RES1 | TCR_EL2_TBI |
	       (idmap_ips() << TCR_EL2_PS_SHIFT);
}

#define RESUME_SCTLR_EL1	(INIT_SCTLR_EL1_MMU_OFF | SCTLR_ELx_M | \
				 SCTLR_ELx_C | SCTLR_ELx_I | SCTLR_ELx_SA)
#define RESUME_SCTLR_EL2	(SCTLR_EL2_RES1 | ENDIAN_SET_EL2 | SCTLR_ELx_M | \
				 SCTLR_ELx_C | SCTLR_ELx_I | SCTLR_ELx_SA)

static bool is_usable_ram(const efi_memory_desc_t *md)
{
	if (md->attribute & EFI_MEMORY_RUNTIME)
		return false;

	switch (md->type) {
	case EFI_LOADER_CODE:
	case EFI_LOADER_DATA:
	case EFI_BOOT_SERVICES_CODE:
	case EFI_BOOT_SERVICES_DATA:
	case EFI_CONVENTIONAL_MEMORY:
	case EFI_PERSISTENT_MEMORY:
		return true;
	}
	return false;
}

/* Firmware owned memory that may hold tables the image may want to read */
static bool is_firmware_memory(const efi_memory_desc_t *md)
{
	switch (md->type) {
	case EFI_RUNTIME_SERVICES_CODE:
	case EFI_RUNTIME_SERVICES_DATA:
	case EFI_ACPI_RECLAIM_MEMORY:
	case EFI_ACPI_MEMORY_NVS:
		return md->attribute & EFI_MEMORY_WB;
	}
	return false;
}

static int add_region(struct efi_kexec_region **r, unsigned long *n,
		      unsigned long *max, u64 base, u64 size, u32 type,
		      u64 attr, u32 flags)
{
	if (!size)
		return 0;
	if (*n == *max) {
		struct efi_kexec_region *p;

		*max = *max ? 2 * *max : 64;
		p = krealloc_array(*r, *max, sizeof(**r), GFP_KERNEL);
		if (!p)
			return -ENOMEM;
		*r = p;
	}
	(*r)[(*n)++] = (struct efi_kexec_region){
		.base = base, .size = size, .type = type, .attr = attr,
		.flags = flags,
	};
	return 0;
}

/*
 * Describe all of memory to the EFI runtime, based on the firmware's memory
 * map: memory that is in use by this kernel becomes EfiBootServicesData, so
 * that the incoming kernel will treat it as free memory after the image calls
 * ExitBootServices(), except for the region we allocated, which the EFI
 * runtime may allocate from. All other entries are passed on unmodified, so
 * that the incoming kernel can use the firmware's runtime services, ACPI
 * tables etc. just like the current one.
 *
 * The region may span several entries of the firmware's memory map, so clip
 * each usable entry against the region's static prefix (page tables, resume
 * trampoline etc, which are described as EfiBootServicesData as well) and
 * against the part that the EFI runtime may allocate from.
 */
static int build_regions(struct kexec_efi_data *d,
			 struct efi_kexec_region **regions,
			 unsigned long *nr_regions)
{
	u64 astart = d->alloc_start, aend = d->base + d->size;
	struct efi_kexec_region *r = NULL;
	unsigned long n = 0, max = 0;
	efi_memory_desc_t *md;
	int ret = 0;

	for_each_efi_memory_desc(md) {
		u64 start = md->phys_addr;
		u64 end = start + (md->num_pages << EFI_PAGE_SHIFT);
		u64 lo, hi;

		if (!is_usable_ram(md)) {
			ret = add_region(&r, &n, &max, start, end - start,
					 md->type, md->attribute, 0);
			if (ret)
				break;
			continue;
		}

		/* the part of this entry that the EFI runtime may allocate from */
		lo = max(start, astart);
		hi = min(end, aend);
		if (lo >= hi)
			lo = hi = end;

		ret = add_region(&r, &n, &max, start, lo - start,
				 EFI_BOOT_SERVICES_DATA, md->attribute, 0) ?:
		      add_region(&r, &n, &max, lo, hi - lo,
				 EFI_CONVENTIONAL_MEMORY, md->attribute,
				 EFI_KEXEC_REGION_ALLOCATABLE) ?:
		      add_region(&r, &n, &max, hi, end - hi,
				 EFI_BOOT_SERVICES_DATA, md->attribute, 0);
		if (ret)
			break;
	}

	if (ret) {
		kfree(r);
		return ret;
	}
	*regions = r;
	*nr_regions = n;
	return 0;
}

static int idmap_map_unaligned(struct kexec_efi_data *d, u64 start, u64 size)
{
	u64 end = ALIGN(start + size, SZ_2M);

	start = ALIGN_DOWN(start, SZ_2M);
	if (end > BIT_ULL(IDMAP_VA_BITS))
		return 0;
	return idmap_map_range(d, start, end);
}

/* SMBIOS 3.0 entry point structure */
struct smbios3_entry {
	u8	anchor[5];
	u8	ep_checksum;
	u8	ep_length;
	u8	major, minor, docrev, ep_rev, reserved;
	u32	max_size;
	u64	table_addr;
} __packed;

static int map_firmware_memory(struct kexec_efi_data *d)
{
	efi_memory_desc_t *md;
	int ret;

	for_each_efi_memory_desc(md) {
		if (!is_firmware_memory(md))
			continue;
		ret = idmap_map_unaligned(d, md->phys_addr,
					  md->num_pages << EFI_PAGE_SHIFT);
		if (ret)
			return ret;
	}

	/*
	 * The EFI stub reads the SMBIOS tables, which may live in memory that is
	 * not covered by the above, e.g., EfiReservedMemoryType regions, which
	 * we don't want to map wholesale.
	 */
	if (efi.smbios3 != EFI_INVALID_TABLE_ADDR) {
		const struct smbios3_entry *ep;

		ret = idmap_map_unaligned(d, efi.smbios3, sizeof(*ep));
		if (ret)
			return ret;

		ep = memremap(efi.smbios3, sizeof(*ep), MEMREMAP_WB);
		if (ep) {
			ret = idmap_map_unaligned(d, ep->table_addr, ep->max_size);
			memunmap((void *)ep);
			if (ret)
				return ret;
		}
	}
	return 0;
}

/*
 * Configuration tables of the firmware that are passed on to the image. This
 * includes the LINUX_EFI_MEMRESERVE table, which the EFI stub of the incoming
 * kernel will use rather than install a new one, so that the persistent
 * reservations made by this kernel and its predecessors are carried over.
 */
static const struct {
	efi_guid_t	guid;
	unsigned long	*addr;
} fw_tables[] = {
	{ ACPI_20_TABLE_GUID,			&efi.acpi20 },
	{ ACPI_TABLE_GUID,			&efi.acpi },
	{ SMBIOS3_TABLE_GUID,			&efi.smbios3 },
	{ SMBIOS_TABLE_GUID,			&efi.smbios },
	{ EFI_SYSTEM_RESOURCE_TABLE_GUID,	&efi.esrt },
	{ LINUX_EFI_TPM_EVENT_LOG_GUID,		&efi.tpm_log },
	{ EFI_TCG2_FINAL_EVENTS_TABLE_GUID,	&efi.tpm_final_log },
	{ LINUX_EFI_MOK_VARIABLE_TABLE_GUID,	&efi.mokvar_table },
	{ LINUX_EFI_MEMRESERVE_TABLE_GUID,	&efi.mem_reserve },
};

static int build_cfgtables(struct efi_kexec_cfgtable **tables,
			   unsigned long *nr_tables, const void *fdt,
			   const void *rt_prop)
{
	struct efi_kexec_cfgtable *t;
	unsigned long n = 0;

	t = kcalloc(ARRAY_SIZE(fw_tables) + 2, sizeof(*t), GFP_KERNEL);
	if (!t)
		return -ENOMEM;

	for (int i = 0; i < ARRAY_SIZE(fw_tables); i++) {
		if (*fw_tables[i].addr == EFI_INVALID_TABLE_ADDR)
			continue;
		t[n].guid = fw_tables[i].guid;
		t[n++].table = *fw_tables[i].addr;
	}

	t[n].guid = EFI_RT_PROPERTIES_TABLE_GUID;
	t[n++].table = (u64)rt_prop;

	if (fdt) {
		t[n].guid = DEVICE_TREE_GUID;
		t[n++].table = (u64)fdt;
	}

	*tables = t;
	*nr_tables = n;
	return 0;
}

/*
 * The firmware's runtime services can only be handed over if the current
 * kernel did not call SetVirtualAddressMap(), i.e., if all runtime regions are
 * mapped 1:1. This is what the arm64 EFI stub does on systems with at least
 * 48 bits of VA space, and what the incoming kernel's EFI stub will do too.
 */
static bool fw_runtime_usable(void)
{
	efi_memory_desc_t *md;

	if (!efi_enabled(EFI_RUNTIME_SERVICES))
		return false;

	for_each_efi_memory_desc(md)
		if ((md->attribute & EFI_MEMORY_RUNTIME) &&
		    md->virt_addr != md->phys_addr)
			return false;
	return true;
}

/* Bump allocator for the area between the page tables and EFI managed memory */
static void *prefix_alloc(phys_addr_t *next, size_t size)
{
	void *p = phys_to_virt(*next);

	*next = ALIGN(*next + size, SZ_4K);
	return p;
}

static void kexec_efi_free(struct kexec_efi_data *d)
{
	if (d->pages)
		free_contig_range(page_to_pfn(d->pages), d->nr_pages);
	kfree(d);
}

struct kexec_efi_run {
	struct kexec_efi_data		*d;
	struct efi_kexec_params		*p;
	struct user_fpsimd_state	fpsimd;
	struct completion		done;
	long				ret;
};

/*
 * Run the image with the identity map installed in TTBR0 and with interrupts
 * enabled, until it calls ExitBootServices() or fails.
 *
 * The image runs on a stack in the region, as it will resume on it at kexec
 * time, and so this stack is only mapped via TTBR0. This has a couple of
 * implications, given that exceptions taken while the image runs are handled
 * on this stack too:
 * - the stack must be THREAD_SIZE in size and THREAD_ALIGN aligned, or the
 *   exception entry code will think it has overflowed;
 * - exception entry must leave TTBR0 alone, and so if software PAN emulation
 *   is in use, all exceptions are kept masked instead;
 * - preemption must be disabled while the image runs: the scheduler installs
 *   the next task's page tables before it switches stacks, at which point the
 *   current stack would no longer be mapped.
 *
 * Use a kernel thread, so that the image runs without a user mm (and so faults
 * on its identity mapped addresses are treated as kernel faults), and so that
 * the image signs return addresses using a pointer authentication key that is
 * not used by any other task.
 */
static int kexec_efi_thread(void *arg)
{
	struct kexec_efi_run *run = arg;
	struct efi_kexec_jmpbuf jb;
	unsigned long flags = 0;
	unsigned long daif;

	kernel_neon_begin(&run->fpsimd);
	preempt_disable();
	if (system_uses_ttbr0_pan())
		flags = local_daif_save();
	cpu_install_ttbr0(run->d->ttbr0, TCR_T0SZ(IDMAP_VA_BITS));

	daif = read_sysreg(daif);
	run->ret = efi_kexec_call(efi_kexec_run, run->p, &jb);
	if (read_sysreg(daif) != daif) {
		pr_warn("EFI image changed the exception masks, restoring\n");
		write_sysreg(daif, daif);
	}
	efi_kexec_teardown();

	cpu_uninstall_idmap();
	if (system_uses_ttbr0_pan())
		local_daif_restore(flags);
	preempt_enable();
	kernel_neon_end(&run->fpsimd);

	complete(&run->done);
	return 0;
}

static long kexec_efi_run_image(struct kexec_efi_data *d,
				struct efi_kexec_params *p)
{
	struct kexec_efi_run *run;
	struct task_struct *t;
	long ret;

	run = kzalloc_obj(*run);
	if (!run)
		return -ENOMEM;

	run->d = d;
	run->p = p;
	init_completion(&run->done);

	efi_kexec_cur = d;
	t = kthread_run(kexec_efi_thread, run, "kexec_efi");
	if (IS_ERR(t)) {
		ret = PTR_ERR(t);
	} else {
		wait_for_completion(&run->done);
		ret = run->ret;
	}
	efi_kexec_cur = NULL;

	kfree(run);
	return ret;
}

/*
 * Unlike an ordinary kexec image, which only runs after the current kernel has
 * shut down, the EFI image runs in kernel mode at load time. So if the kernel
 * enforces signatures on modules, require a valid signature on the image too.
 * (Lockdown already enforces this for all kexec_file images.)
 */
static int kexec_efi_check_sig(const char *kernel, unsigned long kernel_len)
{
	int ret = -EKEYREJECTED;

	if (!is_module_sig_enforced())
		return 0;

#ifdef CONFIG_KEXEC_IMAGE_VERIFY_SIG
	ret = kexec_kernel_verify_pe_sig(kernel, kernel_len);
#endif
	if (ret)
		pr_err("Module signatures are enforced, refusing unsigned EFI image\n");
	return ret;
}

static void *kexec_efi_load(struct kimage *image, char *kernel,
			    unsigned long kernel_len, char *initrd,
			    unsigned long initrd_len, char *cmdline,
			    unsigned long cmdline_len)
{
	struct efi_kexec_cfgtable *tables = NULL;
	struct efi_kexec_region *regions = NULL;
	efi_rt_properties_table_t *rt_prop;
	struct efi_kexec_params params;
	struct kexec_efi_data *d;
	unsigned long nr_tables, nr_regions;
	phys_addr_t next;
	void *fdt = NULL;
	long ret;

	if (image->type == KEXEC_TYPE_CRASH)
		return ERR_PTR(-EOPNOTSUPP);

	if (!efi_enabled(EFI_MEMMAP)) {
		pr_err("No EFI memory map available\n");
		return ERR_PTR(-ENODEV);
	}

	ret = kexec_efi_check_sig(kernel, kernel_len);
	if (ret)
		return ERR_PTR(ret);

	d = kzalloc_obj(*d);
	if (!d)
		return ERR_PTR(-ENOMEM);

	/*
	 * Allocate a naturally aligned, physically contiguous region that is
	 * large enough for the image, a decompressed copy of the kernel, the
	 * initrd and the EFI runtime's own data structures.
	 */
	d->size = roundup_pow_of_two(max(SZ_128M, SZ_64M + 4 * kernel_len +
						  initrd_len));
	d->nr_pages = d->size >> PAGE_SHIFT;
	d->pages = alloc_contig_pages(d->nr_pages, GFP_KERNEL | __GFP_NOWARN,
				      numa_mem_id(), NULL);
	if (!d->pages) {
		pr_err("Failed to allocate %zu MiB of contiguous memory\n",
		       d->size / SZ_1M);
		ret = -ENOMEM;
		goto out_free;
	}
	d->base = page_to_phys(d->pages);
	if (d->base + d->size > BIT_ULL(IDMAP_VA_BITS)) {
		ret = -ENOMEM;
		goto out_free;
	}

	/*
	 * The stack for the image comes first. Exceptions may be taken on it,
	 * and so it must be THREAD_SIZE in size and THREAD_ALIGN aligned, which
	 * the region's natural alignment takes care of. This also means that a
	 * stack overflow runs off the start of the region, where it is likely
	 * to hit unmapped memory, and will be caught by the exception entry
	 * code's overflow check otherwise. Note that images started by the
	 * image (e.g., the kernel started by an EFI zboot decompressor) run on
	 * this stack too, below the frames of the image that started them.
	 */
	d->stack_top = d->base + THREAD_SIZE;

	/* Then the page tables */
	d->pt_next = d->stack_top;
	d->pt_end = d->pt_next + PT_POOL_SIZE;
	if (!pt_alloc(d, &d->ttbr0)) {
		ret = -ENOMEM;
		goto out_free;
	}
	ret = idmap_map_range(d, d->base, d->base + d->size) ?:
	      map_firmware_memory(d);
	if (ret)
		goto out_free;
	dsb(ishst);

	/* Then the resume block, the trampoline and other static allocations */
	next = d->pt_end;
	d->resume = prefix_alloc(&next, sizeof(*d->resume));
	d->resume_pa = virt_to_phys(d->resume);
	d->trampoline_pa = next;
	memcpy(prefix_alloc(&next, efi_kexec_resume_end - efi_kexec_resume_start),
	       efi_kexec_resume_start, efi_kexec_resume_end - efi_kexec_resume_start);

	rt_prop = prefix_alloc(&next, sizeof(*rt_prop));
	*rt_prop = (efi_rt_properties_table_t){
		.version = EFI_RT_PROPERTIES_TABLE_VERSION,
		.length	 = sizeof(*rt_prop),
		.runtime_services_supported = fw_runtime_usable() ?
					      efi.runtime_supported_mask : 0,
	};

	if (acpi_disabled) {
		void *dt = of_kexec_alloc_and_setup_fdt(image, 0, 0, cmdline, 0);

		if (!dt) {
			ret = -EINVAL;
			goto out_free;
		}
		fdt_pack(dt);
		fdt = prefix_alloc(&next, fdt_totalsize(dt));
		memcpy(fdt, dt, fdt_totalsize(dt));
		kvfree(dt);
	}

	/* Everything up to here is described as EfiBootServicesData */
	d->alloc_start = ALIGN(next, SZ_64K);

	ret = build_regions(d, &regions, &nr_regions) ?:
	      build_cfgtables(&tables, &nr_tables,
			      fdt ? (void *)virt_to_phys(fdt) : NULL,
			      (void *)virt_to_phys(rt_prop));
	if (ret)
		goto out_free;

	params = (struct efi_kexec_params){
		.image		= kernel,
		.image_size	= kernel_len,
		.initrd		= initrd,
		.initrd_size	= initrd_len,
		.cmdline	= cmdline,
		.cmdline_size	= cmdline_len,
		.regions	= regions,
		.nr_regions	= nr_regions,
		.tables		= tables,
		.nr_tables	= nr_tables,
		.fw_runtime	= fw_runtime_usable() ? (u64)efi.runtime : 0,
		.stack_top	= d->stack_top,
	};

	ret = kexec_efi_run_image(d, &params);
	if (ret != EFI_KEXEC_SUSPENDED) {
		pr_err("Failed to run EFI image: %ld\n", ret);
		if (ret >= 0)
			ret = -ENOEXEC;
		goto out_free;
	}
	kfree(regions);
	kfree(tables);

	/* Prepare the MMU configuration for the resume trampoline */
	d->resume->mair = read_sysreg(mair_el1);
	d->resume->ttbr0 = d->ttbr0;
	d->resume->tcr_el1 = idmap_tcr_el1();
	d->resume->sctlr_el1 = RESUME_SCTLR_EL1;
	d->resume->tcr_el2 = idmap_tcr_el2();
	d->resume->sctlr_el2 = RESUME_SCTLR_EL2;
	idmap_prepare_for_resume(d);

	/* The trampoline runs with the MMU off: clean everything to the PoC */
	dcache_clean_inval_poc((unsigned long)phys_to_virt(d->base),
			       (unsigned long)phys_to_virt(d->base) + d->size);

	image->start = d->trampoline_pa + efi_kexec_resume_entry_offset;
	image->arch.dtb_mem = d->resume_pa;
	image->arch.efi = d;

	pr_info("EFI image suspended at ExitBootServices(), system table @ %#llx\n",
		params.systab);
	return NULL;

out_free:
	kfree(regions);
	kfree(tables);
	kexec_efi_free(d);
	return ERR_PTR(ret);
}

/* Called when the kimage is freed */
void kexec_efi_free_image(struct kimage *image)
{
	if (image->arch.efi) {
		kexec_efi_free(image->arch.efi);
		image->arch.efi = NULL;
	}
}

static int kexec_efi_probe(const char *buf, unsigned long len)
{
	const struct mz_hdr *mz = (const void *)buf;
	const struct pe_hdr *pe;

	if (len < sizeof(*mz) || le16_to_cpu(mz->magic) != IMAGE_DOS_SIGNATURE)
		return -ENOEXEC;

	if (le32_to_cpu(mz->peaddr) > len - sizeof(*pe))
		return -ENOEXEC;

	pe = (const void *)buf + le32_to_cpu(mz->peaddr);
	if (le32_to_cpu(pe->magic) != IMAGE_NT_SIGNATURE ||
	    le16_to_cpu(pe->machine) != IMAGE_FILE_MACHINE_ARM64)
		return -ENOEXEC;

	return 0;
}

const struct kexec_file_ops kexec_efi_ops = {
	.probe		= kexec_efi_probe,
	.load		= kexec_efi_load,
#ifdef CONFIG_KEXEC_IMAGE_VERIFY_SIG
	.verify_sig	= kexec_kernel_verify_pe_sig,
#endif
};
