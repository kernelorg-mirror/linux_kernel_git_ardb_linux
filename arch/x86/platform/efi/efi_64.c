// SPDX-License-Identifier: GPL-2.0
/*
 * x86_64 specific EFI support functions
 * Based on Extensible Firmware Interface Specification version 1.0
 *
 * Copyright (C) 2005-2008 Intel Co.
 *	Fenghua Yu <fenghua.yu@intel.com>
 *	Bibo Mao <bibo.mao@intel.com>
 *	Chandramouli Narayanan <mouli@linux.intel.com>
 *	Huang Ying <ying.huang@intel.com>
 *
 * Code to convert EFI to E820 map has been implemented in elilo bootloader
 * based on a EFI patch by Edgar Hucek. Based on the E820 map, the page table
 * is setup appropriately for EFI runtime code.
 * - mouli 06/14/2007.
 *
 */

#define pr_fmt(fmt) "efi: " fmt

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/memblock.h>
#include <linux/ioport.h>
#include <linux/mc146818rtc.h>
#include <linux/efi.h>
#include <linux/export.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include <linux/reboot.h>
#include <linux/slab.h>
#include <linux/ucs2_string.h>
#include <linux/cc_platform.h>
#include <linux/sched/task.h>

#include <asm/setup.h>
#include <asm/page.h>
#include <asm/e820/api.h>
#include <asm/tlbflush.h>
#include <asm/proto.h>
#include <asm/efi.h>
#include <asm/cacheflush.h>
#include <asm/fixmap.h>
#include <asm/realmode.h>
#include <asm/time.h>
#include <asm/pgalloc.h>
#include <asm/sev.h>

/*
 * We allocate runtime services regions top-down, starting from -4G, i.e.
 * 0xffff_ffff_0000_0000 and limit EFI VA mapping space to 64G.
 */
static u64 efi_va = EFI_VA_START;
static struct mm_struct *efi_prev_mm;

/*
 * We need our own copy of the higher levels of the page tables
 * because we want to avoid inserting EFI region mappings (EFI_VA_END
 * to EFI_VA_START) into the standard kernel page tables. Everything
 * else can be shared, see efi_sync_low_kernel_mappings().
 *
 * We don't want the pgd on the pgd_list and cannot use pgd_alloc() for the
 * allocation.
 */
int __init efi_alloc_page_tables(void)
{
	pgd_t *pgd, *efi_pgd;
	p4d_t *p4d;
	pud_t *pud;
	gfp_t gfp_mask;

	gfp_mask = GFP_KERNEL | __GFP_ZERO;
	efi_pgd = (pgd_t *)__get_free_pages(gfp_mask, PGD_ALLOCATION_ORDER);
	if (!efi_pgd)
		goto fail;

	pgd = efi_pgd + pgd_index(EFI_VA_END);
	p4d = p4d_alloc(&init_mm, pgd, EFI_VA_END);
	if (!p4d)
		goto free_pgd;

	pud = pud_alloc(&init_mm, p4d, EFI_VA_END);
	if (!pud)
		goto free_p4d;

	efi_mm.pgd = efi_pgd;
	mm_init_cpumask(&efi_mm);
	init_new_context(NULL, &efi_mm);

	return 0;

free_p4d:
	if (pgtable_l5_enabled())
		free_page((unsigned long)pgd_page_vaddr(*pgd));
free_pgd:
	free_pages((unsigned long)efi_pgd, PGD_ALLOCATION_ORDER);
fail:
	return -ENOMEM;
}

/*
 * Add low kernel mappings for passing arguments to EFI functions.
 */
void efi_sync_low_kernel_mappings(void)
{
	unsigned num_entries;
	pgd_t *pgd_k, *pgd_efi;
	p4d_t *p4d_k, *p4d_efi;
	pud_t *pud_k, *pud_efi;
	pgd_t *efi_pgd = efi_mm.pgd;

	pgd_efi = efi_pgd + pgd_index(PAGE_OFFSET);
	pgd_k = pgd_offset_k(PAGE_OFFSET);

	num_entries = pgd_index(EFI_VA_END) - pgd_index(PAGE_OFFSET);
	memcpy(pgd_efi, pgd_k, sizeof(pgd_t) * num_entries);

	pgd_efi = efi_pgd + pgd_index(EFI_VA_END);
	pgd_k = pgd_offset_k(EFI_VA_END);
	p4d_efi = p4d_offset(pgd_efi, 0);
	p4d_k = p4d_offset(pgd_k, 0);

	num_entries = p4d_index(EFI_VA_END);
	memcpy(p4d_efi, p4d_k, sizeof(p4d_t) * num_entries);

	/*
	 * We share all the PUD entries apart from those that map the
	 * EFI regions. Copy around them.
	 */
	BUILD_BUG_ON((EFI_VA_START & ~PUD_MASK) != 0);
	BUILD_BUG_ON((EFI_VA_END & ~PUD_MASK) != 0);

	p4d_efi = p4d_offset(pgd_efi, EFI_VA_END);
	p4d_k = p4d_offset(pgd_k, EFI_VA_END);
	pud_efi = pud_offset(p4d_efi, 0);
	pud_k = pud_offset(p4d_k, 0);

	num_entries = pud_index(EFI_VA_END);
	memcpy(pud_efi, pud_k, sizeof(pud_t) * num_entries);

	pud_efi = pud_offset(p4d_efi, EFI_VA_START);
	pud_k = pud_offset(p4d_k, EFI_VA_START);

	num_entries = PTRS_PER_PUD - pud_index(EFI_VA_START);
	memcpy(pud_efi, pud_k, sizeof(pud_t) * num_entries);
}

/*
 * Wrapper for slow_virt_to_phys() that handles NULL addresses.
 */
static inline phys_addr_t
virt_to_phys_or_null_size(void *va, unsigned long size)
{
	phys_addr_t pa;

	if (!va)
		return 0;

	if (virt_addr_valid(va))
		return virt_to_phys(va);

	pa = slow_virt_to_phys(va);

	/* check if the object crosses a page boundary */
	if (WARN_ON((pa ^ (pa + size - 1)) & PAGE_MASK))
		return 0;

	return pa;
}

#define virt_to_phys_or_null(addr)				\
	virt_to_phys_or_null_size((addr), sizeof(*(addr)))

int __init efi_setup_page_tables(unsigned long pa_memmap, unsigned num_pages)
{
	unsigned long pfn, pf;
	pgd_t *pgd = efi_mm.pgd;

	/*
	 * It can happen that the physical address of new_memmap lands in memory
	 * which is not mapped in the EFI page table. Therefore we need to go
	 * and ident-map those pages containing the map before calling
	 * phys_efi_set_virtual_address_map().
	 */
	pfn = pa_memmap >> PAGE_SHIFT;
	pf = _PAGE_NX | _PAGE_RW | _PAGE_ENC;
	if (kernel_map_pages_in_pgd(pgd, pfn, pa_memmap, num_pages, pf)) {
		pr_err("Error ident-mapping new memmap (0x%lx)!\n", pa_memmap);
		return 1;
	}

	/*
	 * Certain firmware versions are way too sentimental and still believe
	 * they are exclusive and unquestionable owners of the first physical page,
	 * even though they explicitly mark it as EFI_CONVENTIONAL_MEMORY
	 * (but then write-access it later during SetVirtualAddressMap()).
	 *
	 * Create a 1:1 mapping for this page, to avoid triple faults during early
	 * boot with such firmware. We are free to hand this page to the BIOS,
	 * as trim_bios_range() will reserve the first page and isolate it away
	 * from memory allocators anyway.
	 */
	if (kernel_map_pages_in_pgd(pgd, 0x0, 0x0, 1, pf)) {
		pr_err("Failed to create 1:1 mapping for the first page!\n");
		return 1;
	}

	/*
	 * When SEV-ES is active, the GHCB as set by the kernel will be used
	 * by firmware. Create a 1:1 unencrypted mapping for each GHCB.
	 */
	if (sev_es_efi_map_ghcbs(pgd)) {
		pr_err("Failed to create 1:1 mapping for the GHCBs!\n");
		return 1;
	}

	return 0;
}

static void __init __map_region(efi_memory_desc_t *md, u64 va)
{
	unsigned long flags = _PAGE_RW;
	unsigned long pfn;
	pgd_t *pgd = efi_mm.pgd;

	/*
	 * EFI_RUNTIME_SERVICES_CODE regions typically cover PE/COFF
	 * executable images in memory that consist of both R-X and
	 * RW- sections, so we cannot apply read-only or non-exec
	 * permissions just yet. However, modern EFI systems provide
	 * a memory attributes table that describes those sections
	 * with the appropriate restricted permissions, which are
	 * applied in efi_runtime_update_mappings() below. All other
	 * regions can be mapped non-executable at this point, with
	 * the exception of boot services code regions, but those will
	 * be unmapped again entirely in efi_free_boot_services().
	 */
	if (md->type != EFI_BOOT_SERVICES_CODE &&
	    md->type != EFI_RUNTIME_SERVICES_CODE)
		flags |= _PAGE_NX;

	if (!(md->attribute & EFI_MEMORY_WB))
		flags |= _PAGE_PCD;

	if (cc_platform_has(CC_ATTR_GUEST_MEM_ENCRYPT) &&
	    md->type != EFI_MEMORY_MAPPED_IO)
		flags |= _PAGE_ENC;

	pfn = md->phys_addr >> PAGE_SHIFT;
	if (kernel_map_pages_in_pgd(pgd, pfn, va, md->num_pages, flags))
		pr_warn("Error mapping PA 0x%llx -> VA 0x%llx!\n",
			   md->phys_addr, va);
}

void __init efi_map_region(efi_memory_desc_t *md)
{
	unsigned long size = md->num_pages << PAGE_SHIFT;
	u64 pa = md->phys_addr;

	/*
	 * Make sure the 1:1 mappings are present as a catch-all for b0rked
	 * firmware which doesn't update all internal pointers after switching
	 * to virtual mode and would otherwise crap on us.
	 */
	__map_region(md, md->phys_addr);

	efi_va -= size;

	/* Is PA 2M-aligned? */
	if (!(pa & (PMD_SIZE - 1))) {
		efi_va &= PMD_MASK;
	} else {
		u64 pa_offset = pa & (PMD_SIZE - 1);
		u64 prev_va = efi_va;

		/* get us the same offset within this 2M page */
		efi_va = (efi_va & PMD_MASK) + pa_offset;

		if (efi_va > prev_va)
			efi_va -= PMD_SIZE;
	}

	if (efi_va < EFI_VA_END) {
		pr_warn(FW_WARN "VA address range overflow!\n");
		return;
	}

	/* Do the VA map */
	__map_region(md, efi_va);
	md->virt_addr = efi_va;
}

/*
 * kexec kernel will use efi_map_region_fixed to map efi runtime memory ranges.
 * md->virt_addr is the original virtual address which had been mapped in kexec
 * 1st kernel.
 */
void __init efi_map_region_fixed(efi_memory_desc_t *md)
{
	__map_region(md, md->phys_addr);
	__map_region(md, md->virt_addr);
}

void __init parse_efi_setup(u64 phys_addr, u32 data_len)
{
	efi_setup = phys_addr + sizeof(struct setup_data);
}

static int __init efi_update_mappings(efi_memory_desc_t *md, unsigned long pf)
{
	unsigned long pfn;
	pgd_t *pgd = efi_mm.pgd;
	int err1, err2;

	/* Update the 1:1 mapping */
	pfn = md->phys_addr >> PAGE_SHIFT;
	err1 = kernel_map_pages_in_pgd(pgd, pfn, md->phys_addr, md->num_pages, pf);
	if (err1) {
		pr_err("Error while updating 1:1 mapping PA 0x%llx -> VA 0x%llx!\n",
			   md->phys_addr, md->virt_addr);
	}

	err2 = kernel_map_pages_in_pgd(pgd, pfn, md->virt_addr, md->num_pages, pf);
	if (err2) {
		pr_err("Error while updating VA mapping PA 0x%llx -> VA 0x%llx!\n",
			   md->phys_addr, md->virt_addr);
	}

	return err1 || err2;
}

bool efi_disable_ibt_for_runtime __ro_after_init = true;

static int __init efi_update_mem_attr(struct mm_struct *mm, efi_memory_desc_t *md,
				      bool has_ibt)
{
	unsigned long pf = 0;

	efi_disable_ibt_for_runtime |= !has_ibt;

	if (md->attribute & EFI_MEMORY_XP)
		pf |= _PAGE_NX;

	if (!(md->attribute & EFI_MEMORY_RO))
		pf |= _PAGE_RW;

	if (cc_platform_has(CC_ATTR_GUEST_MEM_ENCRYPT))
		pf |= _PAGE_ENC;

	return efi_update_mappings(md, pf);
}

void __init efi_runtime_update_mappings(void)
{
	efi_memory_desc_t *md;

	/*
	 * Use the EFI Memory Attribute Table for mapping permissions if it
	 * exists, since it is intended to supersede EFI_PROPERTIES_TABLE.
	 */
	if (efi_enabled(EFI_MEM_ATTR)) {
		efi_disable_ibt_for_runtime = false;
		efi_memattr_apply_permissions(NULL, efi_update_mem_attr);
		return;
	}

	/*
	 * EFI_MEMORY_ATTRIBUTES_TABLE is intended to replace
	 * EFI_PROPERTIES_TABLE. So, use EFI_PROPERTIES_TABLE to update
	 * permissions only if EFI_MEMORY_ATTRIBUTES_TABLE is not
	 * published by the firmware. Even if we find a buggy implementation of
	 * EFI_MEMORY_ATTRIBUTES_TABLE, don't fall back to
	 * EFI_PROPERTIES_TABLE, because of the same reason.
	 */

	if (!efi_enabled(EFI_NX_PE_DATA))
		return;

	for_each_efi_memory_desc(md) {
		unsigned long pf = 0;

		if (!(md->attribute & EFI_MEMORY_RUNTIME))
			continue;

		if (!(md->attribute & EFI_MEMORY_WB))
			pf |= _PAGE_PCD;

		if ((md->attribute & EFI_MEMORY_XP) ||
			(md->type == EFI_RUNTIME_SERVICES_DATA))
			pf |= _PAGE_NX;

		if (!(md->attribute & EFI_MEMORY_RO) &&
			(md->type != EFI_RUNTIME_SERVICES_CODE))
			pf |= _PAGE_RW;

		if (cc_platform_has(CC_ATTR_GUEST_MEM_ENCRYPT))
			pf |= _PAGE_ENC;

		efi_update_mappings(md, pf);
	}
}

void __init efi_dump_pagetable(void)
{
#ifdef CONFIG_EFI_PGT_DUMP
	ptdump_walk_pgd_level(NULL, &efi_mm);
#endif
}

/*
 * Makes the calling thread switch to/from efi_mm context. Can be used
 * in a kernel thread and user context. Preemption needs to remain disabled
 * while the EFI-mm is borrowed. mmgrab()/mmdrop() is not used because the mm
 * can not change under us.
 * It should be ensured that there are no concurrent calls to this function.
 */
void efi_enter_mm(void)
{
	efi_prev_mm = current->active_mm;
	current->active_mm = &efi_mm;
	switch_mm(efi_prev_mm, &efi_mm, NULL);
}

void efi_leave_mm(void)
{
	current->active_mm = efi_prev_mm;
	switch_mm(&efi_mm, efi_prev_mm, NULL);
}

efi_status_t __init __no_sanitize_address
efi_set_virtual_address_map(unsigned long memory_map_size,
			    unsigned long descriptor_size,
			    u32 descriptor_version,
			    efi_memory_desc_t *virtual_map,
			    unsigned long systab_phys)
{
	const efi_system_table_t *systab = (efi_system_table_t *)systab_phys;
	efi_status_t status;
	unsigned long flags;

	efi_enter_mm();

	efi_fpu_begin();

	/* Disable interrupts around EFI calls: */
	local_irq_save(flags);
	status = efi_call(efi.runtime->set_virtual_address_map,
			  memory_map_size, descriptor_size,
			  descriptor_version, virtual_map);
	local_irq_restore(flags);

	efi_fpu_end();

	/* grab the virtually remapped EFI runtime services table pointer */
	efi.runtime = READ_ONCE(systab->runtime);

	efi_leave_mm();

	return status;
}
