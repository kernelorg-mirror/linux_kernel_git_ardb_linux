// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2022 Google LLC
// Author: Ard Biesheuvel <ardb@google.com>

// NOTE: code in this file runs *very* early, and is not permitted to use
// global variables or anything that relies on absolute addressing.

#define arm64_use_ng_mappings 0

#include <linux/elf.h>
#include <linux/libfdt.h>
#include <linux/init.h>
#include <linux/linkage.h>
#include <linux/types.h>
#include <linux/sizes.h>
#include <linux/string.h>

#include <asm/archrandom.h>
#include <asm/memory.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>

/* taken from lib/string.c */
static char *__strstr(const char *s1, const char *s2)
{
	size_t l1, l2;

	l2 = strlen(s2);
	if (!l2)
		return (char *)s1;
	l1 = strlen(s1);
	while (l1 >= l2) {
		l1--;
		if (!memcmp(s1, s2, l2))
			return (char *)s1;
		s1++;
	}
	return NULL;
}

/*
 * Returns whether @pfx appears in @string, either at the very start, or
 * elsewhere but preceded by a space character.
 */
static bool string_contains_prefix(const u8 *string, const u8 *pfx)
{
	const u8 *str;

	str = __strstr(string, pfx);
	return str == string || (str > string && *(str - 1) == ' ');
}

static bool cmdline_has(void *fdt, const u8 *word)
{
	if (!IS_ENABLED(CONFIG_CMDLINE_FORCE)) {
		int node;
		const u8 *prop;

		node = fdt_path_offset(fdt, "/chosen");
		if (node < 0)
			goto out;

		prop = fdt_getprop(fdt, node, "bootargs", NULL);
		if (!prop)
			goto out;

		if (string_contains_prefix(prop, word))
			return true;

		if (IS_ENABLED(CONFIG_CMDLINE_EXTEND))
			goto out;

		return false;
	}
out:
	return string_contains_prefix(CONFIG_CMDLINE, word);
}

static u64 get_kaslr_seed(void *fdt)
{
	int node, len;
	fdt64_t *prop;
	u64 ret;

	node = fdt_path_offset(fdt, "/chosen");
	if (node < 0)
		return 0;

	prop = fdt_getprop_w(fdt, node, "kaslr-seed", &len);
	if (!prop || len != sizeof(u64))
		return 0;

	ret = fdt64_to_cpu(*prop);
	*prop = 0;
	return ret;
}

static u64 kaslr_early_init(void *fdt)
{
	u64 seed;

	if (cmdline_has(fdt, "nokaslr"))
		return 0;

	seed = get_kaslr_seed(fdt);
	if (!seed) {
#ifdef CONFIG_ARCH_RANDOM
		 if (!__early_cpu_has_rndr() ||
		     !__arm64_rndr((unsigned long *)&seed))
#endif
		return 0;
	}

	/*
	 * OK, so we are proceeding with KASLR enabled. Calculate a suitable
	 * kernel image offset from the seed. Let's place the kernel in the
	 * middle half of the VMALLOC area (VA_BITS_MIN - 2), and stay clear of
	 * the lower and upper quarters to avoid colliding with other
	 * allocations.
	 */
	return BIT(VA_BITS_MIN - 3) + (seed & GENMASK(VA_BITS_MIN - 3, 0));
}

extern const Elf64_Rela rela_start[], rela_end[];
extern const u64 relr_start[], relr_end[];

static void relocate_kernel(u64 offset)
{
	const Elf64_Rela *rela;
	const u64 *relr;
	u64 *place;

	for (rela = rela_start; rela < rela_end; rela++) {
		if (ELF64_R_TYPE(rela->r_info) != R_AARCH64_RELATIVE)
			continue;
		place = (u64 *)(rela->r_offset + offset);
		*place = rela->r_addend + offset;
	}

	if (!IS_ENABLED(CONFIG_RELR) || !offset)
		return;

	/*
	 * Apply RELR relocations.
	 *
	 * RELR is a compressed format for storing relative relocations. The
	 * encoded sequence of entries looks like:
	 * [ AAAAAAAA BBBBBBB1 BBBBBBB1 ... AAAAAAAA BBBBBB1 ... ]
	 *
	 * i.e. start with an address, followed by any number of bitmaps. The
	 * address entry encodes 1 relocation. The subsequent bitmap entries
	 * encode up to 63 relocations each, at subsequent offsets following
	 * the last address entry.
	 *
	 * The bitmap entries must have 1 in the least significant bit. The
	 * assumption here is that an address cannot have 1 in lsb. Odd
	 * addresses are not supported. Any odd addresses are stored in the
	 * RELA section, which is handled above.
	 *
	 * Excluding the least significant bit in the bitmap, each non-zero bit
	 * in the bitmap represents a relocation to be applied to a
	 * corresponding machine word that follows the base address word. The
	 * second least significant bit represents the machine word immediately
	 * following the initial address, and each bit that follows represents
	 * the next word, in linear order. As such, a single bitmap can encode
	 * up to 63 relocations in a 64-bit object.
	 */
	for (relr = relr_start; relr < relr_end; relr++) {
		u64 *p, r = *relr;

		if ((r & 1) == 0) {
			place = (u64 *)(r + offset);
			*place++ += offset;
		} else {
			for (p = place; r; p++) {
				r >>= 1;
				if (r & 1)
					*p += offset;
			}
			place += 63;
		}
	}
}

extern void idmap_cpu_replace_ttbr1(void *pgdir);

static void map_range(pgd_t **pgd, u64 start, u64 end, u64 pa, pgprot_t prot,
		      int level, pte_t *tbl, bool may_use_cont)
{
	u64 cmask = (level == 3) ? CONT_PTE_SIZE - 1 : U64_MAX;
	u64 protval = pgprot_val(prot) & ~PTE_TYPE_MASK;
	int lshift = (3 - level) * (PAGE_SHIFT - 3);
	u64 lmask = (PAGE_SIZE << lshift) - 1;

	// Advance tbl to the entry that covers start
	tbl += (start >> (lshift + PAGE_SHIFT)) % BIT(PAGE_SHIFT - 3);

	// Set the right block/page bits for this level unless we are
	// clearing the mapping
	if (protval)
		protval |= (level < 3) ? PMD_TYPE_SECT : PTE_TYPE_PAGE;

	while (start < end) {
		u64 next = min((start | lmask) + 1, end);

		if (level < 3 &&
		    (start & lmask || next & lmask || pa & lmask)) {
			// This chunk needs a finer grained mapping
			// Put down a table mapping if necessary and recurse
			if (pte_none(*tbl)) {
				*tbl = __pte(__phys_to_pte_val((u64)*pgd) |
					     PMD_TYPE_TABLE);
				*pgd += PTRS_PER_PTE;
			}
			map_range(pgd, start, next, pa, prot, level + 1,
				  (pte_t *)__pte_to_phys(*tbl), may_use_cont);
		} else {
			// Start a contiguous range if start and pa are
			// suitably aligned
			if (((start | pa) & cmask) == 0 && may_use_cont)
				protval |= PTE_CONT;
			// Clear the contiguous attribute if the remaining
			// range does not cover a contiguous block
			if ((end & ~cmask) <= start)
				protval &= ~PTE_CONT;
			// Put down a block or page mapping
			*tbl = __pte(__phys_to_pte_val(pa) | protval);
		}
		pa += next - start;
		start = next;
		tbl++;
	}
}

static void map_segment(pgd_t **pgd, u64 va_offset, void *start, void *end,
			pgprot_t prot, bool may_use_cont)
{
	map_range(pgd, ((u64)start + va_offset) & ~PAGE_OFFSET,
		  ((u64)end + va_offset) & ~PAGE_OFFSET, (u64)start,
		  prot, 4 - CONFIG_PGTABLE_LEVELS, (pte_t *)init_pg_dir,
		  may_use_cont);
}

static void unmap_segment(u64 va_offset, void *start, void *end)
{
	map_range(NULL, ((u64)start + va_offset) & ~PAGE_OFFSET,
		  ((u64)end + va_offset) & ~PAGE_OFFSET, (u64)start,
		  __pgprot(0), 4 - CONFIG_PGTABLE_LEVELS, (pte_t *)init_pg_dir,
		  false);
}

/*
 * Open coded check for BTI, only for use to determine configuration
 * for early mappings for before the cpufeature code has run.
 */
static bool arm64_early_this_cpu_has_bti(void)
{
	u64 pfr1;

	if (!IS_ENABLED(CONFIG_ARM64_BTI_KERNEL))
		return false;

	pfr1 = read_sysreg_s(SYS_ID_AA64PFR1_EL1);
	return cpuid_feature_extract_unsigned_field(pfr1,
						    ID_AA64PFR1_BT_SHIFT);
}

static bool arm64_early_this_cpu_has_e0pd(void)
{
	u64 mmfr2;

	if (!IS_ENABLED(CONFIG_ARM64_E0PD))
		return false;

	mmfr2 = read_sysreg_s(SYS_ID_AA64MMFR2_EL1);
	return cpuid_feature_extract_unsigned_field(mmfr2,
						    ID_AA64MMFR2_E0PD_SHIFT);
}

extern void disable_wxn(void);

static void map_kernel(void *fdt, u64 kaslr_offset, u64 va_offset)
{
	pgd_t *pgdp = (void *)init_pg_dir + PAGE_SIZE;
	pgprot_t text_prot = PAGE_KERNEL_ROX;
	pgprot_t data_prot = PAGE_KERNEL;
	pgprot_t prot;
	bool nowxn = false;

	if (cmdline_has(fdt, "rodata=off")) {
		text_prot = PAGE_KERNEL_EXEC;
		nowxn = true;
	}

	if (IS_ENABLED(CONFIG_ARM64_WXN) &&
	    (nowxn || cmdline_has(fdt, "arm64.nowxn")))
		disable_wxn();

	// If we have a CPU that supports BTI and a kernel built for
	// BTI then mark the kernel executable text as guarded pages
	// now so we don't have to rewrite the page tables later.
	if (arm64_early_this_cpu_has_bti() && !cmdline_has(fdt, "arm64.nobti"))
		text_prot = __pgprot_modify(text_prot, PTE_GP, PTE_GP);

	// Assume that any CPU that does not implement E0PD needs KPTI to
	// ensure that KASLR randomized addresses will not leak. This means we
	// need to use non-global mappings for the kernel text and data.
	if (!arm64_early_this_cpu_has_e0pd() && kaslr_offset >= MIN_KIMG_ALIGN) {
		text_prot = __pgprot_modify(text_prot, PTE_NG, PTE_NG);
		data_prot = __pgprot_modify(data_prot, PTE_NG, PTE_NG);
	}

	// Map all code read-write on the first pass for relocation processing
	prot = IS_ENABLED(CONFIG_RELOCATABLE) ? data_prot : text_prot;

	map_segment(&pgdp, va_offset, _stext, _etext, prot, true);
	map_segment(&pgdp, va_offset, __start_rodata, __inittext_begin, data_prot, false);
	map_segment(&pgdp, va_offset, __inittext_begin, __inittext_end, prot, false);
	map_segment(&pgdp, va_offset, __initdata_begin, __initdata_end, data_prot, false);
	map_segment(&pgdp, va_offset, _data, init_pg_dir, data_prot, true);
	// omit [init_pg_dir, _end] - it doesn't need a kernel mapping
	dsb(ishst);

	idmap_cpu_replace_ttbr1(init_pg_dir);

	if (IS_ENABLED(CONFIG_RELOCATABLE)) {
		relocate_kernel(kaslr_offset);

		// Unmap the text region before remapping it, to avoid
		// potential TLB conflicts on the contiguous descriptors. This
		// assumes that it is permitted to clear the valid bit on a
		// live descriptor with the CONT bit set.
		unmap_segment(va_offset, _stext, _etext);
		dsb(ishst);
		isb();
		__tlbi(vmalle1);
		isb();

		// Remap these segments with different permissions
		// No new page table allocations should be needed
		map_segment(NULL, va_offset, _stext, _etext, text_prot, true);
		map_segment(NULL, va_offset, __inittext_begin, __inittext_end,
			    text_prot, false);
		dsb(ishst);
	}

	// Copy the root page table to its final location
	memcpy((void *)swapper_pg_dir + va_offset, init_pg_dir, PGD_SIZE);
	idmap_cpu_replace_ttbr1(swapper_pg_dir);
}

asmlinkage u64 early_map_kernel(void *fdt)
{
	u64 kaslr_seed = 0, kaslr_offset = 0;
	u64 va_base = KIMAGE_VADDR;
	u64 pa_base = (u64)&_text;

	// Clear the initial page tables before populating them
	memset(init_pg_dir, 0, init_pg_end - init_pg_dir);

	// The virtual KASLR displacement modulo 2MiB is decided by the
	// physical placement of the image, as otherwise, we might not be able
	// to create the early kernel mapping using 2 MiB block descriptors. So
	// take the low bits of the KASLR offset from the physical address, and
	// fill in the high bits from the seed.
	if (IS_ENABLED(CONFIG_RELOCATABLE)) {
		kaslr_offset = pa_base & (MIN_KIMG_ALIGN - 1);
		if (IS_ENABLED(CONFIG_RANDOMIZE_BASE)) {
			kaslr_seed = kaslr_early_init(fdt);
			kaslr_offset |= kaslr_seed & ~(MIN_KIMG_ALIGN - 1);
		}
		va_base += kaslr_offset;
	}

	map_kernel(fdt, kaslr_offset, va_base - pa_base);

	// Return the lower 16 bits of the seed - this will be
	// used to randomize the linear map
	return kaslr_seed & U16_MAX;
}
