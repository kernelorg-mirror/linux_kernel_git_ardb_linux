// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2022 Google LLC
// Author: Ard Biesheuvel <ardb@google.com>

#include <linux/init.h>
#include <linux/libfdt.h>
#include <linux/linkage.h>
#include <linux/types.h>
#include <linux/sizes.h>
#include <linux/string.h>

#include <asm/memory.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>

#include "pi.h"

extern const u8 __eh_frame_start[], __eh_frame_end[];

extern void idmap_cpu_replace_ttbr1(void *pgdir);

static void __init map_range(pgd_t **pgd, u64 start, u64 end, u64 pa,
			     pgprot_t prot, int level, pte_t *tbl,
			     bool may_use_cont)
{
	u64 cmask = (level == 3) ? CONT_PTE_SIZE - 1 : U64_MAX;
	u64 protval = pgprot_val(prot) & ~PTE_TYPE_MASK;
	int lshift = (3 - level) * (PAGE_SHIFT - 3);
	u64 lmask = (PAGE_SIZE << lshift) - 1;

	/* Advance tbl to the entry that covers start */
	tbl += (start >> (lshift + PAGE_SHIFT)) % BIT(PAGE_SHIFT - 3);

	/*
	 * Set the right block/page bits for this level unless we are
	 * clearing the mapping
	 */
	if (protval)
		protval |= (level < 3) ? PMD_TYPE_SECT : PTE_TYPE_PAGE;

	while (start < end) {
		u64 next = min((start | lmask) + 1, end);

		if (level < 3 && (start | next | pa) & lmask) {
			/*
			 * This chunk needs a finer grained mapping. Put down
			 * a table mapping if necessary and recurse.
			 */
			if (pte_none(*tbl)) {
				*tbl = __pte(__phys_to_pte_val((u64)*pgd) |
					     PMD_TYPE_TABLE | PMD_TABLE_UXN);
				*pgd += PTRS_PER_PTE;
			}
			map_range(pgd, start, next, pa, prot, level + 1,
				  (pte_t *)__pte_to_phys(*tbl), may_use_cont);
		} else {
			/*
			 * Start a contiguous range if start and pa are
			 * suitably aligned
			 */
			if (((start | pa) & cmask) == 0 && may_use_cont)
				protval |= PTE_CONT;

			/*
			 * Clear the contiguous attribute if the remaining
			 * range does not cover a contiguous block
			 */
			if ((end & ~cmask) <= start)
				protval &= ~PTE_CONT;

			/* Put down a block or page mapping */
			*tbl = __pte(__phys_to_pte_val(pa) | protval);
		}
		pa += next - start;
		start = next;
		tbl++;
	}
}

static void __init map_segment(pgd_t **pgd, u64 va_offset, void *start,
			       void *end, pgprot_t prot, bool may_use_cont)
{
	map_range(pgd, ((u64)start + va_offset) & ~PAGE_OFFSET,
		  ((u64)end + va_offset) & ~PAGE_OFFSET, (u64)start,
		  prot, 4 - CONFIG_PGTABLE_LEVELS, (pte_t *)init_pg_dir,
		  may_use_cont);
}

static void __init unmap_segment(u64 va_offset, void *start, void *end)
{
	map_range(NULL, ((u64)start + va_offset) & ~PAGE_OFFSET,
		  ((u64)end + va_offset) & ~PAGE_OFFSET, (u64)start,
		  __pgprot(0), 4 - CONFIG_PGTABLE_LEVELS, (pte_t *)init_pg_dir,
		  false);
}

static bool __init arm64_early_this_cpu_has_bti(void)
{
	u64 pfr1;

	if (!IS_ENABLED(CONFIG_ARM64_BTI_KERNEL))
		return false;

	pfr1 = read_sysreg(ID_AA64PFR1_EL1);
	pfr1 &= ~id_aa64pfr1_override.mask;
	pfr1 |= id_aa64pfr1_override.val;

	return cpuid_feature_extract_unsigned_field(pfr1,
						    ID_AA64PFR1_EL1_BT_SHIFT);
}

static bool __init arm64_early_this_cpu_has_e0pd(void)
{
	u64 mmfr2;

	if (!IS_ENABLED(CONFIG_ARM64_E0PD))
		return false;

	mmfr2 = read_sysreg_s(SYS_ID_AA64MMFR2_EL1);
	return cpuid_feature_extract_unsigned_field(mmfr2,
						    ID_AA64MMFR2_EL1_E0PD_SHIFT);
}

static bool __init arm64_early_this_cpu_has_pac(void)
{
	u64 isar1, isar2;
	u8 feat;

	if (!IS_ENABLED(CONFIG_ARM64_PTR_AUTH_KERNEL))
		return false;

	isar1 = read_sysreg(ID_AA64ISAR1_EL1);
	isar1 &= ~id_aa64isar1_override.mask;
	isar1 |= id_aa64isar1_override.val;
	feat = cpuid_feature_extract_unsigned_field(isar1,
						    ID_AA64ISAR1_EL1_APA_SHIFT);
	if (feat)
		return true;

	feat = cpuid_feature_extract_unsigned_field(isar1,
						    ID_AA64ISAR1_EL1_API_SHIFT);
	if (feat)
		return true;

	isar2 = read_sysreg_s(SYS_ID_AA64ISAR2_EL1);
	isar2 &= ~id_aa64isar2_override.mask;
	isar2 |= id_aa64isar2_override.val;
	feat = cpuid_feature_extract_unsigned_field(isar2,
						    ID_AA64ISAR2_EL1_APA3_SHIFT);
	return feat;
}

static void __init map_kernel(u64 kaslr_offset, u64 va_offset)
{
	bool enable_scs = IS_ENABLED(CONFIG_UNWIND_PATCH_PAC_INTO_SCS);
	bool twopass = IS_ENABLED(CONFIG_RELOCATABLE);
	pgd_t *pgdp = (void *)init_pg_dir + PAGE_SIZE;
	pgprot_t text_prot = PAGE_KERNEL_ROX;
	pgprot_t data_prot = PAGE_KERNEL;
	pgprot_t prot;

	/*
	 * External debuggers may need to write directly to the text mapping to
	 * install SW breakpoints. Allow this (only) when explicitly requested
	 * with rodata=off.
	 */
	if (cpuid_feature_extract_unsigned_field(arm64_sw_feature_override.val,
						 ARM64_SW_FEATURE_OVERRIDE_RODATA_OFF))
		text_prot = PAGE_KERNEL_EXEC;

	/*
	 * We only enable the shadow call stack dynamically if we are running
	 * on a system that does not implement PAC or BTI. PAC and SCS provide
	 * roughly the same level of protection, and BTI relies on the PACIASP
	 * instructions serving as landing pads, preventing us from patching
	 * those instructions into something else.
	 */
	if (arm64_early_this_cpu_has_pac())
		enable_scs = false;

	if (arm64_early_this_cpu_has_bti()) {
		enable_scs = false;

		/*
		 * If we have a CPU that supports BTI and a kernel built for
		 * BTI then mark the kernel executable text as guarded pages
		 * now so we don't have to rewrite the page tables later.
		 */
		text_prot = __pgprot_modify(text_prot, PTE_GP, PTE_GP);
	}

	/* Map all code read-write on the first pass if needed */
	twopass |= enable_scs;
	prot = twopass ? data_prot : text_prot;

	map_segment(&pgdp, va_offset, _stext, _etext, prot, !twopass);
	map_segment(&pgdp, va_offset, __start_rodata, __inittext_begin, data_prot, false);
	map_segment(&pgdp, va_offset, __inittext_begin, __inittext_end, prot, false);
	map_segment(&pgdp, va_offset, __initdata_begin, __initdata_end, data_prot, false);
	map_segment(&pgdp, va_offset, _data, _end, data_prot, true);
	dsb(ishst);

	idmap_cpu_replace_ttbr1(init_pg_dir);

	if (twopass) {
		if (IS_ENABLED(CONFIG_RELOCATABLE))
			relocate_kernel(kaslr_offset);

		if (enable_scs) {
			scs_patch(__eh_frame_start + va_offset,
				  __eh_frame_end - __eh_frame_start);
			asm("ic ialluis");

			dynamic_scs_is_enabled = true;
		}

		/*
		 * Unmap the text region before remapping it, to avoid
		 * potential TLB conflicts when creating the contiguous
		 * descriptors.
		 */
		unmap_segment(va_offset, _stext, _etext);
		dsb(ishst);
		isb();
		__tlbi(vmalle1);
		isb();

		/*
		 * Remap these segments with different permissions
		 * No new page table allocations should be needed
		 */
		map_segment(NULL, va_offset, _stext, _etext, text_prot, true);
		map_segment(NULL, va_offset, __inittext_begin, __inittext_end,
			    text_prot, false);
		dsb(ishst);
	}
}

asmlinkage void __init early_map_kernel(u64 boot_status, void *fdt)
{
	static char const chosen_str[] __initconst = "/chosen";
	int chosen = fdt_path_offset(fdt, chosen_str);
	u64 va_base, pa_base = (u64)&_text;
	u64 kaslr_offset = pa_base % MIN_KIMG_ALIGN;

	/* Clear BSS and the initial page tables */
	memset(__bss_start, 0, (u64)init_pg_end - (u64)__bss_start);

	/* Parse the command line for CPU feature overrides */
	init_feature_override(boot_status, fdt, chosen);

	/*
	 * The virtual KASLR displacement modulo 2MiB is decided by the
	 * physical placement of the image, as otherwise, we might not be able
	 * to create the early kernel mapping using 2 MiB block descriptors. So
	 * take the low bits of the KASLR offset from the physical address, and
	 * fill in the high bits from the seed.
	 */
	if (IS_ENABLED(CONFIG_RANDOMIZE_BASE)) {
		u64 kaslr_seed = kaslr_early_init(fdt, chosen);

		kaslr_offset |= kaslr_seed & ~(MIN_KIMG_ALIGN - 1);

		/*
		 * Assume that any CPU that does not implement E0PD needs KPTI
		 * to ensure that KASLR randomized addresses will not leak.
		 * This means we need to use non-global mappings for the kernel
		 * text and data.
		 */
		if (kaslr_seed && !arm64_early_this_cpu_has_e0pd())
			arm64_use_ng_mappings = true;
	}

	va_base = KIMAGE_VADDR + kaslr_offset;
	map_kernel(kaslr_offset, va_base - pa_base);
}
