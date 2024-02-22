// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2023 Google LLC
// Author: Ard Biesheuvel <ardb@google.com>

#include <linux/types.h>
#include <linux/sizes.h>

#include <asm/memory.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>

#include "pi.h"

static u64 __init early_linear_alloc(void *ctx)
{
	pte_t (**ptep)[PTRS_PER_PTE] = ctx;

	return (u64)(*ptep)++;
}

/**
 * map_range - Map a contiguous range of physical pages into virtual memory
 *
 * @pgalloc:		Callback to allocate a new page table. If %NULL, then
 *			@pgalloc_ctx is assumed to be the address of a pointer
 *			variable holding the physical address of an array of
 *			available pages from which to allocate page tables.
 * @pgalloc_ctx:	Opaque context argument for @pgalloc
 * @start:		Virtual address of the start of the range
 * @end:		Virtual address of the end of the range (exclusive)
 * @pa:			Physical address of the start of the range
 * @prot:		Access permissions of the range. If PTE_CONT is included,
 *			it will be set as appropriate on contiguous level 3 ranges.
 *			If PTE_TABLE_BIT is included, only table and page mappings
 *			are created, and block mappings are avoided.
 * @level:		Translation level for the mapping
 * @tbl:		The level @level page table to create the mappings in
 * @va_offset:		Offset between a physical page and its current mapping
 * 			in the VA space
 */
int __init map_range(u64 (*pgalloc)(void *ctx), void *pgalloc_ctx, u64 start,
		     u64 end, u64 pa, const pgprot_t prot, int level, pte_t *tbl,
		     u64 va_offset)
{
	u64 cmask = (level == 3) ? CONT_PTE_SIZE - 1 : U64_MAX;
	u64 protval = pgprot_val(prot) & ~(PTE_CONT | PTE_TYPE_MASK);
	bool pages_only = pgprot_val(prot) & PTE_TABLE_BIT;
	bool may_use_cont = pgprot_val(prot) & PTE_CONT;
	int lshift = (3 - level) * (PAGE_SHIFT - 3);
	u64 lmask = (PAGE_SIZE << lshift) - 1;

	start	&= PAGE_MASK;
	pa	&= PAGE_MASK;

	/* Advance tbl to the entry that covers start */
	tbl += (start >> (lshift + PAGE_SHIFT)) % PTRS_PER_PTE;

	/*
	 * Set the right block/page bits for this level unless we are
	 * clearing the mapping
	 */
	if (protval)
		protval |= (level < 3) ? PMD_TYPE_SECT : PTE_TYPE_PAGE;

	if (!pgalloc)
		pgalloc = early_linear_alloc;

	while (start < end) {
		u64 next = min((start | lmask) + 1, PAGE_ALIGN(end));
		int ret;

		if (level < 3 && (pages_only || (start | next | pa) & lmask)) {
			/*
			 * This chunk needs a finer grained mapping. Create a
			 * table mapping if necessary and recurse.
			 */
			if (pte_none(*tbl) && protval) {
				u64 pg = pgalloc(pgalloc_ctx);

				if (!pg)
					return -ENOMEM;

				*tbl = __pte(__phys_to_pte_val(pg) |
					     PMD_TYPE_TABLE | PMD_TABLE_UXN);
			}
			if (!pte_none(*tbl)) {
				ret = map_range(pgalloc, pgalloc_ctx, start,
						next, pa, prot, level + 1,
						(pte_t *)(__pte_to_phys(*tbl) + va_offset),
						va_offset);
				if (ret)
					return ret;
			}
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

	return 0;
}

asmlinkage u64 __init create_init_idmap(pgd_t *pg_dir, pteval_t clrmask)
{
	u64 ptep = (u64)pg_dir + PAGE_SIZE;
	pgprot_t text_prot = PAGE_KERNEL_ROX;
	pgprot_t data_prot = PAGE_KERNEL;

	clrmask |= PTE_TABLE_BIT; // allow block mappings
	pgprot_val(text_prot) &= ~clrmask;
	pgprot_val(data_prot) &= ~clrmask;

	map_range(NULL, &ptep, (u64)_stext, (u64)__initdata_begin, (u64)_stext,
		  text_prot, IDMAP_ROOT_LEVEL, (pte_t *)pg_dir, 0);
	map_range(NULL, &ptep, (u64)__initdata_begin, (u64)_end, (u64)__initdata_begin,
		  data_prot, IDMAP_ROOT_LEVEL, (pte_t *)pg_dir, 0);

	return ptep;
}
