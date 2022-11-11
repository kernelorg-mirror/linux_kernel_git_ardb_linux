/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Kernel page table mapping
 *
 * Copyright (C) 2015 ARM Ltd.
 */

#ifndef __ASM_KERNEL_PGTABLE_H
#define __ASM_KERNEL_PGTABLE_H

#include <asm/boot.h>
#include <asm/pgtable-hwdef.h>
#include <asm/sparsemem.h>

/*
 * The linear mapping and the start of memory are both 2M aligned (per
 * the arm64 booting.txt requirements). Hence we can use section mapping
 * with 4K (section size = 2M) but not with 16K (section size = 32M) or
 * 64K (section size = 512M).
 */
#ifdef CONFIG_ARM64_4K_PAGES
#define INIT_IDMAP_USES_PMD_MAPS	1
#define INIT_IDMAP_TABLE_LEVELS		(CONFIG_PGTABLE_LEVELS - 1)
#else
#define INIT_IDMAP_USES_PMD_MAPS	0
#define INIT_IDMAP_TABLE_LEVELS		(CONFIG_PGTABLE_LEVELS)
#endif

/*
 * If KASLR is enabled, then an offset K is added to the kernel address
 * space. The bottom 21 bits of this offset are zero to guarantee 2MB
 * alignment for PA and VA.
 *
 * For each pagetable level of the swapper, we know that the shift will
 * be larger than 21 (for the 4KB granule case we use section maps thus
 * the smallest shift is actually 30) thus there is the possibility that
 * KASLR can increase the number of pagetable entries by 1, so we make
 * room for this extra entry.
 *
 * Note KASLR cannot increase the number of required entries for a level
 * by more than one because it increments both the virtual start and end
 * addresses equally (the extra entry comes from the case where the end
 * address is just pushed over a boundary and the start address isn't).
 */

#ifdef CONFIG_RANDOMIZE_BASE
#define EARLY_KASLR	(1)
#else
#define EARLY_KASLR	(0)
#endif

#define EARLY_ENTRIES(vstart, vend, shift, add) \
	((((vend) - 1) >> (shift)) - ((vstart) >> (shift)) + 1 + add)

#define EARLY_PGDS(vstart, vend, add) (EARLY_ENTRIES(vstart, vend, PGDIR_SHIFT, add))

#if INIT_IDMAP_TABLE_LEVELS > 3
#define EARLY_PUDS(vstart, vend, add) (EARLY_ENTRIES(vstart, vend, PUD_SHIFT, add))
#else
#define EARLY_PUDS(vstart, vend, add) (0)
#endif

#if INIT_IDMAP_TABLE_LEVELS > 2
#define EARLY_PMDS(vstart, vend, add) (EARLY_ENTRIES(vstart, vend, INIT_IDMAP_TABLE_SHIFT, add))
#else
#define EARLY_PMDS(vstart, vend, add) (0)
#endif

#define EARLY_PAGES(vstart, vend, add) ( 1 			/* PGDIR page */				\
			+ EARLY_PGDS((vstart), (vend), add) 	/* each PGDIR needs a next level page table */	\
			+ EARLY_PUDS((vstart), (vend), add)	/* each PUD needs a next level page table */	\
			+ EARLY_PMDS((vstart), (vend), add))	/* each PMD needs a next level page table */
#define INIT_DIR_SIZE (PAGE_SIZE * (EARLY_PAGES(KIMAGE_VADDR, _end, EARLY_KASLR) + EARLY_SEGMENT_EXTRA_PAGES))

/* the initial ID map may need two extra pages if it needs to be extended */
#if VA_BITS < 48
#define INIT_IDMAP_DIR_SIZE	((INIT_IDMAP_DIR_PAGES + 2) * PAGE_SIZE)
#else
#define INIT_IDMAP_DIR_SIZE	(INIT_IDMAP_DIR_PAGES * PAGE_SIZE)
#endif
#define INIT_IDMAP_DIR_PAGES	EARLY_PAGES(KIMAGE_VADDR, _end + MAX_FDT_SIZE + INIT_IDMAP_BLOCK_SIZE, 1)

/* Initial memory map size */
#if INIT_IDMAP_USES_PMD_MAPS
#define INIT_IDMAP_BLOCK_SHIFT	PMD_SHIFT
#define INIT_IDMAP_BLOCK_SIZE	PMD_SIZE
#define INIT_IDMAP_TABLE_SHIFT	PUD_SHIFT
#else
#define INIT_IDMAP_BLOCK_SHIFT	PAGE_SHIFT
#define INIT_IDMAP_BLOCK_SIZE	PAGE_SIZE
#define INIT_IDMAP_TABLE_SHIFT	PMD_SHIFT
#endif

/* The number of segments in the kernel image (text, rodata, inittext, initdata, data+bss) */
#define KERNEL_SEGMENT_COUNT	5

#if INIT_IDMAP_BLOCK_SIZE > SEGMENT_ALIGN
#define EARLY_SEGMENT_EXTRA_PAGES (KERNEL_SEGMENT_COUNT + 1)
#else
#define EARLY_SEGMENT_EXTRA_PAGES 0
#endif

/*
 * Initial memory map attributes.
 */
#if INIT_IDMAP_USES_PMD_MAPS
#define INIT_IDMAP_RW_MMUFLAGS	(PMD_ATTRINDX(MT_NORMAL) | PMD_TYPE_SECT | PMD_SECT_AF | PMD_SECT_S)
#define INIT_IDMAP_RX_MMUFLAGS	(INIT_IDMAP_RW_MMUFLAGS | PMD_SECT_RDONLY)
#else
#define INIT_IDMAP_RW_MMUFLAGS	(PTE_ATTRINDX(MT_NORMAL) | PTE_TYPE_PAGE | PTE_AF | PTE_SHARED)
#define INIT_IDMAP_RX_MMUFLAGS	(INIT_IDMAP_RW_MMUFLAGS | PTE_RDONLY)
#endif

/*
 * To make optimal use of block mappings when laying out the linear
 * mapping, round down the base of physical memory to a size that can
 * be mapped efficiently, i.e., either PUD_SIZE (4k granule) or PMD_SIZE
 * (64k granule), or a multiple that can be mapped using contiguous bits
 * in the page tables: 32 * PMD_SIZE (16k granule)
 */
#if defined(CONFIG_ARM64_4K_PAGES)
#define ARM64_MEMSTART_SHIFT		PUD_SHIFT
#elif defined(CONFIG_ARM64_16K_PAGES)
#define ARM64_MEMSTART_SHIFT		CONT_PMD_SHIFT
#else
#define ARM64_MEMSTART_SHIFT		PMD_SHIFT
#endif

/*
 * sparsemem vmemmap imposes an additional requirement on the alignment of
 * memstart_addr, due to the fact that the base of the vmemmap region
 * has a direct correspondence, and needs to appear sufficiently aligned
 * in the virtual address space.
 */
#if ARM64_MEMSTART_SHIFT < SECTION_SIZE_BITS
#define ARM64_MEMSTART_ALIGN	(1UL << SECTION_SIZE_BITS)
#else
#define ARM64_MEMSTART_ALIGN	(1UL << ARM64_MEMSTART_SHIFT)
#endif

#endif	/* __ASM_KERNEL_PGTABLE_H */
