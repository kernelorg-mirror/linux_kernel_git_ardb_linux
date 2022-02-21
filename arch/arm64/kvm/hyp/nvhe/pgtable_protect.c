// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2022 Google LLC
 * Author: Ard Biesheuvel <ardb@google.com>
 */

#include <linux/kvm_host.h>

#include <asm/kvm_mmu.h>

#include <nvhe/mem_protect.h>
#include <nvhe/mm.h>
#include <nvhe/pgtable_protect.h>
#include <nvhe/trap_handler.h>

static int kvm_pgtable_ptp_remap_page(u64 addr, bool readonly)
{
	enum kvm_pgtable_prot prot = PKVM_HOST_MEM_PROT & ~KVM_PGTABLE_PROT_W;
	int ret;

	addr &= PAGE_MASK;

	hyp_spin_lock(&host_kvm.lock);

	// TODO check host ownership

	if (readonly) {
		ret = host_stage2_idmap_locked(addr, PAGE_SIZE, prot);
		/*
		 * We'll get -EAGAIN if the mapping already exists, but with
		 * different permission attributes.
		 */
		// TODO check that the next call will only affect a single page
		if (ret == -EAGAIN)
			ret = kvm_pgtable_stage2_wrprotect(&host_kvm.pgt, addr,
							   PAGE_SIZE);
		__kvm_tlb_flush_vmid_ipa(host_kvm.pgt.mmu, addr, 3);
	} else {
		/* unmap so the next access will page it in as R/W */
		ret = kvm_pgtable_stage2_unmap(&host_kvm.pgt, addr, PAGE_SIZE);
	}
	hyp_spin_unlock(&host_kvm.lock);
	BUG_ON(ret);
	return ret;
}

static bool kvm_pgtable_ptp_is_pgroot(u64 addr)
{
	u8 flags = READ_ONCE(hyp_phys_to_page(addr)->ptp_flags);

	return flags == HYP_PAGE_PTP_PGROOT;
}

static bool kvm_pgtable_ptp_is_untracked(u64 addr)
{
	u8 flags = READ_ONCE(hyp_phys_to_page(addr)->ptp_flags);

	return flags == HYP_PAGE_PTP_UNTRACKED;
}

static bool kvm_pgtable_ptp_make_pgtable(u64 addr)
{
	u8 *flags = &hyp_phys_to_page(addr)->ptp_flags;

	if (cmpxchg_relaxed(flags, HYP_PAGE_PTP_UNTRACKED,
			    HYP_PAGE_PTP_PGTABLE) != HYP_PAGE_PTP_UNTRACKED)
		return false;

	kvm_pgtable_ptp_remap_page(addr, true);
	return true;
}

static bool kvm_pgtable_ptp_make_pgroot(u64 addr)
{
	u8 *flags = &hyp_phys_to_page(addr)->ptp_flags;

	if (cmpxchg_relaxed(flags, HYP_PAGE_PTP_UNTRACKED,
			    HYP_PAGE_PTP_PGROOT) != HYP_PAGE_PTP_UNTRACKED)
		return false;

	kvm_pgtable_ptp_remap_page(addr, true);
	return true;
}

static void kvm_pgtable_ptp_make_untracked(u64 addr)
{
	u8 old;

	if (!addr_is_memory(addr))
		return;

	old = xchg_relaxed(&hyp_phys_to_page(addr)->ptp_flags,
			   HYP_PAGE_PTP_UNTRACKED);

	if (old == HYP_PAGE_PTP_PGTABLE)
		kvm_pgtable_ptp_remap_page(addr, false);
}

static bool kvm_pgtable_ptp_clear_pgroot(u64 addr)
{
	u8 *flags = &hyp_phys_to_page(addr)->ptp_flags;

	if (cmpxchg_relaxed(flags, HYP_PAGE_PTP_PGROOT,
			    HYP_PAGE_PTP_UNTRACKED) != HYP_PAGE_PTP_PGROOT)
		return false;
	kvm_pgtable_ptp_remap_page(addr, false);
	return true;
}

static void inject_ptp_host_exception(struct kvm_cpu_context *host_ctxt)
{
	inject_host_exception(host_ctxt,
			      ESR_ELx_EC_UNKNOWN << ESR_ELx_EC_SHIFT);
}

static pteval_t fixmap_get_pteval(phys_addr_t phys_ptep, int idx)
{
	const void *p = hyp_fixmap_map(phys_ptep + 8 * idx);
	pteval_t ret = p ? *(pteval_t *)p : 0x0;
	hyp_fixmap_unmap();
	return ret;
}

/*
 * Resolve @address against the page table hierarchy starting from @pgd, and
 * decide whether @pteval appearing at @ptep amounts to a block or page mapping
 * for @address. In doubt, return false.
 */
static bool is_block_or_page_mapping(phys_addr_t pgd, u64 addr, pte_t *ptep,
				     u64 pteval, int *level)
{
	bool is_block = false;
	phys_addr_t p4d;
	phys_addr_t pud;
	phys_addr_t pmd;
	phys_addr_t pte;

	*level = -1;

	/* not enough information to decide - err on the side of caution */
	if (!pgd || addr == ULONG_MAX)
		return false;

	/* check for block mapping - encodings are the same for levels < 3 */
	if ((pteval & PMD_TYPE_MASK) == PMD_TYPE_SECT)
		is_block = true;

	/*
	 * pteval is a valid entry, and could describe either a table mapping
	 * or a page mapping, depending on which level it happens to appear at.
	 * Walk the page tables to figure this out.
	 */
	if (((u64)ptep & PAGE_MASK) == pgd) {
		*level = 4 - CONFIG_PGTABLE_LEVELS;
		return is_block && *level > 0;
	}

	p4d = __pgd_to_phys(__pgd(fixmap_get_pteval(pgd, pgd_index(addr))));
	if (__is_defined(__PAGETABLE_P4D_FOLDED)) {
		pud = p4d;
	} else {
		if (((u64)ptep & PAGE_MASK) == p4d) {
			*level = 0;
			return false;
		}
		pud = __p4d_to_phys(__p4d(fixmap_get_pteval(p4d, p4d_index(addr))));
	}
	if (__is_defined(__PAGETABLE_PUD_FOLDED)) {
		pmd = pud;
	} else {
		if (((u64)ptep & PAGE_MASK) == pud) {
			*level = 1;
			return is_block;
		}
		pmd = __pud_to_phys(__pud(fixmap_get_pteval(pud, pud_index(addr))));
	}

	if (__is_defined(__PAGETABLE_PMD_FOLDED)) {
		pte = pmd;
	} else {
		if (((u64)ptep & PAGE_MASK) == pmd) {
			*level = 2;
			return is_block;
		}
		pte = __pmd_to_phys(__pmd(fixmap_get_pteval(pmd, pmd_index(addr))));
	}

	if (((u64)ptep & PAGE_MASK) == pte) {
		*level = 3;
		return true;
	}

	return false;
}

/*
 * Check whether creating @count valid entries at @level for the target pages
 * described in @pteval[] is permitted by the policy.
 */
static bool pkvm_pgtable_policy_allows(phys_addr_t phys_pgdp, bool is_table,
				       int level, const u64 *pteval, int count)
{
	int i;

	if (level == 3) {
		/*
		 * Don't allow page mappings of pgtable pages, to avoid
		 * mistaking them for table mappings upon release.
		 */
		for (i = 0; i < count; i++) {
			u64 pa = __pte_to_phys(__pte(pteval[i]));

			if ((pteval[i] & PTE_VALID) &&
			    addr_is_memory(pa) &&
			    !kvm_pgtable_ptp_is_untracked(pa))
				return false;
		}
	}

	//
	//
	// TODO invoke policy engine
	//
	//

	return true;
}

/*
 * Life cycle of a EL1 page table
 * ==============================
 *
 * EL1 is in charge of allocating and freeing pages to be used for intermediate
 * page tables, but we have to keep track of them at EL2 in order to maintain
 * read-only mappings of those pages at stage 2, to force the EL1 OS to use the
 * HYP api to make modifications to the layout of each virtual address space.
 *
 * While root page tables are assigned and released explicitly, intermediate
 * page tables are tracked by interpreting the changes made by the EL1 OS using
 * the routine below. If the call results in a table entry to be created or
 * removed, this fact must be reflected in the stage 2 tracking of the page.
 *
 * So the simple rules are:
 * - if the update creates a table mapping, the target page is remapped
 *   read-only at stage 2, wiped (*) and marked as a table page, unless it
 *   is already in that state, in which case the update is rejected;
 * - if the update removes a table mapping, the target page is marked as
 *   untracked, and remapped read-write again.
 *
 * There are two issues that make this slightly more complicated than desired:
 * - The core mm layer in Linux does not provide a target address for every page
 *   table modification arriving through the API below, but only for ones that
 *   create block or page mappings.
 * - we cannot easily distinguish between level 3 page mappings and higher level
 *   table mappings, given that they use the same descriptor bit.
 *
 * A new valid mapping is assumed to be a table mapping unless the pgd+address
 * arguments identify it positively as a block or page mapping. The target of a
 * new table mapping must not be in pgroot or pgtable state, and will be wiped
 * and moved into pgtable state before the new valid mapping is created.
 *
 * If the new descriptor value is 0x0 and the entry is covered by a pgroot or
 * pgtable page, and refers to a page that is currently in pgtable state, the
 * page is reverted to default state after the old valid mapping is removed.
 *
 * (*) migration of level 2 entries is permitted as well, but only if all valid
 *     level 3 mappings they cover comply with the policy.
 */
void handle___pkvm_xchg_ro_pte(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(u64, pgdp, host_ctxt, 1);
	DECLARE_REG(u64, address, host_ctxt, 2);
	DECLARE_REG(u64, ptep, host_ctxt, 3);
	DECLARE_REG(u64, pteval, host_ctxt, 4);
	bool is_tracked;
	pte_t *ptaddr;
	u64 oldval;

	is_tracked = !kvm_pgtable_ptp_is_untracked(ptep);

	if (is_tracked && (pteval & PTE_VALID)) {
		bool is_table;
		int level;

		/* valid entries must be created in the context of a pgd[] */
		if (!pgdp) {
			// TODO check whether pgdp is pgroot??
			inject_ptp_host_exception(host_ctxt);
			return;
		}

		is_table = !is_block_or_page_mapping(pgdp, address, (pte_t *)ptep,
						     pteval, &level);

		if (!pkvm_pgtable_policy_allows(pgdp, is_table, level, &pteval, 1)) {
			inject_ptp_host_exception(host_ctxt);
			return;
		}

		if (is_table) {
			u64 pa = __pte_to_phys(__pte(pteval));

			if (!kvm_pgtable_ptp_make_pgtable(pa)) {
				inject_ptp_host_exception(host_ctxt);
				return;
			}

			ptaddr = hyp_fixmap_map(pa);

			if (level == 2) {
				// We permit moving level 2 entries as long
				// as all valid level 3 entry they carry pass
				// the policy check
				if (!pkvm_pgtable_policy_allows(pgdp, false, 3,
								(pteval_t *)ptaddr,
								PTRS_PER_PTE)) {
					inject_ptp_host_exception(host_ctxt);
					return;
				}
			} else {
				// wipe the page before first use
				memset(ptaddr, 0, PAGE_SIZE);
			}
			hyp_fixmap_unmap();
		}
	}

	ptaddr = hyp_fixmap_map(ptep);
	oldval = xchg_relaxed(&pte_val(*ptaddr), pteval);
	hyp_fixmap_unmap();

	/*
	 * If the old entry was a valid table or page entry, assume it is the
	 * former and stop tracking it as a page table.
	 * TODO deal with oldval/pteval being valid table mappings of the same page
	 */
	if (is_tracked && (oldval & PTE_TYPE_MASK) == PTE_TYPE_PAGE) {
		/*
		 * If we are removing a mapping from a pgtable/pgroot page and
		 * the entry targets a pgtable page, move it to default state.
		 */
		kvm_pgtable_ptp_make_untracked(__pte_to_phys(__pte(oldval)));
	}
	cpu_reg(host_ctxt, 1) = oldval;
}

void handle___pkvm_cmpxchg_ro_pte(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(u64, ptep, host_ctxt, 1);
	DECLARE_REG(u64, oldval, host_ctxt, 2);
	DECLARE_REG(u64, newval, host_ctxt, 3);
	pte_t *ptaddr;

	/*
	 * cmpxchg_ro_pte() must only be used when updates to mapping attributes
	 * performed by the CPU may race with updates of the access/dirty flags
	 * by the page table walker. If we can enforce this at HYP level, there
	 * is no need to go through the policy check at all.
	 */
	if (((oldval ^ newval) & ~(PTE_DIRTY|PTE_WRITE|PTE_AF|PTE_RDONLY)) ||
	    kvm_pgtable_ptp_is_untracked(ptep)) {
		inject_ptp_host_exception(host_ctxt);
		return;
	}

	ptaddr = hyp_fixmap_map(ptep);
	cpu_reg(host_ctxt, 1) = cmpxchg_relaxed(&pte_val(*ptaddr),
						oldval, newval);
	hyp_fixmap_unmap();
}

void handle___pkvm_assign_pgroot(struct kvm_cpu_context *host_ctxt)
{
	/*
	 * We don't permit the root table's address to be used in TTBRn_EL1 by
	 * the host unless the page is mapped read-only at stage2, and carries
	 * the correct annotation (HYP_PAGE_PTP_PGROOT). If the page is not in
	 * the right state yet, set the correct state and wipe the contents.
	 * This ensures that a root page table only contains entries that were
	 * vetted by the HYP api.
	 */
	DECLARE_REG(u64, pgdp, host_ctxt, 1);
	void *ptaddr;

	// remap the page as r/o at stage, and tag as a pgd[]
	if (!kvm_pgtable_ptp_make_pgroot(pgdp)) {
		inject_ptp_host_exception(host_ctxt);
		return;
	}

	ptaddr = hyp_fixmap_map(pgdp);
	memset(ptaddr, 0, PAGE_SIZE);	// wipe the page before first use
	hyp_fixmap_unmap();
}

void handle___pkvm_release_pgroot(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(u64, pgdp, host_ctxt, 1);
	int i;

	pgdp &= PAGE_MASK;

	hyp_spin_lock(&host_kvm.lock);

	/* check that the root pgtable is not live on any CPU */
	for (i = 0; i < hyp_nr_cpus; i++) {
		const struct kvm_cpu_context *ctx;

		ctx = &per_cpu_ptr(&kvm_host_data, i)->host_ctxt;
		if (pgdp == ttbr_to_phys(ctx->sys_regs[TTBR0_EL1])) {
			inject_ptp_host_exception(host_ctxt);
			hyp_spin_unlock(&host_kvm.lock);
			return;
		}
	}

	hyp_spin_unlock(&host_kvm.lock);

	if (!kvm_pgtable_ptp_clear_pgroot(pgdp))
		inject_ptp_host_exception(host_ctxt);
}

void pkvm_handle_ttbr0_update(struct kvm_cpu_context *host_ctxt, u64 regval)
{
	u64 addr;

	hyp_spin_lock(&host_kvm.lock);

	// TODO stage 2 protection of reserved_pg_dir
	// TODO elide double trap for pgd switch
	addr = ttbr_to_phys(regval);
	if (addr != hyp_virt_to_phys(reserved_pg_dir) &&
	    addr != hyp_virt_to_phys(idmap_pg_dir) &&
	    !kvm_pgtable_ptp_is_pgroot(addr)) {
		inject_ptp_host_exception(host_ctxt);
		hyp_spin_unlock(&host_kvm.lock);
		return;
	}
	host_ctxt->sys_regs[TTBR0_EL1] = regval;
	hyp_spin_unlock(&host_kvm.lock);

	write_sysreg(regval, TTBR0_EL1);
}
