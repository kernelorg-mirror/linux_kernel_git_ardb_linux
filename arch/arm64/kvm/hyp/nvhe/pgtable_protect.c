// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021 Google LLC
 * Author: Ard Biesheuvel <ardb@google.com>
 */

#include <linux/kvm_host.h>

#include <asm/kvm_mmu.h>

#include <nvhe/mem_protect.h>
#include <nvhe/mm.h>
#include <nvhe/pgtable_protect.h>
#include <nvhe/trap_handler.h>

#define KVM_PTE_S2L3_ATTR_UNTRACKED	(BIT(6) | BIT(7))
#define KVM_PTE_S2L3_ATTR_PGROOT	(BIT(6) | BIT(55))
#define KVM_PTE_S2L3_ATTR_PGTABLE	(BIT(6) | BIT(56))

#define KVM_PTE_S2L3_ATTR_PGMASK	(BIT(6) | BIT(7) | BIT(55) | BIT(56))

extern struct hyp_pool host_s2_mem;
extern unsigned long hyp_nr_cpus;

static int stage2_grab_level3_walker(u64 addr, u64 end, u32 level,
				     kvm_pte_t *ptep,
				     enum kvm_pgtable_walk_flags flag,
				     void * const arg)
{
	if (level == 3)
		*(kvm_pte_t **)arg = ptep;

	return 0;
}

/*
 * kvm_pgtable_grab_level3_entry - Return a pointer to the level 3 entry that
 * 				   covers @address in the page tables starting
 * 				   from @pgt. If @mc is non-NULL, it will be
 * 				   used to allocate intermediate tables as
 * 				   needed. Otherwise, NULL is returned if no
 * 				   level 3 entry exists for @addr.
 */
static kvm_pte_t *kvm_pgtable_grab_level3_entry(struct kvm_pgtable *pgt,
						u64 addr, void *mc)
{
	const enum kvm_pgtable_prot prot = KVM_PGTABLE_PROT_R |
					   KVM_PGTABLE_PROT_W |
					   KVM_PGTABLE_PROT_X;
	kvm_pte_t *entry = NULL;
	struct kvm_pgtable_walker walker = {
		.cb		= stage2_grab_level3_walker,
		.arg		= &entry,
		.flags		= KVM_PGTABLE_WALK_LEAF,
	};

	kvm_pgtable_walk(pgt, addr, PAGE_SIZE, &walker);
	if (entry || !mc)
		return entry;

	kvm_pgtable_stage2_map(pgt, addr, PAGE_SIZE, addr, prot, mc);

	kvm_pgtable_walk(pgt, addr, PAGE_SIZE, &walker);
	return entry;
}

static bool kvm_pgtable_stage2_is_pg(struct kvm_pgtable *pgt, u64 addr)
{
	const kvm_pte_t *ptep = kvm_pgtable_grab_level3_entry(pgt, addr, NULL);

	if (!ptep)
		return false;

	switch (smp_load_acquire(ptep) & KVM_PTE_S2L3_ATTR_PGMASK) {
	case KVM_PTE_S2L3_ATTR_PGROOT:
	case KVM_PTE_S2L3_ATTR_PGTABLE:
		return true;
	}
	return false;
}

static bool kvm_pgtable_stage2_is_pgroot(struct kvm_pgtable *pgt, u64 addr)
{
	const kvm_pte_t *ptep = kvm_pgtable_grab_level3_entry(pgt, addr, NULL);

	return ptep && (smp_load_acquire(ptep) &
			KVM_PTE_S2L3_ATTR_PGMASK) == KVM_PTE_S2L3_ATTR_PGROOT;
}

static bool kvm_pgtable_stage2_is_untracked(struct kvm_pgtable *pgt, u64 addr)
{
	const kvm_pte_t *ptep = kvm_pgtable_grab_level3_entry(pgt, addr, NULL);

	// TODO this should check for r/w at any level with s/w bits cleared

	return !ptep || (smp_load_acquire(ptep) &
			 KVM_PTE_S2L3_ATTR_PGMASK) == KVM_PTE_S2L3_ATTR_UNTRACKED;
}

static bool kvm_pgtable_stage2_set_state(struct kvm_pgtable *pgt,
					 struct hyp_pool *pool,
					 u64 addr, u64 from, u64 to)
{
	kvm_pte_t *ptep, old, new;
	bool ret = false;

	if (pool)
		hyp_spin_lock(&host_kvm.lock);

	ptep = kvm_pgtable_grab_level3_entry(pgt, addr, pool);
	if (!ptep)
		goto out;

	old = new = READ_ONCE(*ptep) & ~KVM_PTE_S2L3_ATTR_PGMASK;
	old |= from;
	new |= to;

	ret = (cmpxchg_release(ptep, old, new) == old);

out:
	if (pool)
		hyp_spin_unlock(&host_kvm.lock);
	return ret;
}

static bool kvm_pgtable_stage2_make_pgtable(struct kvm_pgtable *pgt, u64 addr)
{
	return kvm_pgtable_stage2_set_state(pgt, &host_s2_mem, addr,
					    KVM_PTE_S2L3_ATTR_UNTRACKED,
					    KVM_PTE_S2L3_ATTR_PGTABLE);
}

static bool kvm_pgtable_stage2_make_pgroot(struct kvm_pgtable *pgt, u64 addr)
{
	return kvm_pgtable_stage2_set_state(pgt, &host_s2_mem, addr,
					    KVM_PTE_S2L3_ATTR_UNTRACKED,
					    KVM_PTE_S2L3_ATTR_PGROOT);
}

static bool kvm_pgtable_stage2_clear_pgtable(struct kvm_pgtable *pgt, u64 addr)
{
	return kvm_pgtable_stage2_set_state(pgt, NULL, addr,
					    KVM_PTE_S2L3_ATTR_PGTABLE,
					    KVM_PTE_S2L3_ATTR_UNTRACKED);
}

static bool kvm_pgtable_stage2_clear_pgroot(struct kvm_pgtable *pgt, u64 addr)
{
	return kvm_pgtable_stage2_set_state(pgt, NULL, addr,
					    KVM_PTE_S2L3_ATTR_PGROOT,
					    KVM_PTE_S2L3_ATTR_UNTRACKED);
}

static void inject_external_abort(struct kvm_cpu_context *host_ctxt)
{
	struct kvm_vcpu *vcpu = host_ctxt->__hyp_running_vcpu;

	if (vcpu)
		; // TODO

	write_sysreg_el2(read_sysreg_el2(SYS_ELR) - 1, SYS_ELR);
}

/*
 * Resolve @address against the page table hierarchy starting from @pgd, and
 * decide whether @pteval appearing at @ptep amounts to a block or page mapping
 * for @address. In doubt, return false.
 */
static bool is_block_or_page_mapping(pgd_t *pgd, u64 addr, pte_t *ptep,
				     u64 pteval, int *level)
{
	bool is_block = false;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

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
	if (!(((u64)pgd ^ (u64)ptep) & PAGE_MASK)) {
		*level = 4 - CONFIG_PGTABLE_LEVELS;
		return is_block && *level > 0;
	}

	p4d = (p4d_t *)__pgd_to_phys(kern_hyp_va(pgd)[pgd_index(addr)]);
	if (__is_defined(__PAGETABLE_P4D_FOLDED)) {
		pud = (pud_t *)p4d;
	} else {
		if (!(((u64)p4d ^ (u64)ptep) & PAGE_MASK)) {
			*level = 0;
			return false;
		}
		pud = (pud_t *)__p4d_to_phys(kern_hyp_va(p4d)[p4d_index(addr)]);
	}

	if (__is_defined(__PAGETABLE_PUD_FOLDED)) {
		pmd = (pmd_t *)pud;
	} else {
		if (!(((u64)pud ^ (u64)ptep) & PAGE_MASK)) {
			*level = 1;
			return is_block;
		}
		pmd = (pmd_t *)__pud_to_phys(kern_hyp_va(pud)[pud_index(addr)]);
	}

	if (__is_defined(__PAGETABLE_PMD_FOLDED)) {
		pte = (pte_t *)pmd;
	} else {
		if (!(((u64)pmd ^ (u64)ptep) & PAGE_MASK)) {
			*level = 2;
			return is_block;
		}
		pte = (pte_t *)__pmd_to_phys(kern_hyp_va(pmd)[pmd_index(addr)]);
	}

	if (!(((u64)pte ^ (u64)ptep) & PAGE_MASK)) {
		*level = 3;
		return true;
	}

	return false;
}

/*
 * Check whether creating @count valid entries at @level for the target pages
 * described in @pteval[] is permitted by the policy.
 */
static bool pkvm_pgtable_policy_allows(const pgd_t *pgd, bool is_table,
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
			    kvm_pgtable_stage2_is_pg(&host_kvm.pgt, pa))
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
 * - if the update removes a table mapping, the target page is released and
 *   marked read-write again.
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
	DECLARE_REG(pgd_t *, pgdp, host_ctxt, 1);
	DECLARE_REG(u64, address, host_ctxt, 2);
	DECLARE_REG(pte_t *, ptep, host_ctxt, 3);
	DECLARE_REG(u64, pteval, host_ctxt, 4);
	bool is_pgtable;
	u64 oldval;

	is_pgtable = kvm_pgtable_stage2_is_pg(&host_kvm.pgt, (u64)ptep);

	if (is_pgtable && (pteval & PTE_VALID)) {
		bool is_table;
		int level;

		/* valid entries must be created in the context of a pgd[] */
		if (!pgdp) {
			// TODO check whether pgdp is pgroot??
			inject_external_abort(host_ctxt);
			return;
		}

		is_table = !is_block_or_page_mapping(pgdp, address, ptep,
						     pteval, &level);

		if (!pkvm_pgtable_policy_allows(pgdp, is_table, level, &pteval, 1)) {
			inject_external_abort(host_ctxt);
			return;
		}

		if (is_table) {
			u64 pa = __pte_to_phys(__pte(pteval));

			if (!kvm_pgtable_stage2_make_pgtable(&host_kvm.pgt, pa)) {
				inject_external_abort(host_ctxt);
				return;
			}

			// map the page table at hyp so we can manipulate it
			__pkvm_create_mappings(kern_hyp_va(pa), PAGE_SIZE, pa,
					       PAGE_HYP);

			if (level == 2) {
				// We permit moving level 2 entries as long
				// as all valid level 3 entry they carry pass
				// the policy check
				if (!pkvm_pgtable_policy_allows(pgdp, false, 3,
								(u64 *)kern_hyp_va(pa),
								PTRS_PER_PTE)) {
					inject_external_abort(host_ctxt);
					return;
				}
			} else {
				// wipe the page before first use
				memset((void *)kern_hyp_va(pa), 0, PAGE_SIZE);
			}
		}
	}

	if (!is_pgtable &&
	    kvm_pgtable_stage2_is_untracked(&host_kvm.pgt, (u64)ptep)) {
		u64 ptaddr = (u64)kern_hyp_va(ptep) & PAGE_MASK;

		/*
		 * If ptep points into a page that we are not tracking, it may
		 * not be mapped at stage 2 yet.
		 */
		__pkvm_create_mappings(ptaddr, PAGE_SIZE, (u64)ptep & PAGE_MASK,
				       PAGE_HYP);
	}

	oldval = xchg_relaxed(&pte_val(*kern_hyp_va(ptep)), pteval);

	/*
	 * If the old entry was a valid table or page entry, assume it is the
	 * former and stop tracking it as a page table.
	 */
	if (is_pgtable && (oldval & PTE_TYPE_MASK) == PTE_TYPE_PAGE) {
		/*
		 * If we are removing a mapping from a pgtable/pgroot page and
		 * the entry targets a pgtable page, move it to default state.
		 */
		kvm_pgtable_stage2_clear_pgtable(&host_kvm.pgt,
						 __pte_to_phys(__pte(oldval)));
	}
	cpu_reg(host_ctxt, 1) = oldval;
}

void handle___pkvm_cmpxchg_ro_pte(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(pte_t *, ptep, host_ctxt, 1);
	DECLARE_REG(u64, oldval, host_ctxt, 2);
	DECLARE_REG(u64, newval, host_ctxt, 3);

	/*
	 * cmpxchg_ro_pte() must only be used when updates to mapping attributes
	 * performed by the CPU may race with updates of the access/dirty flags
	 * by the page table walker. If we can enforce this at HYP level, there
	 * is no need to go through the policy check at all.
	 */
	if (((oldval ^ newval) & ~(PTE_DIRTY|PTE_WRITE|PTE_AF|PTE_RDONLY)) ||
	    !kvm_pgtable_stage2_is_pg(&host_kvm.pgt, (u64)ptep)) {
		inject_external_abort(host_ctxt);
		return;
	}

	cpu_reg(host_ctxt, 1) = cmpxchg_relaxed(&pte_val(*kern_hyp_va(ptep)),
						oldval, newval);
}

void handle___pkvm_assign_pgroot(struct kvm_cpu_context *host_ctxt)
{
	/*
	 * We don't permit the root table's address to be used in TTBRn_EL1 by
	 * the host unless the page is mapped read-only at stage2, and carries
	 * the correct annotation (rt@s2). If the page is not in the correct
	 * state yet, set the correct state and wipe the contents. This ensures
	 * that a root page table only contains entries that were vetted by the
	 * HYP api.
	 */
	DECLARE_REG(pgd_t *, pgdp, host_ctxt, 1);
	u64 ptaddr = (u64)kern_hyp_va(pgdp) & PAGE_MASK;

	// remap the page as r/o at stage, and tag as a pgd[]
	if (!kvm_pgtable_stage2_make_pgroot(&host_kvm.pgt, (u64)pgdp)) {
		inject_external_abort(host_ctxt);
		return;
	}

	// create stage1@el2 mapping if needed
	__pkvm_create_mappings(ptaddr, PAGE_SIZE, (u64)pgdp & PAGE_MASK, PAGE_HYP);

	// wipe the page before first use
	memset((void *)ptaddr, 0, PAGE_SIZE);
}

void handle___pkvm_release_pgroot(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(pgd_t *, pgdp, host_ctxt, 1);
	u64 ptaddr = (u64)kern_hyp_va(pgdp) & PAGE_MASK;
	int i;

	hyp_spin_lock(&host_kvm.lock);

	/* check that the root pgtable is not live on any CPU */
	for (i = 0; i < hyp_nr_cpus; i++) {
		const struct kvm_cpu_context *ctx;

		ctx = &per_cpu_ptr(&kvm_host_data, i)->host_ctxt;
		if (ptaddr == (ctx->sys_regs[TTBR0_EL1] &
			       ~(TTBR_ASID_MASK | TTBR_CNP_BIT))) {
			inject_external_abort(host_ctxt);
			hyp_spin_unlock(&host_kvm.lock);
			return;
		}
	}

	if (!kvm_pgtable_stage2_clear_pgroot(&host_kvm.pgt, (u64)pgdp))
		inject_external_abort(host_ctxt);

	hyp_spin_unlock(&host_kvm.lock);
}

void pkvm_handle_ttbr0_update(struct kvm_cpu_context *host_ctxt, u64 regval)
{
	u64 addr;

	hyp_spin_lock(&host_kvm.lock);

	// TODO stage 2 protection of reserved_pg_dir
	// TODO elide double trap for pgd switch
	addr = regval & ~(TTBR_ASID_MASK | TTBR_CNP_BIT);
	if (addr != hyp_virt_to_phys(reserved_pg_dir) &&
	    !kvm_pgtable_stage2_is_pgroot(&host_kvm.pgt, addr)) {
		inject_external_abort(host_ctxt);
		hyp_spin_unlock(&host_kvm.lock);
		return;
	}
	host_ctxt->sys_regs[TTBR0_EL1] = regval;
	hyp_spin_unlock(&host_kvm.lock);

	write_sysreg(regval, TTBR0_EL1);
}
