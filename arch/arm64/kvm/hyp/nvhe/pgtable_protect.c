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

void handle___pkvm_xchg_ro_pte(struct kvm_cpu_context *host_ctxt)
{
	//DECLARE_REG(pgd_t *, pgdp, host_ctxt, 1);
	DECLARE_REG(u64, address, host_ctxt, 2);
	DECLARE_REG(pte_t *, ptep, host_ctxt, 3);
	DECLARE_REG(u64, pteval, host_ctxt, 4);
	u64 ptaddr = (u64)kern_hyp_va(ptep) & PAGE_MASK;

	// create stage1@el2 mapping if needed
	__pkvm_create_mappings(ptaddr, PAGE_SIZE, (u64)ptep & PAGE_MASK, PAGE_HYP);

	cpu_reg(host_ctxt, 1) = xchg_relaxed(&pte_val(*kern_hyp_va(ptep)),
					     pteval);
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
	if ((oldval ^ newval) & ~(PTE_DIRTY|PTE_WRITE|PTE_AF|PTE_RDONLY)) {
		inject_external_abort(host_ctxt);
		return;
	}

	// TODO check that ptep points into an active page table

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
