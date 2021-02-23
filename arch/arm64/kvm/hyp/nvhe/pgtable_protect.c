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

void handle___pkvm_xchg_ro_pte(struct kvm_cpu_context *host_ctxt)
{
	//DECLARE_REG(pgd_t *, pgdp, host_ctxt, 1);
	DECLARE_REG(u64, address, host_ctxt, 2);
	DECLARE_REG(u64, ptep, host_ctxt, 3);
	DECLARE_REG(u64, pteval, host_ctxt, 4);
	pte_t *ptaddr;

	ptaddr = hyp_fixmap_map(ptep);
	cpu_reg(host_ctxt, 1) = xchg_relaxed(&pte_val(*ptaddr), pteval);
	hyp_fixmap_unmap();
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
	if ((oldval ^ newval) & ~(PTE_DIRTY|PTE_WRITE|PTE_AF|PTE_RDONLY)) {
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
