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
	DECLARE_REG(u64, ptep, host_ctxt, 2);
	DECLARE_REG(u64, pteval, host_ctxt, 3);
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
