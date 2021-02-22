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
	DECLARE_REG(pte_t *, ptep, host_ctxt, 2);
	DECLARE_REG(u64, pteval, host_ctxt, 3);
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
