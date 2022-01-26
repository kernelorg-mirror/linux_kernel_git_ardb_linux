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
