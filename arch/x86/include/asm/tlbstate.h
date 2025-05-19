/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_TLBSTATE_H
#define _ASM_X86_TLBSTATE_H

#include <linux/types.h>
#include <linux/cache.h>
#include <asm/percpu.h>

#ifndef MODULE

/*
 * 6 because 6 should be plenty and struct tlb_state will fit in two cache
 * lines.
 */
#define TLB_NR_DYN_ASIDS	6

struct tlb_context {
	u64 ctx_id;
	u64 tlb_gen;
};

struct tlb_state {
	/*
	 * cpu_tlbstate.loaded_mm should match CR3 whenever interrupts
	 * are on.  This means that it may not match current->active_mm,
	 * which will contain the previous user mm when we're in lazy TLB
	 * mode even if we've already switched back to swapper_pg_dir.
	 *
	 * During switch_mm_irqs_off(), loaded_mm will be set to
	 * LOADED_MM_SWITCHING during the brief interrupts-off window
	 * when CR3 and loaded_mm would otherwise be inconsistent.  This
	 * is for nmi_uaccess_okay()'s benefit.
	 */
	struct mm_struct *loaded_mm;

#define LOADED_MM_SWITCHING ((struct mm_struct *)1UL)

	/* Last user mm for optimizing IBPB */
	union {
		struct mm_struct	*last_user_mm;
		unsigned long		last_user_mm_spec;
	};

	u16 loaded_mm_asid;
	u16 next_asid;

	/*
	 * If set we changed the page tables in such a way that we
	 * needed an invalidation of all contexts (aka. PCIDs / ASIDs).
	 * This tells us to go invalidate all the non-loaded ctxs[]
	 * on the next context switch.
	 *
	 * The current ctx was kept up-to-date as it ran and does not
	 * need to be invalidated.
	 */
	bool invalidate_other;

#ifdef CONFIG_ADDRESS_MASKING
	/*
	 * Active LAM mode.
	 *
	 * X86_CR3_LAM_U57/U48 shifted right by X86_CR3_LAM_U57_BIT or 0 if LAM
	 * disabled.
	 */
	u8 lam;
#endif

	/*
	 * Mask that contains TLB_NR_DYN_ASIDS+1 bits to indicate
	 * the corresponding user PCID needs a flush next time we
	 * switch to it; see SWITCH_TO_USER_CR3.
	 */
	unsigned short user_pcid_flush_mask;

	/*
	 * Access to this CR4 shadow and to H/W CR4 is protected by
	 * disabling interrupts when modifying either one.
	 */
	unsigned long cr4;

	/*
	 * This is a list of all contexts that might exist in the TLB.
	 * There is one per ASID that we use, and the ASID (what the
	 * CPU calls PCID) is the index into ctxts.
	 *
	 * For each context, ctx_id indicates which mm the TLB's user
	 * entries came from.  As an invariant, the TLB will never
	 * contain entries that are out-of-date as when that mm reached
	 * the tlb_gen in the list.
	 *
	 * To be clear, this means that it's legal for the TLB code to
	 * flush the TLB without updating tlb_gen.  This can happen
	 * (for now, at least) due to paravirt remote flushes.
	 *
	 * NB: context 0 is a bit special, since it's also used by
	 * various bits of init code.  This is fine -- code that
	 * isn't aware of PCID will end up harmlessly flushing
	 * context 0.
	 */
	struct tlb_context ctxs[TLB_NR_DYN_ASIDS];
};
DECLARE_PER_CPU_ALIGNED(struct tlb_state, cpu_tlbstate);

#endif /* MODULE */
#endif /* _ASM_X86_TLBSTATE_H */
