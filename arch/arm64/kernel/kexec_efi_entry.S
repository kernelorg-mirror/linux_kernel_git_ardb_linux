/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Entry, exit and resume helpers for booting EFI images via kexec.
 *
 * At load time, efi_kexec_call() records the kernel's callee-saved register
 * state and calls into Rust, which loads and starts the EFI image. When the
 * image calls ExitBootServices(), efi_kexec_exit_boot_services() captures the
 * image's register state in a struct efi_kexec_resume, and unwinds straight
 * back into efi_kexec_call(), abandoning the frames in between.
 *
 * At reboot time, the position independent code between efi_kexec_resume_start
 * and efi_kexec_resume_end is entered via cpu_soft_restart() from a copy that
 * lives in memory that is preserved across the kexec, with the MMU off, and at
 * EL2 if it is available. It enables the MMU using the identity map prepared
 * at load time, restores the image's register state and returns EFI_SUCCESS
 * from the image's call to ExitBootServices().
 */

#include <linux/linkage.h>

#include <asm/assembler.h>
#include <asm/kexec_efi.h>
#include <asm/sysreg.h>
#include <asm/virt.h>

	.text

/*
 * long efi_kexec_call(long (*fn)(void *), void *arg,
 *		       struct efi_kexec_jmpbuf *jb)
 *
 * Call fn(arg) and return its return value, unless the EFI image successfully
 * calls ExitBootServices(), in which case EFI_KEXEC_SUSPENDED is returned.
 */
SYM_FUNC_START(efi_kexec_call)
	stp	x29, x30, [sp, #-96]!
	mov	x29, sp
	stp	x19, x20, [sp, #16]
	stp	x21, x22, [sp, #32]
	stp	x23, x24, [sp, #48]
	stp	x25, x26, [sp, #64]
	stp	x27, x28, [sp, #80]

	mov	x3, sp
	str	x3, [x2, #EFI_KEXEC_JB_SP]
	adr_l	x3, efi_kexec_jb
	str	x2, [x3]

	/*
	 * Only the A key is reinstated when the image is resumed, so run the
	 * image with the other keys disabled: this does not affect the kernel,
	 * which only uses the A key, including in the interrupt handlers that
	 * may run while the image does. (With VHE, this accesses SCTLR_EL2.)
	 */
	mrs	x3, sctlr_el1
	str	x3, [x2, #EFI_KEXEC_JB_SCTLR]
	mov_q	x4, SCTLR_ELx_ENIB | SCTLR_ELx_ENDA | SCTLR_ELx_ENDB
	bic	x3, x3, x4
	msr	sctlr_el1, x3
	isb

	mov	x3, x0
	mov	x0, x1
	blr	x3

.Lcall_return:
	adr_l	x3, efi_kexec_jb
	ldr	x4, [x3]
	ldr	x4, [x4, #EFI_KEXEC_JB_SCTLR]
	msr	sctlr_el1, x4
	isb
	str	xzr, [x3]
	ldp	x19, x20, [sp, #16]
	ldp	x21, x22, [sp, #32]
	ldp	x23, x24, [sp, #48]
	ldp	x25, x26, [sp, #64]
	ldp	x27, x28, [sp, #80]
	ldp	x29, x30, [sp], #96
	ret
SYM_FUNC_END(efi_kexec_call)

/*
 * efi_status_t efi_kexec_exit_boot_services(efi_handle_t handle,
 *					     unsigned long map_key)
 *
 * The ExitBootServices() implementation exposed to the EFI image. Validate the
 * arguments, and if this succeeds, capture the image's register state and
 * unwind into efi_kexec_call().
 */
SYM_FUNC_START(efi_kexec_exit_boot_services)
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	bl	efi_kexec_ebs_check		// returns struct efi_kexec_resume *
	ldp	x29, x30, [sp], #16
	cbnz	x0, 0f
	mov_q	x0, EFI_KEXEC_EFI_INVALID_PARAMETER
	ret

	/* Capture the image's register state as it was at the time of the call */
0:	stp	x19, x20, [x0, #EFI_KEXEC_RES_X19]
	stp	x21, x22, [x0, #EFI_KEXEC_RES_X19 + 16]
	stp	x23, x24, [x0, #EFI_KEXEC_RES_X19 + 32]
	stp	x25, x26, [x0, #EFI_KEXEC_RES_X19 + 48]
	stp	x27, x28, [x0, #EFI_KEXEC_RES_X19 + 64]
	stp	x29, x30, [x0, #EFI_KEXEC_RES_FP]
	mov	x1, sp
	str	x1, [x0, #EFI_KEXEC_RES_SP]
	stp	d8, d9, [x0, #EFI_KEXEC_RES_D8]
	stp	d10, d11, [x0, #EFI_KEXEC_RES_D8 + 16]
	stp	d12, d13, [x0, #EFI_KEXEC_RES_D8 + 32]
	stp	d14, d15, [x0, #EFI_KEXEC_RES_D8 + 48]

	/*
	 * If pointer authentication is enabled, the image may have signed
	 * return addresses on its stack using the A key, which is this kernel
	 * thread's in-kernel key. Record it so that the resume trampoline can
	 * reinstate it, as the image needs to authenticate those addresses
	 * after it is resumed. (With VHE, this reads SCTLR_EL2.)
	 */
	mrs	x1, sctlr_el1
	and	x1, x1, #SCTLR_ELx_ENIA
	str	x1, [x0, #EFI_KEXEC_RES_ENIA]
	cbz	x1, 1f
	mrs_s	x2, SYS_APIAKEYLO_EL1
	mrs_s	x3, SYS_APIAKEYHI_EL1
	stp	x2, x3, [x0, #EFI_KEXEC_RES_APIA_LO]

	/* Unwind to efi_kexec_call() and return EFI_KEXEC_SUSPENDED */
1:
	adr_l	x1, efi_kexec_jb
	ldr	x1, [x1]
	ldr	x2, [x1, #EFI_KEXEC_JB_SP]
	mov	sp, x2
	mov	x0, #EFI_KEXEC_SUSPENDED
	b	.Lcall_return
SYM_FUNC_END(efi_kexec_exit_boot_services)

	.pushsection ".data", "aw"
	.align	3
SYM_DATA_LOCAL(efi_kexec_jb, .quad 0)
	.popsection

/*
 * Resume trampoline - this code is copied into memory that is preserved
 * across the kexec, and must therefore be position independent.
 *
 * x0: physical address of the struct efi_kexec_resume
 *
 * Entered with the MMU and caches off, at EL2 or EL1. With VHE, HCR_EL2.E2H
 * may be set, in which case the EL1 system register encodings used below
 * access the corresponding EL2 registers.
 */
	.pushsection ".rodata", "a"
	.align	11
SYM_DATA_START(efi_kexec_resume_start)
	/*
	 * Vector table for the resume phase: the old kernel's vectors are no
	 * longer mapped, so make any exception park the CPU in a WFE loop
	 * instead of faulting recursively.
	 */
	.rept	16
	wfe
	b	. - 4
	.balign	0x80
	.endr

.Lresume_entry:
	ldr	x1, [x0, #EFI_KEXEC_RES_MAIR]
	ldr	x2, [x0, #EFI_KEXEC_RES_TCR_EL1]
	ldr	x3, [x0, #EFI_KEXEC_RES_TTBR0]
	ldr	x4, [x0, #EFI_KEXEC_RES_SCTLR_EL1]
	adr	x6, efi_kexec_resume_start

	/* Is FEAT_TCR2 implemented? Then disable PIE, POE etc via TCR2_ELx */
	mrs_s	x7, SYS_ID_AA64MMFR3_EL1
	ubfx	x7, x7, #ID_AA64MMFR3_EL1_TCRX_SHIFT, #4

	/*
	 * Reinstate the pointer authentication A key that the image may have
	 * used to sign return addresses at load time, and enable it below.
	 * The key registers are shared between EL1 and EL2.
	 */
	ldr	x8, [x0, #EFI_KEXEC_RES_ENIA]
	cbz	x8, 5f
	ldp	x9, x10, [x0, #EFI_KEXEC_RES_APIA_LO]
	msr_s	SYS_APIAKEYLO_EL1, x9
	msr_s	SYS_APIAKEYHI_EL1, x10

5:	mrs	x5, CurrentEL
	cmp	x5, #CurrentEL_EL2
	b.ne	1f

	/* Without VHE, TCR_EL2 and SCTLR_EL2 have their own layout */
	mrs	x5, hcr_el2
	tbnz	x5, #HCR_EL2_E2H_SHIFT, 0f
	ldr	x2, [x0, #EFI_KEXEC_RES_TCR_EL2]
	ldr	x4, [x0, #EFI_KEXEC_RES_SCTLR_EL2]

0:	msr	vbar_el2, x6
	cbz	x7, 3f
	msr_s	SYS_TCR2_EL2, xzr
3:	msr	mair_el2, x1
	msr	tcr_el2, x2
	msr	ttbr0_el2, x3
	isb
	tlbi	alle2
	dsb	nsh
	isb
	ic	iallu
	orr	x4, x4, x8
	msr	sctlr_el2, x4
	isb
	b	2f

1:	msr	vbar_el1, x6
	cbz	x7, 4f
	msr_s	SYS_TCR2_EL1, xzr
4:	msr	mair_el1, x1
	msr	tcr_el1, x2
	msr	ttbr0_el1, x3
	isb
	tlbi	vmalle1
	dsb	nsh
	isb
	ic	iallu
	orr	x4, x4, x8
	msr	sctlr_el1, x4
	isb

	/* Restore the image's state and return EFI_SUCCESS from ExitBootServices() */
2:	ldp	x19, x20, [x0, #EFI_KEXEC_RES_X19]
	ldp	x21, x22, [x0, #EFI_KEXEC_RES_X19 + 16]
	ldp	x23, x24, [x0, #EFI_KEXEC_RES_X19 + 32]
	ldp	x25, x26, [x0, #EFI_KEXEC_RES_X19 + 48]
	ldp	x27, x28, [x0, #EFI_KEXEC_RES_X19 + 64]
	ldp	d8, d9, [x0, #EFI_KEXEC_RES_D8]
	ldp	d10, d11, [x0, #EFI_KEXEC_RES_D8 + 16]
	ldp	d12, d13, [x0, #EFI_KEXEC_RES_D8 + 32]
	ldp	d14, d15, [x0, #EFI_KEXEC_RES_D8 + 48]
	ldr	x1, [x0, #EFI_KEXEC_RES_SP]
	mov	sp, x1
	ldp	x29, x30, [x0, #EFI_KEXEC_RES_FP]
	mov	x0, xzr
	ret
SYM_DATA_END_LABEL(efi_kexec_resume_start, SYM_L_GLOBAL, efi_kexec_resume_end)

/* Offset of the trampoline's entry point from efi_kexec_resume_start */
	.balign	8
SYM_DATA(efi_kexec_resume_entry_offset, .quad .Lresume_entry - efi_kexec_resume_start)
	.popsection
