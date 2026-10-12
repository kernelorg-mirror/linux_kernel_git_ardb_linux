/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Definitions shared between the C, Rust and assembler parts of the arm64
 * kexec loader for EFI images.
 */
#ifndef __ASM_KEXEC_EFI_H
#define __ASM_KEXEC_EFI_H

/* Returned by efi_kexec_call() when the image called ExitBootServices() */
#define EFI_KEXEC_SUSPENDED		1

/* EFI_INVALID_PARAMETER for 64-bit EFI */
#define EFI_KEXEC_EFI_INVALID_PARAMETER	0x8000000000000002

/* Layout of struct efi_kexec_jmpbuf */
#define EFI_KEXEC_JB_SP			0
#define EFI_KEXEC_JB_SCTLR		8

/* Layout of struct efi_kexec_resume */
#define EFI_KEXEC_RES_X19		0	/* x19 .. x28 */
#define EFI_KEXEC_RES_FP		80
#define EFI_KEXEC_RES_LR		88
#define EFI_KEXEC_RES_SP		96
#define EFI_KEXEC_RES_D8		104	/* d8 .. d15 */
#define EFI_KEXEC_RES_MAIR		168
#define EFI_KEXEC_RES_TTBR0		176
#define EFI_KEXEC_RES_TCR_EL1		184	/* EL1 format, also EL2 with E2H */
#define EFI_KEXEC_RES_SCTLR_EL1		192	/* EL1 format, also EL2 with E2H */
#define EFI_KEXEC_RES_TCR_EL2		200	/* EL2 format, E2H clear */
#define EFI_KEXEC_RES_SCTLR_EL2		208	/* EL2 format, E2H clear */
#define EFI_KEXEC_RES_ENIA		216	/* SCTLR_ELx_ENIA if PAC was on */
#define EFI_KEXEC_RES_APIA_LO		224	/* APIAKeyLo_EL1 */
#define EFI_KEXEC_RES_APIA_HI		232	/* APIAKeyHi_EL1 */
#define EFI_KEXEC_RES_SIZE		240

#ifndef __ASSEMBLER__

#include <linux/build_bug.h>
#include <linux/stddef.h>
#include <linux/types.h>

struct efi_kexec_jmpbuf {
	u64	sp;
	u64	sctlr;
};

static_assert(offsetof(struct efi_kexec_jmpbuf, sctlr) == EFI_KEXEC_JB_SCTLR);

/*
 * The register state of the EFI image at the time it called
 * ExitBootServices(), and the MMU configuration to install at resume time.
 */
struct efi_kexec_resume {
	u64	x19_x28[10];
	u64	fp;
	u64	lr;
	u64	sp;
	u64	d8_d15[8];
	u64	mair;
	u64	ttbr0;
	u64	tcr_el1;
	u64	sctlr_el1;
	u64	tcr_el2;
	u64	sctlr_el2;
	u64	enia;
	u64	apia_lo;
	u64	apia_hi;
};

static_assert(offsetof(struct efi_kexec_resume, fp) == EFI_KEXEC_RES_FP);
static_assert(offsetof(struct efi_kexec_resume, lr) == EFI_KEXEC_RES_LR);
static_assert(offsetof(struct efi_kexec_resume, sp) == EFI_KEXEC_RES_SP);
static_assert(offsetof(struct efi_kexec_resume, d8_d15) == EFI_KEXEC_RES_D8);
static_assert(offsetof(struct efi_kexec_resume, mair) == EFI_KEXEC_RES_MAIR);
static_assert(offsetof(struct efi_kexec_resume, ttbr0) == EFI_KEXEC_RES_TTBR0);
static_assert(offsetof(struct efi_kexec_resume, tcr_el1) == EFI_KEXEC_RES_TCR_EL1);
static_assert(offsetof(struct efi_kexec_resume, sctlr_el1) == EFI_KEXEC_RES_SCTLR_EL1);
static_assert(offsetof(struct efi_kexec_resume, tcr_el2) == EFI_KEXEC_RES_TCR_EL2);
static_assert(offsetof(struct efi_kexec_resume, sctlr_el2) == EFI_KEXEC_RES_SCTLR_EL2);
static_assert(offsetof(struct efi_kexec_resume, enia) == EFI_KEXEC_RES_ENIA);
static_assert(offsetof(struct efi_kexec_resume, apia_lo) == EFI_KEXEC_RES_APIA_LO);
static_assert(sizeof(struct efi_kexec_resume) == EFI_KEXEC_RES_SIZE);

long efi_kexec_call(long (*fn)(void *), void *arg, struct efi_kexec_jmpbuf *jb);
unsigned long efi_kexec_exit_boot_services(void *handle, unsigned long map_key);

/* Implemented in Rust */
long efi_kexec_run(void *params);
void efi_kexec_teardown(void);

/* Called from Rust */
void *efi_kexec_resume_block(void);
void *efiloader_alloc(size_t size, size_t align, bool zero);
void *efiloader_realloc(void *ptr, size_t new_size, size_t align);
void efiloader_free(void *ptr);

/* Position independent trampoline that is copied into the image's memory */
extern const char efi_kexec_resume_start[], efi_kexec_resume_end[];
extern const u64 efi_kexec_resume_entry_offset;

#endif /* __ASSEMBLER__ */
#endif /* __ASM_KEXEC_EFI_H */
