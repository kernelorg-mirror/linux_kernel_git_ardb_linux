// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Google LLC. <ardb@google.com>
 */

#include <linux/efi.h>
#include <linux/pci.h>
#include <linux/stddef.h>

#include <asm/efi.h>
#include <asm/e820/types.h>
#include <asm/setup.h>
#include <asm/desc.h>
#include <asm/boot.h>

#include "efistub.h"

extern char _gzdata_end[];
extern bool efi_no5lvl;

static const struct desc_struct gdt[] = {
	[GDT_ENTRY_KERNEL32_CS]	= GDT_ENTRY_INIT(0xc09b, 0, 0xfffff),
	[GDT_ENTRY_KERNEL_CS]	= GDT_ENTRY_INIT(0xa09b, 0, 0xfffff),
	[GDT_ENTRY_KERNEL_DS]	= GDT_ENTRY_INIT(0xc093, 0, 0xfffff),
};

static void (*la57_toggle)(void *cr3, void *gdt);

#ifdef CONFIG_EFI_MIXED
bool efi_is64 = true;

static struct desc_ptr __used efi32_boot_gdt, efi32_boot_idt;
static u16 __used efi32_boot_cs, efi32_boot_ds;

static u64 __used __page_aligned_bss pgd[512], pud[512];

asmlinkage u32 __naked efi_zboot_compat_entry(u32 handle32, u32 systab32)
{
	/*
	 * Check whether paging and PAE are enabled, and if so, preserve the
	 * firmware's GDT/IDT and segment selectors before replacing them with
	 * ones that can be used to switch into long mode and invoke the 64-bit
	 * EFI entrypoint.
	 */
	asm("	.code32							\n\t"
	    "	movl	%[unsupported], %%eax				\n\t"
	    "	movl	%%cr0, %%edx					\n\t"
	    "	btrl	%[pg], %%edx					\n\t"
	    "	jnc	0f						\n\t"
	    "	movl	%%cr4, %%ecx					\n\t"
	    "	btl	%[pae], %%ecx					\n\t"
	    "	jnc	0f						\n\t"

	    /* Disable interrupts and paging before proceeding */
	    "	cli							\n\t"
	    "	movl	%%edx, %%cr0					\n\t"
	    "	call	1f						\n\t"
	    "0:	ret							\n\t"
	    "1:	pop	%%ebx						\n\t"
	    "	movb	$0, (efi_is64 - 0b)(%%ebx)			\n\t"

	    /* Copy the 4 root PAE entries into a new level 3 table */
	    "	lea	(pud - 0b)(%%ebx), %%edi			\n\t"
	    "	lea	%c[pgtable](%%edi), %%edx			\n\t"
	    "	mov	%%cr3, %%esi					\n\t"
	    "	movw	$8, %%cx					\n\t"
	    "	cld							\n\t"
	    "	rep	movsl						\n\t"

	    /* Set the 'writable' bit, which doesn't exist on legacy PAE */
	    "	orl	%[pgtable], (pud - 0b)(%%ebx)			\n\t"
	    "	orl	%[pgtable], (pud - 0b + 8)(%%ebx)  		\n\t"
	    "	orl	%[pgtable], (pud - 0b + 16)(%%ebx)		\n\t"
	    "	orl	%[pgtable], (pud - 0b + 24)(%%ebx)		\n\t"

	    /* Create a root table and insert an entry for the level 3 table */
	    "	lea	(pgd - 0b)(%%ebx), %%ecx			\n\t"
	    "	mov	%%edx, (%%ecx)					\n\t"
	    "	mov	%%ecx, %%cr3					\n\t"

	    /* Save firmware's GDT/IDT and selector values */
	    "	sgdtl	(efi32_boot_gdt - 0b)(%%ebx)			\n\t"
	    "	sidtl	(efi32_boot_idt - 0b)(%%ebx)			\n\t"
	    "	movw	%%cs, (efi32_boot_cs - 0b)(%%ebx)		\n\t"
	    "	movw	%%ds, (efi32_boot_ds - 0b)(%%ebx)		\n\t"

	    /* Install our own GDT and select __KERNEL_DS */
	    "	leal	(gdt - 0b)(%%ebx), %%eax			\n\t"
	    "	movl	%%eax, (%%esp)					\n\t"
	    "	subl	$4, %%esp					\n\t"
	    "	movw	%[gdtlimit], 2(%%esp)				\n\t"
	    "	lgdtl	2(%%esp)					\n\t"
	    "	movw	%[ds], %%ax					\n\t"
	    "	movw	%%ax, %%ds					\n\t"
	    "	movw	%%ax, %%es					\n\t"
	    "	movw	%%ax, %%fs					\n\t"
	    "	movw	%%ax, %%gs					\n\t"
	    "	movw	%%ax, %%ss					\n\t"

	    /* Prepare for the jump to long mode */
	    "	movl	%[msr_efer], %%ecx				\n\t"
	    "	rdmsr							\n\t"
	    "	btsl	%[efer_lme], %%eax				\n\t"
	    "	wrmsr							\n\t"

	    /* Use MS calling convention for params and align the stack */
	    "	lea	(__efistub_efi_zboot_entry - 0b)(%%ebx), %%ebx	\n\t"
	    "	movl	8(%%esp), %%ecx					\n\t"
	    "	movl	12(%%esp), %%edx				\n\t"
	    "	andl	$~0xf, %%esp					\n\t"
	    "	movl	%[cs], 4(%%esp)					\n\t"
	    "	movl	%%ebx, (%%esp)					\n\t"
	    "	movl	%[cr0_state], %%eax				\n\t"
	    "	movl	%%eax, %%cr0					\n\t"
	    "	lret							\n\t"
	    "	.code64							\n\t"
	    :
	    : [unsupported]	"i"(0x80000003),
	      [pg]		"i"(X86_CR0_PG_BIT),
	      [pae]		"i"(X86_CR4_PAE_BIT),
	      [gdtlimit]	"i"(sizeof(gdt) - 1),
	      [cs]		"i"(__KERNEL_CS),
	      [ds]		"i"(__KERNEL_DS),
	      [pgtable]		"i"(_KERNPG_TABLE_NOENC),
	      [msr_efer]	"i"(MSR_EFER),
	      [efer_lme]	"i"(_EFER_LME),
	      [cr0_state]	"i"(CR0_STATE));
}

u64 __naked __efi64_thunk(u32 func, ...)
{
	asm("	push	%%rbp						\n\t"
	    "	push	%%rbx						\n\t"

	    /* Load up to three arguments passed via the stack */
	    "	movq	0x18(%%rsp), %%rbp				\n\t"
	    "	movq	0x20(%%rsp), %%rbx				\n\t"
	    "	movq	0x28(%%rsp), %%rax				\n\t"

	    /* Create an outgoing stack frame and push 8 arguments */
	    "	subq	$64, %%rsp					\n\t"
	    "	movl	%%esi, 0x0(%%rsp)				\n\t"
	    "	movl	%%edx, 0x4(%%rsp)				\n\t"
	    "	movl	%%ecx, 0x8(%%rsp)				\n\t"
	    "	movl	%%r8d, 0xc(%%rsp)				\n\t"
	    "	movl	%%r9d, 0x10(%%rsp)				\n\t"
	    "	movl	%%ebp, 0x14(%%rsp)				\n\t"
	    "	movl	%%ebx, 0x18(%%rsp)				\n\t"
	    "	movl	%%eax, 0x1c(%%rsp)				\n\t"

	    /* Preserve the active GDT and IDT pointers on the stack */
	    "	leaq	0x20(%%rsp), %%rbx				\n\t"
	    "	sgdt	(%%rbx)						\n\t"
	    "	sidt	16(%%rbx)					\n\t"

	    /* Switch to the firmware's GDT/IDT */
	    "	lidt	efi32_boot_idt(%%rip)				\n\t"
	    "	lgdt	efi32_boot_gdt(%%rip)				\n\t"
	    "	movzwl	efi32_boot_ds(%%rip), %%edx			\n\t"
	    "	movzwq	efi32_boot_cs(%%rip), %%rax			\n\t"

	    /* Long return to 32-bit mode with return address in RBP */
	    "	pushq	%%rax						\n\t"
	    "	leaq	1f(%%rip), %%rax				\n\t"
	    "	leaq	2f(%%rip), %%rbp				\n\t"
	    "	pushq	%%rax						\n\t"
	    "	lretq							\n\t"

	    /* Switch to the firmware's data segment */
	    "	.code32							\n\t"
	    "1:	movw	%%dx, %%ds					\n\t"
	    "	movw	%%dx, %%es					\n\t"
	    "	movw	%%dx, %%ss					\n\t"
	    "	movw	%%dx, %%fs					\n\t"
	    "	movw	%%dx, %%gs					\n\t"

	    /* Disable paging and [implicitly] long mode */
	    "	movl	%%cr0, %%eax					\n\t"
	    "	btrl	%[pg], %%eax					\n\t"
	    "	movl	%%eax, %%cr0					\n\t"

	    /* Call the firmware routine */
	    "	call	*%%edi						\n\t"

	    /* Restore our IDT and GDT from the stack */
	    "	cli							\n\t"
	    "	lidtl	16(%%ebx)					\n\t"
	    "	lgdtl	(%%ebx)						\n\t"
	    "	xorl	%%ebx, %%ebx					\n\t"
	    "	lldt	%%bx						\n\t"

	    /* Re-enable paging and switch back to 64-bit long mode */
	    "	pushl	%[cs]						\n\t"
	    "	pushl	%%ebp						\n\t"
	    "	movl	%%cr0, %%ebx					\n\t"
	    "	btsl	%[pg], %%ebx					\n\t"
	    "	movl	%%ebx, %%cr0					\n\t"
	    "	lret							\n\t"

	    /* Reload our segment selectors and return */
	    "	.code64							\n\t"
	    "2:	movw	%[ds], %%bx					\n\t"
	    "	movw	%%bx, %%ds					\n\t"
	    "	movw	%%bx, %%es					\n\t"
	    "	movw	%%bx, %%ss					\n\t"
	    "	xorw	%%bx, %%bx					\n\t"
	    "	movw	%%bx, %%fs					\n\t"
	    "	movw	%%bx, %%gs					\n\t"
	    "	addq	$64, %%rsp					\n\t"
	    "	pop	%%rbx						\n\t"
	    "	pop	%%rbp						\n\t"
	    "	ret							\n\t"
	    :
	    : [pg]		"i"(X86_CR0_PG_BIT),
	      [cs]		"i"(__KERNEL_CS),
	      [ds]		"i"(__KERNEL_DS));
}
#endif

efi_status_t efi_handle_cmdline(efi_loaded_image_t *image, char **cmdline_ptr)
{
	int options_size = 0;
	efi_status_t status;

	/* Convert unicode cmdline to ascii */
	*cmdline_ptr = efi_convert_cmdline(image, &options_size);
	if (!*cmdline_ptr)
		return EFI_OUT_OF_RESOURCES;

#ifdef CONFIG_CMDLINE_BOOL
	status = efi_parse_options(CONFIG_CMDLINE);
	if (status != EFI_SUCCESS) {
		efi_err("Failed to parse options\n");
		return status;
	}
#endif
	if (!IS_ENABLED(CONFIG_CMDLINE_OVERRIDE)) {
		status = efi_parse_options(*cmdline_ptr);
		if (status != EFI_SUCCESS)
			efi_err("Failed to parse options\n");
	}
	return status;
}

static void efi_remap_exec(unsigned long base, unsigned long size)
{
	static efi_memory_attribute_protocol_t *memattr = (void *)ULONG_MAX;
	efi_guid_t guid = EFI_MEMORY_ATTRIBUTE_PROTOCOL_GUID;
	efi_status_t status;

	if (memattr == (void *)ULONG_MAX) {
		memattr = NULL;
		status = efi_bs_call(locate_protocol, &guid, NULL,
				     (void **)&memattr);
		if (status != EFI_SUCCESS)
			return;
	} else if (!memattr) {
		return;
	}

	status = memattr->clear_memory_attributes(memattr, base, size,
						  EFI_MEMORY_XP);
	if (status != EFI_SUCCESS)
		efi_warn("Failed to clear NX attribute on code region\n");
}

void efi_cache_sync_image(unsigned long image_base, unsigned long alloc_size)
{
	const u32 payload_size = *(u32 *)(_gzdata_end - 4);
	const u32 image_size = *(u32 *)(image_base + 0x10);
	const u32 code_size = *(u32 *)(image_base + 0x20);
	const s32 *reloc = (s32 *)(image_base + payload_size);
	u64 va_offset = __START_KERNEL - image_base;
	u64 range, delta;
	u32 seed;

	if (!IS_ENABLED(CONFIG_RANDOMIZE_BASE) ||
	    image_size == payload_size ||
	    efi_get_random_bytes(sizeof(seed), (u8 *)&seed) != EFI_SUCCESS)
		return;

	range = KERNEL_IMAGE_SIZE - image_size;
	delta = ((seed * range) >> 32UL) & ~(CONFIG_PHYSICAL_ALIGN - 1);

	/*
	 * Process relocations: 32 bit relocations first then 64 bit after.
	 * Three sets of binary relocations are added to the end of the kernel
	 * before compression. Each relocation table entry is the kernel
	 * address of the location which needs to be updated stored as a
	 * 32-bit value which is sign extended to 64 bits.
	 *
	 * Format is:
	 *
	 * kernel bits...
	 * 0 - zero terminator for 64 bit relocations
	 * 64 bit relocation repeated
	 * 0 - zero terminator for inverse 32 bit relocations
	 * 32 bit inverse relocation repeated
	 * 0 - zero terminator for 32 bit relocations
	 * 32 bit relocation repeated
	 *
	 * So we work backwards from the end of the decompressed image.
	 */
	while (*--reloc)
		*(u32 *)((s64)*reloc - va_offset) += delta;

	while (*--reloc)
		*(u32 *)((s64)*reloc - va_offset) -= delta;

	while (*--reloc)
		*(u64 *)((s64)*reloc - va_offset) += delta;

	efi_free(alloc_size - image_size, image_base + image_size);

	efi_remap_exec(image_base, PAGE_ALIGN(code_size));
}

static void __naked tmpl_toggle(void *cr3, void *gdt)
{
	/*
	 * This is template code that will be copied into a 32-bit addressable
	 * buffer, allowing us to drop to 32-bit mode with paging disabled,
	 * which is required to be able to toggle the CR4.LA57 bit.
	 *
	 * The first MOVB instruction is only there to capture the size of the
	 * sequence, and implicitly, the offset to the LJMP's immediate, which
	 * will be populated with the correct absolute address after copying.
	 */
	asm("0:	movb	$(4f - .), %%al		\n\t"
	    "	lgdt	(%%rsi)			\n\t"
	    "	movw	%[ds], %%ax		\n\t"
	    "	movw	%%ax, %%ds		\n\t"
	    "	movw	%%ax, %%ss		\n\t"
	    "	leaq	2f(%%rip), %%rax	\n\t"
	    "	pushq	%[cs32]			\n\t"
	    "	pushq	%%rax			\n\t"
	    "	lretq				\n\t"
	    "1:	retq				\n\t"
	    "	.code32				\n\t"
	    "2:	movl	%%cr0, %%eax		\n\t"
	    "	btrl	%[pg], %%eax		\n\t"
	    "	movl	%%eax, %%cr0		\n\t"
	    "	jmp	3f			\n\t"
	    "3:	movl	%%cr4, %%ecx		\n\t"
	    "	btcl	%[la57], %%ecx		\n\t"
	    "	movl	%%ecx, %%cr4		\n\t"
	    "	movl	%%edi, %%cr3		\n\t"
	    "	btsl	%[pg], %%eax		\n\t"
	    "	movl	%%eax, %%cr0		\n\t"
	    "	ljmpl	%[cs], $(1b - 0b) 	\n\t"
	    "4:	.code64"
	    :
	    : [cs32]	"i"(__KERNEL32_CS),
	      [cs]	"i"(__KERNEL_CS),
	      [ds]	"i"(__KERNEL_DS),
	      [pg]	"i"(X86_CR0_PG_BIT),
	      [la57]	"i"(X86_CR4_LA57_BIT));
}

/*
 * Enabling (or disabling) 5 level paging is tricky, because it can only be
 * done from 32-bit mode with paging disabled. This means not only that the
 * code itself must be running from 32-bit addressable physical memory, but
 * also that the root page table must be 32-bit addressable, as we cannot
 * program a 64-bit value into CR3 when running in 32-bit mode.
 */
static efi_status_t efi_setup_5level_paging(void)
{
	bool want_la57 = IS_ENABLED(CONFIG_X86_5LEVEL) && !efi_no5lvl;
	bool have_la57 = native_read_cr4() & X86_CR4_LA57;
	const u8 tmpl_size = ((u8 *)tmpl_toggle)[1];
	efi_status_t status;
	u8 *la57_code;

	if (!efi_is_64bit())
		return EFI_SUCCESS;

	/* check for 5 level paging support */
	if (native_cpuid_eax(0) < 7 ||
	    !(native_cpuid_ecx(7) & (1 << (X86_FEATURE_LA57 & 31))))
		return EFI_SUCCESS;

	/*
	 * If LA57 is supported but disabled, and we have no interest in
	 * enabling it, we can bail here. In all other cases, we need to
	 * prepare the toggle support routine, even for the case where LA57 is
	 * currently on and we want to keep it on, as the firmware might return
	 * from ExitBootServices() with LA57 disabled.
	 */
	if (!want_la57 && !have_la57)
		return EFI_SUCCESS;

	/* allocate some 32-bit addressable memory for code and a page table */
	status = efi_allocate_pages(2 * PAGE_SIZE, (unsigned long *)&la57_code,
				    U32_MAX);
	if (status != EFI_SUCCESS)
		return status;

	la57_toggle = memcpy(la57_code, tmpl_toggle, tmpl_size);
	memset(la57_code + tmpl_size, 0x0, 2 * PAGE_SIZE - tmpl_size);

	/*
	 * To avoid having to allocate a 32-bit addressable stack, we use a
	 * ljmp to switch back to long mode. However, this takes an absolute
	 * address, so we have to poke it in at runtime. The dummy MOVB
	 * instruction at the beginning can be used to locate the immediate.
	 */
	*(u32 *)&la57_code[tmpl_size - 6] += (u64)la57_code;

	efi_remap_exec((unsigned long)la57_code, PAGE_SIZE);

	return EFI_SUCCESS;
}

static void efi_5level_switch(void)
{
	bool want_la57 = IS_ENABLED(CONFIG_X86_5LEVEL) && !efi_no5lvl;
	bool have_la57 = native_read_cr4() & X86_CR4_LA57;
	u64 *pgt = (void *)la57_toggle + PAGE_SIZE;
	u64 *cr3 = (u64 *)__native_read_cr3();
	struct desc_ptr desc;
	u64 *new_cr3;

	if (!la57_toggle || (want_la57 && have_la57))
		return;

	if (!have_la57) {
		/*
		 * We are going to enable 5 level paging, so we need to
		 * allocate a root level page from the 32-bit addressable
		 * physical region, and plug the existing hierarchy into it.
		 */
		new_cr3 = pgt;
		new_cr3[0] = (u64)cr3 | _PAGE_TABLE_NOENC;
	} else {
		// take the new root table pointer from the current entry #0
		new_cr3 = (u64 *)(cr3[0] & PAGE_MASK);

		// copy the new root level table if it is not 32-bit addressable
		if ((u64)new_cr3 > U32_MAX) {
			for (int i = 0; i < PTRS_PER_PGD; i++)
				pgt[i] = new_cr3[i];
			new_cr3 = pgt;
		}
	}

	desc.size	= sizeof(gdt) - 1;
	desc.address 	= (u64)gdt;

	la57_toggle(new_cr3, &desc);
}

efi_status_t efi_stub_common(efi_handle_t handle,
			     efi_loaded_image_t *image,
			     unsigned long image_addr,
			     char *cmdline_ptr)
{
	void __noreturn (*startup_64)(void *, struct boot_params *);
	const struct linux_efi_initrd *initrd = NULL;
	struct boot_params *boot_params;
	struct setup_header *hdr;
	efi_status_t status;

	if (!efi_is_64bit())
		efi_info("Using EFI mixed mode on 32-bit firmware\n");

	status = efi_setup_5level_paging();
	if (status != EFI_SUCCESS) {
		efi_err("efi_setup_5level_paging() failed!\n");
		return status;
	}

	boot_params = efi_alloc_boot_params();
	if (!boot_params)
		return EFI_OUT_OF_RESOURCES;

	hdr = &boot_params->hdr;
	hdr->type_of_loader = 0x21;

	efi_set_u64_split((unsigned long)cmdline_ptr,
			  &hdr->cmd_line_ptr, &boot_params->ext_cmd_line_ptr);

	status = efi_load_initrd(image, hdr->initrd_addr_max, ULONG_MAX,
				 &initrd);
	if (status != EFI_SUCCESS)
		goto fail;
	if (initrd && initrd->size > 0) {
		efi_set_u64_split(initrd->base, &hdr->ramdisk_image,
				  &boot_params->ext_ramdisk_image);
		efi_set_u64_split(initrd->size, &hdr->ramdisk_size,
				  &boot_params->ext_ramdisk_size);
	}

	status = efi_x86_stub_common(boot_params, handle);
	if (status != EFI_SUCCESS)
		goto fail;

	efi_5level_switch();

	startup_64 = (void *)image_addr;
	startup_64(NULL, boot_params);
fail:
	efi_free(sizeof(struct boot_params), (unsigned long)boot_params);
	return status;
}

struct screen_info *__alloc_screen_info(void)
{
	return NULL;
}
