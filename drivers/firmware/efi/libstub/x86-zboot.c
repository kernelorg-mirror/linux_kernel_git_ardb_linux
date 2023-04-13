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
const bool efi_is64 = true;

u64 __efi64_thunk(u32 func, ...)
{
	return EFI_UNSUPPORTED;
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

void efi_cache_sync_image(unsigned long image_base, unsigned long alloc_size)
{
	const u32 payload_size = *(u32 *)(_gzdata_end - 4);
	const u32 image_size = *(u32 *)(image_base + 0x10);
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
