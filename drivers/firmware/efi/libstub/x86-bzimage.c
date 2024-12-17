// SPDX-License-Identifier: GPL-2.0-only

#include <linux/efi.h>

#include <asm/efi.h>
#include <asm/setup.h>
#include <asm/boot.h>
#include <asm/kaslr.h>

#include "efistub.h"
#include "x86-stub.h"

extern char _bss[], _ebss[];

efi_status_t __efiapi efi_pe_entry(efi_handle_t handle,
				   efi_system_table_t *sys_table_arg)
{
	efi_stub_entry(handle, sys_table_arg, NULL);
}

#ifdef CONFIG_EFI_HANDOVER_PROTOCOL
void efi_handover_entry(efi_handle_t handle, efi_system_table_t *sys_table_arg,
			struct boot_params *boot_params)
{
	memset(_bss, 0, _ebss - _bss);
	efi_stub_entry(handle, sys_table_arg, boot_params);
}

#ifndef CONFIG_EFI_MIXED
extern __alias(efi_handover_entry)
void efi32_stub_entry(efi_handle_t handle, efi_system_table_t *sys_table_arg,
		      struct boot_params *boot_params);

extern __alias(efi_handover_entry)
void efi64_stub_entry(efi_handle_t handle, efi_system_table_t *sys_table_arg,
		      struct boot_params *boot_params);
#endif
#endif

#ifdef CONFIG_RANDOMIZE_BASE
void efi_get_seed(void *seed, size_t size)
{
	efi_get_random_bytes(size, seed);

	/*
	 * This only updates seed[0] when running on 32-bit, but in that case,
	 * seed[1] is not used anyway, as there is no virtual KASLR on 32-bit.
	 */
	*(unsigned long *)seed ^= kaslr_get_random_long("EFI");
}
#endif

static void error(char *str)
{
	efi_warn("Decompression failed: %s\n", str);
}

efi_status_t efi_decompress_kernel(unsigned long *kernel_entry,
				   struct boot_params *boot_params)
{
	unsigned long virt_addr, addr, alloc_size, entry;
	efi_status_t status;

	boot_params_ptr	= boot_params;

	/* determine the required size of the allocation */
	alloc_size = ALIGN(max_t(unsigned long, output_len, kernel_total_size),
			   MIN_KERNEL_ALIGN);

	status = efi_allocate_kernel(alloc_size, &virt_addr, &addr, boot_params);
	if (status != EFI_SUCCESS)
		return status;

	entry = decompress_kernel((void *)addr, virt_addr, error);
	if (entry == ULONG_MAX) {
		efi_free(alloc_size, addr);
		return EFI_LOAD_ERROR;
	}

	*kernel_entry = addr + entry;

	return efi_adjust_memory_range_protection(addr, kernel_text_size);
}
