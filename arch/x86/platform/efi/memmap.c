// SPDX-License-Identifier: GPL-2.0
/*
 * Common EFI memory map functions.
 */

#define pr_fmt(fmt) "efi: " fmt

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/efi.h>
#include <asm/efi.h>

/**
 * efi_memmap_install - Install a new EFI memory map in efi.memmap
 * @data: efi memmap installation parameters
 *
 * Unlike efi_memmap_init_*(), this function does not allow the caller
 * to switch from early to late mappings. It simply uses the existing
 * mapping function and installs the new memmap.
 *
 * Returns zero on success, a negative error code on failure.
 */
int __init efi_memmap_install(struct efi_memory_map_data *data)
{
	efi_memmap_unmap();

	if (efi_enabled(EFI_PARAVIRT))
		return 0;

	return __efi_memmap_init(data);
}
