// SPDX-License-Identifier: GPL-2.0-only

#include <linux/efi.h>
#include <asm/efi.h>

#include "efistub.h"
#include "x86-stub.h"

efi_status_t __efiapi
__efistub_efi_zboot_entry(efi_handle_t handle, efi_system_table_t *systab)
{
	efi_stub_entry(handle, systab, NULL);
}

void efi_cache_sync_image(unsigned long base, unsigned long size)
{
}

void efi_get_seed(void *seed, size_t size)
{
	efi_get_random_bytes(size, seed);
}

efi_status_t efi_decompress_kernel(unsigned long *kernel_entry,
				   struct boot_params *bp)
{
	unsigned long va_shift, addr, alloc_size, entry;
	efi_status_t status;

	status = efi_zboot_decompress_init(&alloc_size, &entry) ?:
		 efi_allocate_kernel(alloc_size, &va_shift, &addr, bp) ?:
		 efi_zboot_decompress((void *)addr, alloc_size,
				      va_shift - LOAD_PHYSICAL_ADDR);
	if (status != EFI_SUCCESS)
		return status;


	*kernel_entry = addr + entry;
	return EFI_SUCCESS;
}

#if defined(CONFIG_EFI_HANDOVER_PROTOCOL) && defined(CONFIG_EFI_MIXED)
void efi_handover_entry(efi_handle_t handle, efi_system_table_t *systab,
			struct boot_params *bp)
{
	unreachable(); /* entrypoint not exposed by EFI zboot image */
}
#endif
