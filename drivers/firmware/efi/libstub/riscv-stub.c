// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 Western Digital Corporation or its affiliates.
 */

#include <linux/efi.h>

#include <asm/efi.h>
#include <linux/unaligned.h>

#include "efistub.h"

unsigned long stext_offset(void)
{
	/*
	 * When built as part of the kernel, the EFI stub cannot branch to the
	 * kernel proper via the image header, as the PE/COFF header is
	 * strictly not part of the in-memory presentation of the image, only
	 * of the file representation. So instead, we need to jump to the
	 * actual entrypoint in the .text region of the image.
	 */
	return efistub_kernel_entry_offset(efistub_get_image_info());
}

efi_status_t handle_kernel_image(unsigned long *image_addr,
				 unsigned long *image_size,
				 unsigned long *reserve_addr,
				 unsigned long *reserve_size,
				 efi_loaded_image_t *image,
				 efi_handle_t image_handle)
{
	auto image_info			= efistub_get_image_info();
	unsigned long kernel_base	= efistub_kernel_base(image_info);
	unsigned long kernel_size	= efistub_kernel_size(image_info);
	unsigned long kernel_codesize	= efistub_kernel_codesize(image_info);
	unsigned long kernel_memsize	= efistub_kernel_memsize(image_info);
	efi_status_t status;

	*image_addr = kernel_base;
	*reserve_size = kernel_memsize;

	status = efi_kaslr_relocate_kernel(image_addr,
					   reserve_addr, reserve_size,
					   kernel_size, kernel_codesize, kernel_memsize,
					   efi_kaslr_get_phys_seed(image_handle));
	if (status != EFI_SUCCESS)
		efi_err("Failed to relocate kernel\n");

	return status;
}

void efi_icache_sync(unsigned long start, unsigned long end)
{
	asm volatile ("fence.i" ::: "memory");
}
