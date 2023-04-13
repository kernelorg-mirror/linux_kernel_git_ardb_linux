// SPDX-License-Identifier: GPL-2.0-only

/* -----------------------------------------------------------------------
 *
 *   Copyright 2011 Intel Corporation; author Matt Fleming
 *
 * ----------------------------------------------------------------------- */

#include <linux/efi.h>
#include <linux/stddef.h>

#include <asm/efi.h>
#include <asm/setup.h>
#include <asm/desc.h>
#include <asm/boot.h>

#include "efistub.h"

/* Maximum physical address for 64-bit kernel with 4-level paging */
#define MAXMEM_X86_64_4LEVEL (1ull << 46)

const efi_dxe_services_table_t *efi_dxe_table;
u32 image_offset __section(".data");
static efi_loaded_image_t *image = NULL;

static void
adjust_memory_range_protection(unsigned long start, unsigned long size)
{
	efi_status_t status;
	efi_gcd_memory_space_desc_t desc;
	unsigned long end, next;
	unsigned long rounded_start, rounded_end;
	unsigned long unprotect_start, unprotect_size;

	if (efi_dxe_table == NULL)
		return;

	rounded_start = rounddown(start, EFI_PAGE_SIZE);
	rounded_end = roundup(start + size, EFI_PAGE_SIZE);

	/*
	 * Don't modify memory region attributes, they are
	 * already suitable, to lower the possibility to
	 * encounter firmware bugs.
	 */

	for (end = start + size; start < end; start = next) {

		status = efi_dxe_call(get_memory_space_descriptor, start, &desc);

		if (status != EFI_SUCCESS)
			return;

		next = desc.base_address + desc.length;

		/*
		 * Only system memory is suitable for trampoline/kernel image placement,
		 * so only this type of memory needs its attributes to be modified.
		 */

		if (desc.gcd_memory_type != EfiGcdMemoryTypeSystemMemory ||
		    (desc.attributes & (EFI_MEMORY_RO | EFI_MEMORY_XP)) == 0)
			continue;

		unprotect_start = max(rounded_start, (unsigned long)desc.base_address);
		unprotect_size = min(rounded_end, next) - unprotect_start;

		status = efi_dxe_call(set_memory_space_attributes,
				      unprotect_start, unprotect_size,
				      EFI_MEMORY_WB);

		if (status != EFI_SUCCESS) {
			efi_warn("Unable to unprotect memory range [%08lx,%08lx]: %lx\n",
				 unprotect_start,
				 unprotect_start + unprotect_size,
				 status);
		}
	}
}

/*
 * Trampoline takes 2 pages and can be loaded in first megabyte of memory
 * with its end placed between 128k and 640k where BIOS might start.
 * (see arch/x86/boot/compressed/pgtable_64.c)
 *
 * We cannot find exact trampoline placement since memory map
 * can be modified by UEFI, and it can alter the computed address.
 */

#define TRAMPOLINE_PLACEMENT_BASE ((128 - 8)*1024)
#define TRAMPOLINE_PLACEMENT_SIZE (640*1024 - (128 - 8)*1024)

void startup_32(struct boot_params *boot_params);

static void
setup_memory_protection(unsigned long image_base, unsigned long image_size)
{
	/*
	 * Allow execution of possible trampoline used
	 * for switching between 4- and 5-level page tables
	 * and relocated kernel image.
	 */

	adjust_memory_range_protection(TRAMPOLINE_PLACEMENT_BASE,
				       TRAMPOLINE_PLACEMENT_SIZE);

#ifdef CONFIG_64BIT
	if (image_base != (unsigned long)startup_32)
		adjust_memory_range_protection(image_base, image_size);
#else
	/*
	 * Clear protection flags on a whole range of possible
	 * addresses used for KASLR. We don't need to do that
	 * on x86_64, since KASLR/extraction is performed after
	 * dedicated identity page tables are built and we only
	 * need to remove possible protection on relocated image
	 * itself disregarding further relocations.
	 */
	adjust_memory_range_protection(LOAD_PHYSICAL_ADDR,
				       KERNEL_IMAGE_SIZE - LOAD_PHYSICAL_ADDR);
#endif
}

void __noreturn efi_stub_entry(efi_handle_t handle,
			       efi_system_table_t *sys_table_arg,
			       struct boot_params *boot_params);

/*
 * Because the x86 boot code expects to be passed a boot_params we
 * need to create one ourselves (usually the bootloader would create
 * one for us).
 */
efi_status_t __efiapi efi_pe_entry(efi_handle_t handle,
				   efi_system_table_t *sys_table_arg)
{
	struct boot_params *boot_params;
	struct setup_header *hdr;
	void *image_base;
	efi_guid_t proto = LOADED_IMAGE_PROTOCOL_GUID;
	int options_size = 0;
	efi_status_t status;
	char *cmdline_ptr;

	efi_system_table = sys_table_arg;

	/* Check if we were booted by the EFI firmware */
	if (efi_system_table->hdr.signature != EFI_SYSTEM_TABLE_SIGNATURE)
		efi_exit(handle, EFI_INVALID_PARAMETER);

	status = efi_bs_call(handle_protocol, handle, &proto, (void **)&image);
	if (status != EFI_SUCCESS) {
		efi_err("Failed to get handle for LOADED_IMAGE_PROTOCOL\n");
		efi_exit(handle, status);
	}

	image_base = efi_table_attr(image, image_base);
	image_offset = (void *)startup_32 - image_base;

	boot_params = efi_alloc_boot_params();
	if (!boot_params)
		efi_exit(handle, EFI_OUT_OF_RESOURCES);

	hdr = &boot_params->hdr;

	/* Copy the setup header from the second sector to boot_params */
	memcpy(&hdr->jump, image_base + 512,
	       sizeof(struct setup_header) - offsetof(struct setup_header, jump));

	hdr->type_of_loader = 0x21;

	/* Convert unicode cmdline to ascii */
	cmdline_ptr = efi_convert_cmdline(image, &options_size);
	if (!cmdline_ptr)
		goto fail;

	efi_set_u64_split((unsigned long)cmdline_ptr,
			  &hdr->cmd_line_ptr, &boot_params->ext_cmd_line_ptr);

	hdr->ramdisk_image = 0;
	hdr->ramdisk_size = 0;

	/*
	 * Disregard any setup data that was provided by the bootloader:
	 * setup_data could be pointing anywhere, and we have no way of
	 * authenticating or validating the payload.
	 */
	hdr->setup_data = 0;

	efi_stub_entry(handle, sys_table_arg, boot_params);
	/* not reached */

fail:
	efi_free(sizeof(struct boot_params), (unsigned long)boot_params);

	return efi_exit(handle, status);
}

/*
 * On success, we return the address of startup_32, which has potentially been
 * relocated by efi_relocate_kernel.
 * On failure, we exit to the firmware via efi_exit instead of returning.
 */
asmlinkage unsigned long efi_main(efi_handle_t handle,
				  efi_system_table_t *sys_table_arg,
				  struct boot_params *boot_params)
{
	unsigned long bzimage_addr = (unsigned long)startup_32;
	unsigned long buffer_start, buffer_end;
	struct setup_header *hdr = &boot_params->hdr;
	const struct linux_efi_initrd *initrd = NULL;
	efi_status_t status;

	efi_system_table = sys_table_arg;
	/* Check if we were booted by the EFI firmware */
	if (efi_system_table->hdr.signature != EFI_SYSTEM_TABLE_SIGNATURE)
		efi_exit(handle, EFI_INVALID_PARAMETER);

	efi_dxe_table = get_efi_config_table(EFI_DXE_SERVICES_TABLE_GUID);
	if (efi_dxe_table &&
	    efi_dxe_table->hdr.signature != EFI_DXE_SERVICES_TABLE_SIGNATURE) {
		efi_warn("Ignoring DXE services table: invalid signature\n");
		efi_dxe_table = NULL;
	}

	/*
	 * If the kernel isn't already loaded at a suitable address,
	 * relocate it.
	 *
	 * It must be loaded above LOAD_PHYSICAL_ADDR.
	 *
	 * The maximum address for 64-bit is 1 << 46 for 4-level paging. This
	 * is defined as the macro MAXMEM, but unfortunately that is not a
	 * compile-time constant if 5-level paging is configured, so we instead
	 * define our own macro for use here.
	 *
	 * For 32-bit, the maximum address is complicated to figure out, for
	 * now use KERNEL_IMAGE_SIZE, which will be 512MiB, the same as what
	 * KASLR uses.
	 *
	 * Also relocate it if image_offset is zero, i.e. the kernel wasn't
	 * loaded by LoadImage, but rather by a bootloader that called the
	 * handover entry. The reason we must always relocate in this case is
	 * to handle the case of systemd-boot booting a unified kernel image,
	 * which is a PE executable that contains the bzImage and an initrd as
	 * COFF sections. The initrd section is placed after the bzImage
	 * without ensuring that there are at least init_size bytes available
	 * for the bzImage, and thus the compressed kernel's startup code may
	 * overwrite the initrd unless it is moved out of the way.
	 */

	buffer_start = ALIGN(bzimage_addr - image_offset,
			     hdr->kernel_alignment);
	buffer_end = buffer_start + hdr->init_size;

	if ((buffer_start < LOAD_PHYSICAL_ADDR)				     ||
	    (IS_ENABLED(CONFIG_X86_32) && buffer_end > KERNEL_IMAGE_SIZE)    ||
	    (IS_ENABLED(CONFIG_X86_64) && buffer_end > MAXMEM_X86_64_4LEVEL) ||
	    (image_offset == 0)) {
		extern char _bss[];

		status = efi_relocate_kernel(&bzimage_addr,
					     (unsigned long)_bss - bzimage_addr,
					     hdr->init_size,
					     hdr->pref_address,
					     hdr->kernel_alignment,
					     LOAD_PHYSICAL_ADDR);
		if (status != EFI_SUCCESS) {
			efi_err("efi_relocate_kernel() failed!\n");
			goto fail;
		}
		/*
		 * Now that we've copied the kernel elsewhere, we no longer
		 * have a set up block before startup_32(), so reset image_offset
		 * to zero in case it was set earlier.
		 */
		image_offset = 0;
	}

#ifdef CONFIG_CMDLINE_BOOL
	status = efi_parse_options(CONFIG_CMDLINE);
	if (status != EFI_SUCCESS) {
		efi_err("Failed to parse options\n");
		goto fail;
	}
#endif
	if (!IS_ENABLED(CONFIG_CMDLINE_OVERRIDE)) {
		unsigned long cmdline_paddr = ((u64)hdr->cmd_line_ptr |
					       ((u64)boot_params->ext_cmd_line_ptr << 32));
		status = efi_parse_options((char *)cmdline_paddr);
		if (status != EFI_SUCCESS) {
			efi_err("Failed to parse options\n");
			goto fail;
		}
	}

	/*
	 * At this point, an initrd may already have been loaded by the
	 * bootloader and passed via bootparams. We permit an initrd loaded
	 * from the LINUX_EFI_INITRD_MEDIA_GUID device path to supersede it.
	 *
	 * If the device path is not present, any command-line initrd=
	 * arguments will be processed only if image is not NULL, which will be
	 * the case only if we were loaded via the PE entry point.
	 */
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

	if (IS_ENABLED(CONFIG_EFI_DXE_MEM_ATTRIBUTES))
		setup_memory_protection(bzimage_addr, buffer_end - buffer_start);

	status = efi_x86_stub_common(boot_params, handle);
	if (status != EFI_SUCCESS)
		goto fail;

	return bzimage_addr;
fail:
	efi_err("efi_main() failed!\n");

	efi_exit(handle, status);
	for (;;)
		asm("hlt");
}
