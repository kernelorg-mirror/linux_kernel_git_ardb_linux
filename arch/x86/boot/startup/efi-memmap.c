// SPDX-License-Identifier: GPL-2.0

#include <linux/efi.h>

#include <asm/efi.h>
#include <asm/pgtable_64_types.h>
#include <asm/setup.h>

/*
 * We allocate runtime services regions top-down, starting from -4G, i.e.
 * 0xffff_ffff_0000_0000 and limit EFI VA mapping space to 64G.
 */
static u64 efi_va __initdata = EFI_VA_START;

void __init efi_init_virtual_address_map(struct boot_params *bp)
{
	static const union { char c[4]; u32 v; } sig = { EFI64_LOADER_SIGNATURE };

	struct efi_info *info = &bp->efi_info;
	void *map = (void *)((u64)info->efi_memmap_hi << 32 | info->efi_memmap);
	int num_entries = info->efi_memmap_size / info->efi_memdesc_size;
	efi_system_table_t *systab;
	efi_memory_desc_t *desc;

	if (info->efi_loader_signature != sig.v)
		return;

	for (int i = num_entries - 1; i >= 0; i--) {
		desc = efi_memdesc_ptr(map, info->efi_memdesc_size, i);

		/* Bail if virtual addresses have already been assigned */
		if (desc->virt_addr)
			return;

		if (desc->attribute & EFI_MEMORY_RUNTIME ||
		    desc->type == EFI_BOOT_SERVICES_CODE ||
		    desc->type == EFI_BOOT_SERVICES_DATA) {
			unsigned long size = desc->num_pages << EFI_PAGE_SHIFT;
			u64 pa = desc->phys_addr;

			efi_va -= size;

			/* Is PA 2M-aligned? */
			if (!(pa & (PMD_SIZE - 1))) {
				efi_va &= PMD_MASK;
			} else {
				u64 pa_offset = pa & (PMD_SIZE - 1);
				u64 prev_va = efi_va;

				/* get us the same offset within this 2M page */
				efi_va = (efi_va & PMD_MASK) + pa_offset;

				if (efi_va > prev_va)
					efi_va -= PMD_SIZE;
			}

			if (efi_va < EFI_VA_END) {
				desc->virt_addr = U64_MAX;
				return;
			}

			desc->virt_addr = efi_va;
		}
	}

	systab = (void *)((u64)info->efi_systab_hi << 32 | info->efi_systab);
	if (systab->hdr.signature != EFI_SYSTEM_TABLE_SIGNATURE)
		return;

	efi_fw_vendor		= systab->fw_vendor;
	efi_config_table	= systab->tables;

	systab->runtime->set_virtual_address_map(info->efi_memmap_size,
						 info->efi_memdesc_size,
						 info->efi_memdesc_version,
						 map);
}
