/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/efi.h>
#include <linux/elf.h>

#include <asm/efi.h>

#include "efistub.h"

static struct {
	Elf64_Ehdr	ehdr;
	Elf64_Phdr	phdr[4];
} elf_header;

bool efi_zboot_check_elf(unsigned long *alloc_size,
			 unsigned long *entry,
			 bool (*decompress_slice)(u8 *, unsigned long))
{
	unsigned long min = ULONG_MAX, max = 0;
	bool ret;

	ret = decompress_slice((u8 *)&elf_header, sizeof(elf_header));
	if (!ret) {
		efi_err("failed to extract header\n");
		return false;
	}

	/* Check the ELF magic */
	if (elf_header.ehdr.e_ident[EI_MAG0] != ELFMAG0 ||
	    elf_header.ehdr.e_ident[EI_MAG1] != ELFMAG1 ||
	    elf_header.ehdr.e_ident[EI_MAG2] != ELFMAG2 ||
	    elf_header.ehdr.e_ident[EI_MAG3] != ELFMAG3) {
		return false;
	}

	/*
	 * Check whether the executable header and program headers are laid out
	 * as expected.
	 */
	if (elf_header.ehdr.e_phoff != offsetof(typeof(elf_header), phdr) ||
	    elf_header.ehdr.e_phnum > ARRAY_SIZE(elf_header.phdr)) {
		efi_err("Unexpected ELF header layout\n");
		return false;
	}

	/*
	 * Iterate over the PT_LOAD headers to find the size of the executable
	 * image in memory.
	 */
	for (int i = 0; i < elf_header.ehdr.e_phnum; i++) {
		auto ph = &elf_header.phdr[i];

		if (ph->p_type != PT_LOAD)
			continue;

		min = min(min, ph->p_paddr);
		max = max(max, ph->p_paddr + ph->p_memsz);
	}

	if (min >= max) {
		efi_err("Failed to determine ELF memory size\n");
		return false;
	}

	efi_info("ELF zboot payload detected\n");

	*alloc_size = max - min;
	*entry = elf_header.ehdr.e_entry - elf_header.phdr[0].p_paddr;

	return true;
}

static void handle_dynamic(const Elf64_Dyn *dyn, Elf64_Off p2v_offset,
			   u64 va_shift)
{
	const Elf64_Rela *rela = NULL;
	u64 *relr = NULL;
	int relasize = 0;
	int relrsize = 0;
	u64 *place;

	for (auto d = dyn; d->d_tag != DT_NULL; d++) {
		switch (d->d_tag) {
		case DT_RELA:
			rela = (void *)(d->d_un.d_ptr + p2v_offset);
			break;
		case DT_RELASZ:
			relasize = d->d_un.d_val;
			break;
		case DT_RELR:
			relr = (void *)(d->d_un.d_ptr + p2v_offset);
			break;
		case DT_RELRSZ:
			relrsize = d->d_un.d_val;
			break;
		}
	}

	for (int i = 0; i < relasize / sizeof(*rela); i++) {
		if (ELF64_R_TYPE(rela[i].r_info) == 0x0)
			continue;

		place = (u64 *)(rela[i].r_offset + p2v_offset);
		*place += va_shift;
	}

	for (int i = 0; i < relrsize / sizeof(u64); i++) {
		if ((relr[i] & 1) == 0) {
			place = (u64 *)(relr[i] + p2v_offset);
			*place++ += va_shift;
			continue;
		}

		for (u64 *p = place, r = relr[i] >> 1; r; p++, r >>= 1)
			if (r & 1)
				*p += va_shift;
		place += 63;
	}
}

bool efi_zboot_decompress_segments(u8 *out, unsigned long outlen,
				   unsigned long va_shift,
				   bool (*decompress_slice)(u8 *, unsigned long))
{
	unsigned long pos = sizeof(elf_header);

	/*
	 * Iterate over the program headers, and decompress the payload of each
	 * PT_LOAD entry. This involves skipping the padding by decompressing
	 * it into the output buffer before overwriting it with the actual
	 * data.
	 */
	for (int i = 0; i < elf_header.ehdr.e_phnum; i++) {
		auto ph = &elf_header.phdr[i];
		void *dst = out + ph->p_paddr - elf_header.phdr[0].p_paddr;

		if (ph->p_type == PT_DYNAMIC && va_shift != 0)
			handle_dynamic(dst, (Elf64_Off)dst - ph->p_vaddr, va_shift);

		if (ph->p_type != PT_LOAD)
			continue;

		if (ph->p_offset < pos) {
			efi_err("ELF PT_LOAD headers out of order\n");
			return false;
		}

		/* extract and discard the padding */
		while (ph->p_offset > pos) {
			unsigned long l = min(ph->p_offset - pos, ph->p_memsz);

			decompress_slice(dst, l);
			pos += l;
		}

		/* decompress payload */
		decompress_slice(dst, ph->p_filesz);

		/* clear area that was not covered by file data */
		if (ph->p_memsz > ph->p_filesz)
			memset(dst + ph->p_filesz, 0, ph->p_memsz - ph->p_filesz);

		if (ph->p_flags & PF_X)
			efi_cache_sync_image((unsigned long)dst, ph->p_filesz);

		pos = ph->p_offset + ph->p_filesz;
	}

	/* grab a reference to the memory attributes protocol, if available */
	efi_memory_attribute_protocol_t *memattr;
	efi_status_t status = efi_bs_call(locate_protocol,
					  &EFI_MEMORY_ATTRIBUTE_PROTOCOL_GUID,
					  NULL, (void **)&memattr);
	if (status != EFI_SUCCESS)
		return true;

	for (int i = 0; i < elf_header.ehdr.e_phnum; i++) {
		auto ph = &elf_header.phdr[i];
		unsigned long pa = (unsigned long)out + ph->p_paddr - elf_header.phdr[0].p_paddr;

		if (ph->p_type != PT_LOAD)
			continue;

		if (ph->p_flags == (PF_R | PF_X)) {
			unsigned long l = ALIGN(ph->p_memsz, EFI_PAGE_SIZE);

			status = memattr->set_memory_attributes(memattr, pa, l, EFI_MEMORY_RO);
			if (status != EFI_SUCCESS)
				efi_warn("Failed to set EFI_MEMORY_RO on R-X region\n");

			status = memattr->clear_memory_attributes(memattr, pa, l, EFI_MEMORY_XP);
			if (status != EFI_SUCCESS)
				efi_warn("Failed to clear EFI_MEMORY_XP from R-X region\n");
		}
	}

	return true;
}
