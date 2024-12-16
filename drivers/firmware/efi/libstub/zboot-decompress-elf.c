// SPDX-License-Identifier: GPL-2.0

#include <linux/efi.h>
#include <linux/elf.h>

#include <asm/efi.h>

#include "efistub.h"

static struct {
	Elf64_Ehdr	ehdr;
	Elf64_Phdr	phdr[5];
} elf_header;

static unsigned long load_base;		/* lowest PT_LOAD p_paddr */

bool efi_zboot_check_elf(unsigned long *alloc_size,
			 bool (*decompress_slice)(u8 *, unsigned long))
{
	unsigned long min = ULONG_MAX, max = 0;

	if (!decompress_slice((u8 *)&elf_header, sizeof(elf_header))) {
		efi_err("failed to extract header\n");
		return false;
	}

	/* Check the ELF magic, and whether the image is for this architecture */
	if (elf_header.ehdr.e_ident[EI_MAG0] != ELFMAG0 ||
	    elf_header.ehdr.e_ident[EI_MAG1] != ELFMAG1 ||
	    elf_header.ehdr.e_ident[EI_MAG2] != ELFMAG2 ||
	    elf_header.ehdr.e_ident[EI_MAG3] != ELFMAG3 ||
	    elf_header.ehdr.e_ident[EI_CLASS] != ELF_CLASS ||
	    elf_header.ehdr.e_ident[EI_DATA] != ELF_DATA ||
	    elf_header.ehdr.e_machine != ELF_ARCH) {
		efi_err("Payload is not an ELF image for this architecture\n");
		return false;
	}

	/*
	 * The payload is decompressed as a stream, so the program headers must
	 * directly follow the executable header.
	 */
	if (elf_header.ehdr.e_phoff != sizeof(elf_header.ehdr) ||
	    elf_header.ehdr.e_phentsize != sizeof(Elf64_Phdr) ||
	    elf_header.ehdr.e_phnum == 0 ||
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

		if (ph->p_type != PT_LOAD || !ph->p_memsz)
			continue;

		if (ph->p_filesz > ph->p_memsz ||
		    ph->p_memsz > ULONG_MAX - ph->p_paddr ||
		    ph->p_filesz > ULONG_MAX - ph->p_offset) {
			efi_err("Invalid ELF PT_LOAD header\n");
			return false;
		}

		min = min(min, ph->p_paddr);
		max = max(max, ph->p_paddr + ph->p_memsz);
	}

	if (min >= max) {
		efi_err("Failed to determine ELF memory size\n");
		return false;
	}

	efi_info("ELF zboot payload detected\n");

	load_base = min;
	*alloc_size = max - min;

	return true;
}

/* Decompress and discard len bytes of the payload, using buf as scratch. */
static bool skip_slice(u8 *buf, unsigned long bufsize, unsigned long len,
		       bool (*decompress_slice)(u8 *, unsigned long))
{
	while (len > 0) {
		unsigned long l = min(len, bufsize);

		if (!decompress_slice(buf, l))
			return false;
		len -= l;
	}
	return true;
}

bool efi_zboot_decompress_segments(u8 *out, unsigned long outlen,
				   unsigned long payload_size,
				   bool (*decompress_slice)(u8 *, unsigned long))
{
	unsigned long pos = sizeof(elf_header);
	unsigned long end = 0;	/* end of the previous PT_LOAD in memory */
	u8 buf[256];

	/*
	 * Iterate over the program headers, and decompress the payload of each
	 * PT_LOAD entry. The stream only moves forward, so the PT_LOAD headers
	 * must be sorted by file offset, and, as the ELF spec requires, by
	 * address. Padding between the segments in the file is skipped by
	 * decompressing it into the output buffer before overwriting it with
	 * the actual data, and gaps between the segments in memory are cleared,
	 * so that the result is identical to the binary image.
	 */
	for (int i = 0; i < elf_header.ehdr.e_phnum; i++) {
		auto ph = &elf_header.phdr[i];
		unsigned long offset = ph->p_paddr - load_base;
		u8 *dst = out + offset;

		if (ph->p_type != PT_LOAD || !ph->p_memsz)
			continue;

		if (ph->p_offset < pos || offset < end) {
			efi_err("ELF PT_LOAD headers out of order\n");
			return false;
		}

		/* clear the gap after the previous segment */
		if (offset > end)
			memset(out + end, 0, offset - end);

		/* extract and discard the padding */
		if (!skip_slice(dst, ph->p_memsz, ph->p_offset - pos,
				decompress_slice))
			return false;

		/* decompress payload (zlib fails requests for 0 bytes) */
		if (ph->p_filesz && !decompress_slice(dst, ph->p_filesz))
			return false;

		/* clear area that was not covered by file data */
		if (ph->p_memsz > ph->p_filesz)
			memset(dst + ph->p_filesz, 0, ph->p_memsz - ph->p_filesz);

		pos = ph->p_offset + ph->p_filesz;
		end = offset + ph->p_memsz;
	}

	/* clear the rest of the memory image */
	if (outlen > end)
		memset(out + end, 0, outlen - end);

	/*
	 * Extract and discard the rest of the payload as well, so that the
	 * caller can check that the stream ends there, which also verifies
	 * the checksum of the stream if it has one.
	 */
	if (payload_size > pos &&
	    !skip_slice(buf, sizeof(buf), payload_size - pos, decompress_slice))
		return false;

	return true;
}
