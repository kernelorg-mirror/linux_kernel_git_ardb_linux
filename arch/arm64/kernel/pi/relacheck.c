// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2022 - Google LLC
 * Author: Ard Biesheuvel <ardb@google.com>
 */

#include <elf.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define HOST_ORDER ELFDATA2LSB
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define HOST_ORDER ELFDATA2MSB
#endif

static bool swap;

static uint64_t swab_elfxword(uint64_t val)
{
	return swap ? __builtin_bswap64(val) : val;
}

static Elf64_Ehdr *ehdr;
static Elf64_Shdr *shdr;

static uint32_t swab_elfword(uint32_t val)
{
	return swap ? __builtin_bswap32(val) : val;
}

static uint16_t swab_elfhword(uint16_t val)
{
	return swap ? __builtin_bswap16(val) : val;
}

int main(int argc, char *argv[])
{
	struct stat stat;
	int fd, ret;

	if (argc < 2) {
		fprintf(stderr, "file argument missing\n");
		exit(EXIT_FAILURE);
	}

	fd = open(argv[1], O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "failed to open %s\n", argv[1]);
		exit(EXIT_FAILURE);
	}

	ret = fstat(fd, &stat);
	if (ret < 0) {
		fprintf(stderr, "failed to stat() %s\n", argv[1]);
		exit(EXIT_FAILURE);
	}

	ehdr = mmap(0, stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (ehdr == MAP_FAILED) {
		fprintf(stderr, "failed to mmap() %s\n", argv[1]);
		exit(EXIT_FAILURE);
	}

	swap = ehdr->e_ident[EI_DATA] != HOST_ORDER;
	shdr = (void *)ehdr + swab_elfxword(ehdr->e_shoff);

	for (int i = 0; i < swab_elfhword(ehdr->e_shnum); i++) {
		unsigned long info, flags;
		const Elf64_Rela *rela;
		int numrela;

		if (swab_elfword(shdr[i].sh_type) != SHT_RELA)
			continue;

		/* only consider RELA sections operating on data */
		info = swab_elfword(shdr[i].sh_info);
		flags = swab_elfxword(shdr[info].sh_flags);
		if ((flags & (SHF_ALLOC | SHF_EXECINSTR)) != SHF_ALLOC)
			continue;

		rela = (void *)ehdr + swab_elfxword(shdr[i].sh_offset);
		numrela = swab_elfxword(shdr[i].sh_size) / sizeof(*rela);

		for (int j = 0; j < numrela; j++) {
			uint64_t info = swab_elfxword(rela[j].r_info);

			if (ELF64_R_TYPE(info) == R_AARCH64_ABS64) {
				fprintf(stderr,
					"Absolute relocations detected in %s\n",
					argv[1]);
				exit(EXIT_FAILURE);
			}
		}
	}
	return 0;
}
