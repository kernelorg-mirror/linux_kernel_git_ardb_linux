// SPDX-License-Identifier: GPL-2.0

#include <linux/elf.h>

#include <asm/setup.h>

unsigned long __initdata va_shift;

extern const Elf64_Rela rela_start[], rela_end[];
extern const unsigned long relr_start[], relr_end[];

void __init startup_relocate_kernel(void)
{
	u64 *place;

	if (!va_shift)
		return;

	for (auto rela = rela_start; rela < rela_end; rela++) {
		place = (u64 *)(rela->r_offset + va_shift);
		*place += va_shift;
	}

	for (auto relr = relr_start; relr < relr_end; relr++) {
		switch (*relr & 1) {
		case 0:
			place = (u64 *)(*relr + va_shift);
			*place++ += va_shift;
			break;
		case 1:
			for (u64 *p = place, r = *relr >> 1; r; p++, r >>= 1)
				if (r & 1)
					*p += va_shift;
			place += 63;
		}
	}
}
