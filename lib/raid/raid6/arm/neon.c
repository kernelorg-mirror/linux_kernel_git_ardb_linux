// SPDX-License-Identifier: GPL-2.0-only
/*
 * RAID6 syndrome calculation using ARM NEON intrinsics
 *
 * Copyright (C) 2013 Linaro Ltd <ard.biesheuvel@linaro.org>
 */

#include <asm/simd.h>
#include "algos.h"
#include "arm/neon.h"

/*
 * There are 2 reasons these wrappers are kept in a separate compilation unit
 * from the actual implementations in neonN.c (generated from neon.uc by
 * unroll.awk):
 * - the actual implementations use NEON intrinsics, and the GCC support header
 *   (arm_neon.h) is not fully compatible (type wise) with the kernel;
 * - the neonN.c files are compiled with -mfpu=neon and optimization enabled,
 *   and we have to make sure that we never use *any* NEON/VFP instructions
 *   outside a kernel_neon_begin()/kernel_neon_end() pair.
 */

#define RAID6_NEON_WRAPPER(_pfx, _n, _name)				\
	static void _pfx ## _n ## _gen_syndrome(int disks,		\
					size_t bytes, void **ptrs)	\
	{								\
		scoped_ksimd()						\
			_pfx ## _n ## _gen_syndrome_real(disks,		\
					(unsigned long)bytes, ptrs);	\
	}								\
	static void _pfx ## _n ## _xor_syndrome(int disks,		\
					int start, int stop,		\
					size_t bytes, void **ptrs)	\
	{								\
		scoped_ksimd()						\
			_pfx ## _n ## _xor_syndrome_real(disks,		\
				start, stop, (unsigned long)bytes, ptrs,\
				raid6_vgfmul[raid6_gfexp[start]]);	\
	}								\
	struct raid6_calls const raid6_ ## _name = {			\
		.gen_syndrome	= _pfx ## _n ## _gen_syndrome,		\
		.xor_syndrome	= _pfx ## _n ## _xor_syndrome,		\
		.name		= #_name,				\
	}

RAID6_NEON_WRAPPER(raid6_neon, 1, neonx1);
RAID6_NEON_WRAPPER(raid6_neon, 2, neonx2);
RAID6_NEON_WRAPPER(raid6_neon, 4, neonx4);
RAID6_NEON_WRAPPER(raid6_neon, 8, neonx8);

#ifdef CONFIG_ARM64
/* versions using the EOR3 instruction from the SHA3 extension */
RAID6_NEON_WRAPPER(raid6_eor3_, 1, eor3x1);
RAID6_NEON_WRAPPER(raid6_eor3_, 2, eor3x2);
RAID6_NEON_WRAPPER(raid6_eor3_, 4, eor3x4);
RAID6_NEON_WRAPPER(raid6_eor3_, 8, eor3x8);
#endif
