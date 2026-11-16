/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2017 Linaro Ltd. <ard.biesheuvel@linaro.org>
 */

#ifdef CONFIG_ARM
/*
 * AArch32 does not provide this intrinsic natively because it does not
 * implement the underlying instruction. AArch32 only provides a 64-bit
 * wide vtbl.8 instruction, so use that instead.
 */
static inline uint8x16_t vqtbl1q_u8(uint8x16_t a, uint8x16_t b)
{
	union {
		uint8x16_t	val;
		uint8x8x2_t	pair;
	} __a = { a };

	return vcombine_u8(vtbl2_u8(__a.pair, vget_low_u8(b)),
			   vtbl2_u8(__a.pair, vget_high_u8(b)));
}
#endif
