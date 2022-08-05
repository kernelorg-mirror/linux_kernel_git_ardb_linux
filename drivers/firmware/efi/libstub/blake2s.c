// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * This is an implementation of the BLAKE2s hash and PRF functions.
 *
 * Information: https://blake2.net/
 *
 */

#include <crypto/internal/blake2s.h>

void blake2s_update(struct blake2s_state *state, const u8 *in, size_t inlen)
{
	__blake2s_update(state, in, inlen, false);
}

void blake2s_final(struct blake2s_state *state, u8 *out)
{
	__blake2s_final(state, out, false);
}
