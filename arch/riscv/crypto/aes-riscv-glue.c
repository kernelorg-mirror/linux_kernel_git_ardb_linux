// SPDX-License-Identifier: GPL-2.0-only
/*
 * Linux/riscv port of the OpenSSL AES implementation for RISCV
 *
 * Copyright (C) 2023 VRULL GmbH
 * Author: Heiko Stuebner <heiko.stuebner@vrull.eu>
 */

#include <linux/crypto.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/types.h>
#include <asm/simd.h>
#include <asm/vector.h>
#include <crypto/aes.h>
#include <crypto/internal/cipher.h>
#include <crypto/internal/simd.h>

/* variant using the zvkned vector crypto extension */
void rv64i_zvkned_encrypt(const u8 *in, u8 *out, const u32 *key);
void rv64i_zvkned_decrypt(const u8 *in, u8 *out, const u32 *key);

static int riscv64_aes_setkey_zvkned(struct crypto_tfm *tfm, const u8 *key,
			 unsigned int keylen)
{
	struct crypto_aes_ctx *ctx = crypto_tfm_ctx(tfm);

	return aes_expandkey(ctx, key, keylen);
}

static void riscv64_aes_encrypt_zvkned(struct crypto_tfm *tfm, u8 *dst, const u8 *src)
{
	struct crypto_aes_ctx *ctx = crypto_tfm_ctx(tfm);

	if (crypto_simd_usable()) {
		kernel_rvv_begin();
		rv64i_zvkned_encrypt(src, dst, ctx->key_enc);
		kernel_rvv_end();
	} else {
		aes_encrypt(ctx, dst, src);
	}
}

static void riscv64_aes_decrypt_zvkned(struct crypto_tfm *tfm, u8 *dst, const u8 *src)
{
	struct crypto_aes_ctx *ctx = crypto_tfm_ctx(tfm);

	if (crypto_simd_usable()) {
		kernel_rvv_begin();
		rv64i_zvkned_decrypt(src, dst, ctx->key_enc);
		kernel_rvv_end();
	} else {
		aes_decrypt(ctx, dst, src);
	}
}

struct crypto_alg riscv64_aes_zvkned_alg = {
	.cra_name = "aes",
	.cra_driver_name = "riscv-aes-zvkned",
	.cra_module = THIS_MODULE,
	.cra_priority = 300,
	.cra_type = NULL,
	.cra_flags = CRYPTO_ALG_TYPE_CIPHER,
	.cra_alignmask = 0,
	.cra_blocksize = AES_BLOCK_SIZE,
	.cra_ctxsize = sizeof(struct crypto_aes_ctx),
	.cra_cipher = {
		.cia_min_keysize = AES_MIN_KEY_SIZE,
		.cia_max_keysize = AES_MAX_KEY_SIZE,
		.cia_setkey = riscv64_aes_setkey_zvkned,
		.cia_encrypt = riscv64_aes_encrypt_zvkned,
		.cia_decrypt = riscv64_aes_decrypt_zvkned,
	},
};

static int __init riscv_aes_mod_init(void)
{
	if (riscv_isa_extension_available(NULL, ZVKNED) &&
	    riscv_vector_vlen() >= 128)
		return crypto_register_alg(&riscv64_aes_zvkned_alg);

	return 0;
}

static void __exit riscv_aes_mod_fini(void)
{
	if (riscv_isa_extension_available(NULL, ZVKNED) &&
	    riscv_vector_vlen() >= 128)
		return crypto_unregister_alg(&riscv64_aes_zvkned_alg);
}

module_init(riscv_aes_mod_init);
module_exit(riscv_aes_mod_fini);

MODULE_DESCRIPTION("AES (accelerated)");
MODULE_AUTHOR("Heiko Stuebner <heiko.stuebner@vrull.eu>");
MODULE_LICENSE("GPL");
MODULE_ALIAS_CRYPTO("aes");
