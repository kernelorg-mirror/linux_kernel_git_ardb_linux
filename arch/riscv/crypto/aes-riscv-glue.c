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

struct aes_key {
	u8 key[AES_MAX_KEYLENGTH];
	int rounds;
};

/* variant using the zvkned vector crypto extension */
void rv64i_zvkned_encrypt(const u8 *in, u8 *out, const struct aes_key *key);
void rv64i_zvkned_decrypt(const u8 *in, u8 *out, const struct aes_key *key);
int rv64i_zvkned_set_encrypt_key(const u8 *userKey, const int bits,
				struct aes_key *key);
int rv64i_zvkned_set_decrypt_key(const u8 *userKey, const int bits,
				struct aes_key *key);

struct riscv_aes_ctx {
	struct crypto_cipher *fallback;
	struct aes_key enc_key;
	struct aes_key dec_key;
	unsigned int keylen;
};

static int riscv64_aes_init_zvkned(struct crypto_tfm *tfm)
{
	struct riscv_aes_ctx *ctx = crypto_tfm_ctx(tfm);
	const char *alg = crypto_tfm_alg_name(tfm);
	struct crypto_cipher *fallback;

	fallback = crypto_alloc_cipher(alg, 0, CRYPTO_ALG_NEED_FALLBACK);
	if (IS_ERR(fallback)) {
		pr_err("Failed to allocate transformation for '%s': %ld\n",
		       alg, PTR_ERR(fallback));
		return PTR_ERR(fallback);
	}

	crypto_cipher_set_flags(fallback,
				crypto_cipher_get_flags((struct
							 crypto_cipher *)
							tfm));
	ctx->fallback = fallback;

	return 0;
}

static void riscv_aes_exit(struct crypto_tfm *tfm)
{
	struct riscv_aes_ctx *ctx = crypto_tfm_ctx(tfm);

	if (ctx->fallback) {
		crypto_free_cipher(ctx->fallback);
		ctx->fallback = NULL;
	}
}

static int riscv64_aes_setkey_zvkned(struct crypto_tfm *tfm, const u8 *key,
			 unsigned int keylen)
{
	struct riscv_aes_ctx *ctx = crypto_tfm_ctx(tfm);
	int ret;

	ctx->keylen = keylen;

	if (keylen == 16 || keylen == 32) {
		kernel_rvv_begin();
		ret = rv64i_zvkned_set_encrypt_key(key, keylen * 8, &ctx->enc_key);
		if (ret != 1) {
			kernel_rvv_end();
			return -EINVAL;
		}

		ret = rv64i_zvkned_set_decrypt_key(key, keylen * 8, &ctx->dec_key);
		kernel_rvv_end();
		if (ret != 1)
			return -EINVAL;
	}

	ret = crypto_cipher_setkey(ctx->fallback, key, keylen);

	return ret ? -EINVAL : 0;
}

static void riscv64_aes_encrypt_zvkned(struct crypto_tfm *tfm, u8 *dst, const u8 *src)
{
	struct riscv_aes_ctx *ctx = crypto_tfm_ctx(tfm);

	if (crypto_simd_usable() && (ctx->keylen == 16 || ctx->keylen == 32)) {
		kernel_rvv_begin();
		rv64i_zvkned_encrypt(src, dst, &ctx->enc_key);
		kernel_rvv_end();
	} else {
		crypto_cipher_encrypt_one(ctx->fallback, dst, src);
	}
}

static void riscv64_aes_decrypt_zvkned(struct crypto_tfm *tfm, u8 *dst, const u8 *src)
{
	struct riscv_aes_ctx *ctx = crypto_tfm_ctx(tfm);

	if (crypto_simd_usable() && (ctx->keylen == 16 || ctx->keylen == 32)) {
		kernel_rvv_begin();
		rv64i_zvkned_decrypt(src, dst, &ctx->dec_key);
		kernel_rvv_end();
	} else {
		crypto_cipher_decrypt_one(ctx->fallback, dst, src);
	}
}

struct crypto_alg riscv64_aes_zvkned_alg = {
	.cra_name = "aes",
	.cra_driver_name = "riscv-aes-zvkned",
	.cra_module = THIS_MODULE,
	.cra_priority = 300,
	.cra_type = NULL,
	.cra_flags = CRYPTO_ALG_TYPE_CIPHER | CRYPTO_ALG_NEED_FALLBACK,
	.cra_alignmask = 0,
	.cra_blocksize = AES_BLOCK_SIZE,
	.cra_ctxsize = sizeof(struct riscv_aes_ctx),
	.cra_init = riscv64_aes_init_zvkned,
	.cra_exit = riscv_aes_exit,
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
