// SPDX-License-Identifier: GPL-2.0-only
/*
 * Linux/riscv64 port of the OpenSSL SM4 implementation for RISCV64
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
#include <crypto/sm4.h>
#include <crypto/internal/cipher.h>
#include <crypto/internal/simd.h>

struct sm4_key {
	u32 rkey[SM4_RKEY_WORDS];
};

void rv64i_zvksed_sm4_encrypt(const u8 *in, u8 *out, const struct sm4_key *key);
void rv64i_zvksed_sm4_decrypt(const u8 *in, u8 *out, const struct sm4_key *key);
int rv64i_zvksed_sm4_set_encrypt_key(const u8 *userKey, struct sm4_key *key);
int rv64i_zvksed_sm4_set_decrypt_key(const u8 *userKey, struct sm4_key *key);

struct riscv_sm4_ctx {
	struct crypto_cipher *fallback;
	struct sm4_key enc_key;
	struct sm4_key dec_key;
	unsigned int keylen;
};

static int riscv64_sm4_init_zvksed(struct crypto_tfm *tfm)
{
	struct riscv_sm4_ctx *ctx = crypto_tfm_ctx(tfm);
	const char *alg = crypto_tfm_alg_name(tfm);
	struct crypto_cipher *fallback;

	fallback = crypto_alloc_cipher(alg, 0, CRYPTO_ALG_NEED_FALLBACK);
	if (IS_ERR(fallback)) {
		pr_err("Failed to allocate fallback for '%s': %ld\n",
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

static void riscv64_sm4_exit_zvksed(struct crypto_tfm *tfm)
{
	struct riscv_sm4_ctx *ctx = crypto_tfm_ctx(tfm);

	if (ctx->fallback) {
		crypto_free_cipher(ctx->fallback);
		ctx->fallback = NULL;
	}
}

static int riscv64_sm4_setkey_zvksed(struct crypto_tfm *tfm, const u8 *key,
				     unsigned int keylen)
{
	struct riscv_sm4_ctx *ctx = crypto_tfm_ctx(tfm);
	int ret;

	ctx->keylen = keylen;

	kernel_rvv_begin();
	ret = rv64i_zvksed_sm4_set_encrypt_key(key, &ctx->enc_key);
	if (ret != 1) {
		kernel_rvv_end();
		return -EINVAL;
	}

	ret = rv64i_zvksed_sm4_set_decrypt_key(key, &ctx->dec_key);
	kernel_rvv_end();
	if (ret != 1)
		return -EINVAL;

	ret = crypto_cipher_setkey(ctx->fallback, key, keylen);

	return ret ? -EINVAL : 0;
}

static void riscv64_sm4_encrypt_zvksed(struct crypto_tfm *tfm, u8 *dst, const u8 *src)
{
	struct riscv_sm4_ctx *ctx = crypto_tfm_ctx(tfm);

	if (crypto_simd_usable()) {
		kernel_rvv_begin();
		rv64i_zvksed_sm4_encrypt(src, dst, &ctx->enc_key);
		kernel_rvv_end();
	} else {
		crypto_cipher_encrypt_one(ctx->fallback, dst, src);
	}
}

static void riscv64_sm4_decrypt_zvksed(struct crypto_tfm *tfm, u8 *dst, const u8 *src)
{
	struct riscv_sm4_ctx *ctx = crypto_tfm_ctx(tfm);

	if (crypto_simd_usable()) {
		kernel_rvv_begin();
		rv64i_zvksed_sm4_decrypt(src, dst, &ctx->dec_key);
		kernel_rvv_end();
	} else {
		crypto_cipher_decrypt_one(ctx->fallback, dst, src);
	}
}

struct crypto_alg riscv64_sm4_zvksed_alg = {
	.cra_name = "sm4",
	.cra_driver_name = "riscv-sm4-zvksed",
	.cra_module = THIS_MODULE,
	.cra_priority = 300,
	.cra_flags = CRYPTO_ALG_TYPE_CIPHER | CRYPTO_ALG_NEED_FALLBACK,
	.cra_blocksize = SM4_BLOCK_SIZE,
	.cra_ctxsize = sizeof(struct riscv_sm4_ctx),
	.cra_init = riscv64_sm4_init_zvksed,
	.cra_exit = riscv64_sm4_exit_zvksed,
	.cra_cipher = {
		.cia_min_keysize = SM4_KEY_SIZE,
		.cia_max_keysize = SM4_KEY_SIZE,
		.cia_setkey = riscv64_sm4_setkey_zvksed,
		.cia_encrypt = riscv64_sm4_encrypt_zvksed,
		.cia_decrypt = riscv64_sm4_decrypt_zvksed,
	},
};

static int __init riscv64_sm4_mod_init(void)
{
	if (riscv_isa_extension_available(NULL, ZVKSED) &&
	    riscv_isa_extension_available(NULL, ZVBB) &&
	    riscv_vector_vlen() >= 128)
		return crypto_register_alg(&riscv64_sm4_zvksed_alg);

	return 0;
}

static void __exit riscv64_sm4_mod_fini(void)
{
	if (riscv_isa_extension_available(NULL, ZVKSED) &&
	    riscv_isa_extension_available(NULL, ZVBB) &&
	    riscv_vector_vlen() >= 128)
		crypto_unregister_alg(&riscv64_sm4_zvksed_alg);
}

module_init(riscv64_sm4_mod_init);
module_exit(riscv64_sm4_mod_fini);

MODULE_DESCRIPTION("SM4 (accelerated)");
MODULE_AUTHOR("Heiko Stuebner <heiko.stuebner@vrull.eu>");
MODULE_LICENSE("GPL");
MODULE_ALIAS_CRYPTO("sm4");
