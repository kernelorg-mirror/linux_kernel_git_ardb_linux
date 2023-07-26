// SPDX-License-Identifier: GPL-2.0-only
/*
 * Scalar AES core transform using RISC-V Zkned extensionst
 *
 * Copyright (C) 2023 Google, LLC.
 * Author: Ard Biesheuvel <ardb@kernel.org>
 */

#include <crypto/aes.h>
#include <crypto/algapi.h>
#include <linux/module.h>

asmlinkage void __aes_riscv_scalar_encrypt(u32 *rk, int rounds, u8 *out, const u8 *in);
asmlinkage void __aes_riscv_scalar_decrypt(u32 *rk, int rounds, u8 *out, const u8 *in);

static int aes_riscv_set_key(struct crypto_tfm *tfm, const u8 *in_key,
			     unsigned int key_len)
{
	struct crypto_aes_ctx *ctx = crypto_tfm_ctx(tfm);

	return aes_expandkey(ctx, in_key, key_len);
}

static void aes_riscv_encrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	struct crypto_aes_ctx *ctx = crypto_tfm_ctx(tfm);
	int rounds = 6 + ctx->key_length / 4;

	__aes_riscv_scalar_encrypt(ctx->key_enc, rounds, out, in);
}

static void aes_riscv_decrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	struct crypto_aes_ctx *ctx = crypto_tfm_ctx(tfm);
	int rounds = 6 + ctx->key_length / 4;

	__aes_riscv_scalar_decrypt(ctx->key_dec, rounds, out, in);
}

static struct crypto_alg aes_alg = {
	.cra_name			= "aes",
	.cra_driver_name		= "aes-riscv-scalar",
	.cra_priority			= 200,
	.cra_flags			= CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize			= AES_BLOCK_SIZE,
	.cra_ctxsize			= sizeof(struct crypto_aes_ctx),
	.cra_module			= THIS_MODULE,

	.cra_cipher.cia_min_keysize	= AES_MIN_KEY_SIZE,
	.cra_cipher.cia_max_keysize	= AES_MAX_KEY_SIZE,
	.cra_cipher.cia_setkey		= aes_riscv_set_key,
	.cra_cipher.cia_encrypt		= aes_riscv_encrypt,
	.cra_cipher.cia_decrypt		= aes_riscv_decrypt
};

static int __init riscv_aes_init(void)
{
	if (!riscv_isa_extension_available(NULL, ZKNE) ||
	    !riscv_isa_extension_available(NULL, ZKND))
		return -ENODEV;
	return crypto_register_alg(&aes_alg);
}

static void __exit riscv_aes_fini(void)
{
	crypto_unregister_alg(&aes_alg);
}

module_init(riscv_aes_init);
module_exit(riscv_aes_fini);

MODULE_DESCRIPTION("Scalar AES cipher using RISC-V Zkned extension");
MODULE_AUTHOR("Ard Biesheuvel <ardb@kernel.org>");
MODULE_LICENSE("GPL");
MODULE_ALIAS_CRYPTO("aes");
