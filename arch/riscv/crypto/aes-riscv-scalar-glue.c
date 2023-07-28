// SPDX-License-Identifier: GPL-2.0-only
/*
 * Scalar AES core transform using RISC-V Zkned extensionst
 *
 * Copyright (C) 2023 Google, LLC.
 * Author: Ard Biesheuvel <ardb@kernel.org>
 */

#include <crypto/aes.h>
#include <crypto/algapi.h>
#include <crypto/internal/skcipher.h>
#include <linux/module.h>

asmlinkage void __aes_riscv_scalar_encrypt(u32 *rk, int rounds, u8 *out, const u8 *in);
asmlinkage void __aes_riscv_scalar_decrypt(u32 *rk, int rounds, u8 *out, const u8 *in);
asmlinkage void __aes_riscv_scalar_expand_key(u32 *enc_key, u32 *dec_key, int keylen);

static int aes_riscv_set_key(struct crypto_lskcipher *tfm, const u8 *in_key,
			     unsigned int key_len)
{
	struct crypto_aes_ctx *ctx = crypto_lskcipher_ctx(tfm);
	int err;

	if (!IS_ENABLED(CONFIG_64BIT))
		return aes_expandkey(ctx, in_key, key_len);

	err = aes_check_keylen(key_len);
	if (err)
		return err;

	ctx->key_length = key_len;

	for (int i = 0; i < key_len / sizeof(u32); i++)
		ctx->key_enc[i] = get_unaligned_le32(in_key + i * sizeof(u32));

	__aes_riscv_scalar_expand_key(ctx->key_enc, ctx->key_dec, key_len);
	return 0;
}

static int aes_riscv_encrypt(struct crypto_lskcipher *tfm, const u8 *src,
			     u8 *dst, unsigned int nbytes, u8 *iv, bool final)
{
	struct crypto_aes_ctx *ctx = crypto_lskcipher_ctx(tfm);
	int r = 6 + ctx->key_length / 4;

	if (final && (nbytes % AES_BLOCK_SIZE))
		return -EINVAL;

	while (nbytes >= AES_BLOCK_SIZE) {
		__aes_riscv_scalar_encrypt(ctx->key_enc, r, dst, src);

		dst += AES_BLOCK_SIZE;
		src += AES_BLOCK_SIZE;
		nbytes -= AES_BLOCK_SIZE;
	}
	return nbytes;
}

static int aes_riscv_decrypt(struct crypto_lskcipher *tfm, const u8 *src,
			     u8 *dst, unsigned int nbytes, u8 *iv, bool final)
{
	struct crypto_aes_ctx *ctx = crypto_lskcipher_ctx(tfm);
	int r = 6 + ctx->key_length / 4;

	if (final && (nbytes % AES_BLOCK_SIZE))
		return -EINVAL;

	while (nbytes >= AES_BLOCK_SIZE) {
		__aes_riscv_scalar_decrypt(ctx->key_dec, r, dst, src);

		dst += AES_BLOCK_SIZE;
		src += AES_BLOCK_SIZE;
		nbytes -= AES_BLOCK_SIZE;
	}
	return nbytes;
}

static struct lskcipher_alg aes_alg = {
	.co.base.cra_name		= "aes",
	.co.base.cra_driver_name	= "aes-riscv-scalar",
	.co.base.cra_priority		= 200,
	.co.base.cra_blocksize		= AES_BLOCK_SIZE,
	.co.base.cra_ctxsize		= sizeof(struct crypto_aes_ctx),
	.co.base.cra_module		= THIS_MODULE,
	.co.min_keysize			= AES_MIN_KEY_SIZE,
	.co.max_keysize			= AES_MAX_KEY_SIZE,

	.setkey				= aes_riscv_set_key,
	.encrypt			= aes_riscv_encrypt,
	.decrypt			= aes_riscv_decrypt
};

static int __init riscv_aes_init(void)
{
	if (!riscv_isa_extension_available(NULL, ZKNE) ||
	    !riscv_isa_extension_available(NULL, ZKND))
		return -ENODEV;
	return crypto_register_lskcipher(&aes_alg);
}

static void __exit riscv_aes_fini(void)
{
	crypto_unregister_lskcipher(&aes_alg);
}

module_init(riscv_aes_init);
module_exit(riscv_aes_fini);

MODULE_DESCRIPTION("Scalar AES lskcipher using RISC-V Zkned extension");
MODULE_AUTHOR("Ard Biesheuvel <ardb@kernel.org>");
MODULE_LICENSE("GPL");
MODULE_ALIAS_CRYPTO("aes");
