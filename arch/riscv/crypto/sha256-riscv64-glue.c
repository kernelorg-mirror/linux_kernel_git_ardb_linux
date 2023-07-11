// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Linux/riscv64 port of the OpenSSL SHA256 implementation for RISCV64
 *
 * Copyright (C) 2022 VRULL GmbH
 * Author: Heiko Stuebner <heiko.stuebner@vrull.eu>
 */

#include <linux/module.h>
#include <linux/types.h>
#include <asm/simd.h>
#include <asm/vector.h>
#include <crypto/internal/hash.h>
#include <crypto/internal/simd.h>
#include <crypto/sha2.h>
#include <crypto/sha256_base.h>

asmlinkage void sha256_block_data_order_zvbb_zvknha(u32 *digest, const void *data,
					unsigned int num_blks);

static void __sha256_block_data_order(struct sha256_state *sst, u8 const *src,
				      int blocks)
{
	sha256_block_data_order_zvbb_zvknha(sst->state, src, blocks);
}

static int riscv64_sha256_update(struct shash_desc *desc, const u8 *data,
			 unsigned int len)
{
	if (crypto_simd_usable()) {
		int ret;

		kernel_rvv_begin();
		ret = sha256_base_do_update(desc, data, len,
					    __sha256_block_data_order);
		kernel_rvv_end();
		return ret;
	} else {
		sha256_update(shash_desc_ctx(desc), data, len);
		return 0;
	}
}

static int riscv64_sha256_finup(struct shash_desc *desc, const u8 *data,
			unsigned int len, u8 *out)
{
	if (!crypto_simd_usable()) {
		sha256_update(shash_desc_ctx(desc), data, len);
		sha256_final(shash_desc_ctx(desc), out);
		return 0;
	}

	kernel_rvv_begin();
	if (len)
		sha256_base_do_update(desc, data, len,
				      __sha256_block_data_order);

	sha256_base_do_finalize(desc, __sha256_block_data_order);
	kernel_rvv_end();

	return sha256_base_finish(desc, out);
}

static int riscv64_sha256_final(struct shash_desc *desc, u8 *out)
{
	return riscv64_sha256_finup(desc, NULL, 0, out);
}

static struct shash_alg sha256_alg = {
	.digestsize		= SHA256_DIGEST_SIZE,
	.init			= sha256_base_init,
	.update			= riscv64_sha256_update,
	.final			= riscv64_sha256_final,
	.finup			= riscv64_sha256_finup,
	.descsize		= sizeof(struct sha256_state),
	.base.cra_name		= "sha256",
	.base.cra_driver_name	= "sha256-riscv64-zvknha",
	.base.cra_priority	= 150,
	.base.cra_blocksize	= SHA256_BLOCK_SIZE,
	.base.cra_module	= THIS_MODULE,
};

static int __init sha256_mod_init(void)
{
	/*
	 * From the spec:
	 * Zvknhb supports SHA-256 and SHA-512. Zvknha supports only SHA-256.
	 */
	if ((riscv_isa_extension_available(NULL, ZVKNHA) ||
	     riscv_isa_extension_available(NULL, ZVKNHB)) &&
	     riscv_isa_extension_available(NULL, ZVBB) &&
	     riscv_vector_vlen() >= 128)

		return crypto_register_shash(&sha256_alg);

	return 0;
}

static void __exit sha256_mod_fini(void)
{
	if ((riscv_isa_extension_available(NULL, ZVKNHA) ||
	     riscv_isa_extension_available(NULL, ZVKNHB)) &&
	     riscv_isa_extension_available(NULL, ZVBB) &&
	     riscv_vector_vlen() >= 128)
		crypto_unregister_shash(&sha256_alg);
}

module_init(sha256_mod_init);
module_exit(sha256_mod_fini);

MODULE_DESCRIPTION("SHA-256 secure hash for riscv64");
MODULE_AUTHOR("Andy Polyakov <appro@openssl.org>");
MODULE_AUTHOR("Heiko Stuebner <heiko.stuebner@vrull.eu>");
MODULE_LICENSE("GPL");
MODULE_ALIAS_CRYPTO("sha256");
