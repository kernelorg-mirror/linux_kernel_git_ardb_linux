// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Linux/riscv64 port of the OpenSSL SHA512 implementation for RISCV64
 *
 * Copyright (C) 2023 VRULL GmbH
 * Author: Heiko Stuebner <heiko.stuebner@vrull.eu>
 */

#include <linux/module.h>
#include <linux/types.h>
#include <asm/simd.h>
#include <asm/vector.h>
#include <crypto/internal/hash.h>
#include <crypto/internal/simd.h>
#include <crypto/sha2.h>
#include <crypto/sha512_base.h>

asmlinkage void sha512_block_data_order_zvbb_zvknhb(u64 *digest, const void *data,
					unsigned int num_blks);


static void __sha512_block_data_order(struct sha512_state *sst, u8 const *src,
				      int blocks)
{
	sha512_block_data_order_zvbb_zvknhb(sst->state, src, blocks);
}

static int sha512_update(struct shash_desc *desc, const u8 *data,
			 unsigned int len)
{
	if (crypto_simd_usable()) {
		int ret;

		kernel_rvv_begin();
		ret = sha512_base_do_update(desc, data, len,
					    __sha512_block_data_order);
		kernel_rvv_end();
		return ret;
	} else {
		return crypto_sha512_update(desc, data, len);
	}
}

static int sha512_finup(struct shash_desc *desc, const u8 *data,
			unsigned int len, u8 *out)
{
	if (!crypto_simd_usable())
		return crypto_sha512_finup(desc, data, len, out);

	kernel_rvv_begin();
	if (len)
		sha512_base_do_update(desc, data, len,
				      __sha512_block_data_order);

	sha512_base_do_finalize(desc, __sha512_block_data_order);
	kernel_rvv_end();

	return sha512_base_finish(desc, out);
}

static int sha512_final(struct shash_desc *desc, u8 *out)
{
	return sha512_finup(desc, NULL, 0, out);
}

static struct shash_alg sha512_alg = {
	.digestsize		= SHA512_DIGEST_SIZE,
	.init			= sha512_base_init,
	.update			= sha512_update,
	.final			= sha512_final,
	.finup			= sha512_finup,
	.descsize		= sizeof(struct sha512_state),
	.base.cra_name		= "sha512",
	.base.cra_driver_name	= "sha512-riscv64-zvknhb",
	.base.cra_priority	= 150,
	.base.cra_blocksize	= SHA512_BLOCK_SIZE,
	.base.cra_module	= THIS_MODULE,
};

static int __init sha512_mod_init(void)
{
	/* sha512 needs at least a vlen of 256 to work correctly */
	if (riscv_isa_extension_available(NULL, ZVKNHB) &&
	    riscv_isa_extension_available(NULL, ZVBB) &&
	    riscv_vector_vlen() >= 256)
		return crypto_register_shash(&sha512_alg);

	return 0;
}

static void __exit sha512_mod_fini(void)
{
	if (riscv_isa_extension_available(NULL, ZVKNHB) &&
	    riscv_isa_extension_available(NULL, ZVBB) &&
	    riscv_vector_vlen() >= 256)
		crypto_unregister_shash(&sha512_alg);
}

module_init(sha512_mod_init);
module_exit(sha512_mod_fini);

MODULE_DESCRIPTION("SHA-512 secure hash for riscv64");
MODULE_AUTHOR("Andy Polyakov <appro@openssl.org>");
MODULE_AUTHOR("Ard Biesheuvel <ard.biesheuvel@linaro.org>");
MODULE_LICENSE("GPL");
MODULE_ALIAS_CRYPTO("sha512");
