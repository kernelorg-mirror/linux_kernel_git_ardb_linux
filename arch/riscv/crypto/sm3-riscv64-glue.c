// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Linux/riscv64 port of the OpenSSL SM3 implementation for RISCV64
 *
 * Copyright (C) 2023 VRULL GmbH
 * Author: Heiko Stuebner <heiko.stuebner@vrull.eu>
 */

#include <linux/types.h>
#include <asm/simd.h>
#include <asm/vector.h>
#include <crypto/internal/hash.h>
#include <crypto/internal/simd.h>
#include <crypto/sha2.h>
#include <crypto/sm3_base.h>

asmlinkage void ossl_hwsm3_block_data_order_zvksh(u32 *digest, const void *o,
						  unsigned int num);

static void __sm3_block_data_order(struct sm3_state *sst, u8 const *src,
				      int blocks)
{
	ossl_hwsm3_block_data_order_zvksh(sst->state, src, blocks);
}

static int riscv64_sm3_update(struct shash_desc *desc, const u8 *data,
			 unsigned int len)
{
	if (crypto_simd_usable()) {
		int ret;

		kernel_rvv_begin();
		ret = sm3_base_do_update(desc, data, len,
					    __sm3_block_data_order);
		kernel_rvv_end();
		return ret;
	} else {
		sm3_update(shash_desc_ctx(desc), data, len);
		return 0;
	}
}

static int riscv64_sm3_finup(struct shash_desc *desc, const u8 *data,
			unsigned int len, u8 *out)
{

	if (!crypto_simd_usable()) {
		struct sm3_state *sctx = shash_desc_ctx(desc);

		if (len)
			sm3_update(sctx, data, len);
		sm3_final(sctx, out);
		return 0;
	}

	kernel_rvv_begin();
	if (len)
		sm3_base_do_update(desc, data, len,
				   __sm3_block_data_order);

	sm3_base_do_finalize(desc, __sm3_block_data_order);
	kernel_rvv_end();

	return sm3_base_finish(desc, out);
}

static int riscv64_sm3_final(struct shash_desc *desc, u8 *out)
{
	return riscv64_sm3_finup(desc, NULL, 0, out);
}

static struct shash_alg sm3_alg = {
	.digestsize		= SM3_DIGEST_SIZE,
	.init			= sm3_base_init,
	.update			= riscv64_sm3_update,
	.final			= riscv64_sm3_final,
	.finup			= riscv64_sm3_finup,
	.descsize		= sizeof(struct sm3_state),
	.base.cra_name		= "sm3",
	.base.cra_driver_name	= "sm3-riscv64-zvksh",
	.base.cra_priority	= 150,
	.base.cra_blocksize	= SM3_BLOCK_SIZE,
	.base.cra_module	= THIS_MODULE,
};

static int __init sm3_mod_init(void)
{
	/* sm3 needs at least a vlen of 256 to work correctly */
	if (riscv_isa_extension_available(NULL, ZVKSH) &&
	    riscv_isa_extension_available(NULL, ZVBB) &&
	    riscv_vector_vlen() >= 256)
		return crypto_register_shash(&sm3_alg);

	return 0;
}

static void __exit sm3_mod_fini(void)
{
	if (riscv_isa_extension_available(NULL, ZVKSH) &&
	    riscv_isa_extension_available(NULL, ZVBB) &&
	    riscv_vector_vlen() >= 256)
		crypto_unregister_shash(&sm3_alg);
}

module_init(sm3_mod_init);
module_exit(sm3_mod_fini);

MODULE_DESCRIPTION("SM3 secure hash for riscv64");
MODULE_AUTHOR("Andy Polyakov <appro@openssl.org>");
MODULE_AUTHOR("Ard Biesheuvel <ard.biesheuvel@linaro.org>");
MODULE_LICENSE("GPL");
MODULE_ALIAS_CRYPTO("sm3");
