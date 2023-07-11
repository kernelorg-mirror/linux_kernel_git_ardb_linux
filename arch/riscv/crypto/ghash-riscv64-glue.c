// SPDX-License-Identifier: GPL-2.0
/*
 * RISC-V optimized GHASH routines
 *
 * Copyright (C) 2023 VRULL GmbH
 * Author: Heiko Stuebner <heiko.stuebner@vrull.eu>
 */

#include <linux/types.h>
#include <linux/err.h>
#include <linux/crypto.h>
#include <linux/module.h>
#include <asm/simd.h>
#include <asm/vector.h>
#include <crypto/ghash.h>
#include <crypto/internal/hash.h>
#include <crypto/internal/simd.h>

struct riscv64_ghash_ctx {
	void (*ghash_func)(u64 Xi[2], const u128 Htable[16],
			   const u8 *inp, size_t len);

	/* key used by vector asm */
	u128 htable[16];

	/* key used by software fallback */
	be128 key;
};

struct riscv64_ghash_desc_ctx {
	u64 shash[2];
	u8 buffer[GHASH_DIGEST_SIZE];
	int bytes;
};

static int riscv64_ghash_init(struct shash_desc *desc)
{
	struct riscv64_ghash_desc_ctx *dctx = shash_desc_ctx(desc);

	dctx->bytes = 0;
	memset(dctx->shash, 0, GHASH_DIGEST_SIZE);
	return 0;
}

#ifdef CONFIG_RISCV_ISA_V

void gcm_init_rv64i_zvbb_zvbc(u128 Htable[16], const u64 Xi[2]);
void gcm_init_rv64i_zvkg(u128 Htable[16], const u64 Xi[2]);
void gcm_init_rv64i_zvkg_zvbb(u128 Htable[16], const u64 Xi[2]);

void gcm_ghash_rv64i_zvbb_zvbc(u64 Xi[2], const u128 Htable[16],
			       const u8 *inp, size_t len);
void gcm_ghash_rv64i_zvkg(u64 Xi[2], const u128 Htable[16],
			  const u8 *inp, size_t len);

static int riscv64_zvk_ghash_setkey_zvbb_zvbc(struct crypto_shash *tfm,
					      const u8 *key,
					      unsigned int keylen)
{
	struct riscv64_ghash_ctx *ctx = crypto_tfm_ctx(crypto_shash_tfm(tfm));
	const u64 k[2] = { cpu_to_be64(((const u64 *)key)[0]),
			   cpu_to_be64(((const u64 *)key)[1]) };

	if (keylen != GHASH_BLOCK_SIZE)
		return -EINVAL;

	memcpy(&ctx->key, key, GHASH_BLOCK_SIZE);
	kernel_rvv_begin();
	gcm_init_rv64i_zvbb_zvbc(ctx->htable, k);
	kernel_rvv_end();

	ctx->ghash_func = gcm_ghash_rv64i_zvbb_zvbc;

	return 0;
}

static int riscv64_zvk_ghash_setkey_zvkg(struct crypto_shash *tfm,
					   const u8 *key,
					   unsigned int keylen)
{
	struct riscv64_ghash_ctx *ctx = crypto_tfm_ctx(crypto_shash_tfm(tfm));
	const u64 k[2] = { cpu_to_be64(((const u64 *)key)[0]),
			   cpu_to_be64(((const u64 *)key)[1]) };

	if (keylen != GHASH_BLOCK_SIZE)
		return -EINVAL;

	memcpy(&ctx->key, key, GHASH_BLOCK_SIZE);
	kernel_rvv_begin();
	gcm_init_rv64i_zvkg(ctx->htable, k);
	kernel_rvv_end();

	ctx->ghash_func = gcm_ghash_rv64i_zvkg;

	return 0;
}

static int riscv64_zvk_ghash_setkey_zvkg_zvbb(struct crypto_shash *tfm,
					   const u8 *key,
					   unsigned int keylen)
{
	struct riscv64_ghash_ctx *ctx = crypto_tfm_ctx(crypto_shash_tfm(tfm));
	const u64 k[2] = { cpu_to_be64(((const u64 *)key)[0]),
			   cpu_to_be64(((const u64 *)key)[1]) };

	if (keylen != GHASH_BLOCK_SIZE)
		return -EINVAL;

	memcpy(&ctx->key, key, GHASH_BLOCK_SIZE);
	kernel_rvv_begin();
	gcm_init_rv64i_zvkg_zvbb(ctx->htable, k);
	kernel_rvv_end();

	ctx->ghash_func = gcm_ghash_rv64i_zvkg;

	return 0;
}

static inline void __ghash_block(struct riscv64_ghash_ctx *ctx,
				 struct riscv64_ghash_desc_ctx *dctx)
{
	if (crypto_simd_usable()) {
		kernel_rvv_begin();
		ctx->ghash_func(dctx->shash, ctx->htable,
				dctx->buffer, GHASH_DIGEST_SIZE);
		kernel_rvv_end();
	} else {
		crypto_xor((u8 *)dctx->shash, dctx->buffer, GHASH_BLOCK_SIZE);
		gf128mul_lle((be128 *)dctx->shash, &ctx->key);
	}
}

static inline void __ghash_blocks(struct riscv64_ghash_ctx *ctx,
				  struct riscv64_ghash_desc_ctx *dctx,
				  const u8 *src, unsigned int srclen)
{
	if (crypto_simd_usable()) {
		kernel_rvv_begin();
		ctx->ghash_func(dctx->shash, ctx->htable,
				src, srclen);
		kernel_rvv_end();
	} else {
		while (srclen >= GHASH_BLOCK_SIZE) {
			crypto_xor((u8 *)dctx->shash, src, GHASH_BLOCK_SIZE);
			gf128mul_lle((be128 *)dctx->shash, &ctx->key);
			srclen -= GHASH_BLOCK_SIZE;
			src += GHASH_BLOCK_SIZE;
		}
	}
}

static int riscv64_zvk_ghash_update(struct shash_desc *desc,
			   const u8 *src, unsigned int srclen)
{
	unsigned int len;
	struct riscv64_ghash_ctx *ctx = crypto_tfm_ctx(crypto_shash_tfm(desc->tfm));
	struct riscv64_ghash_desc_ctx *dctx = shash_desc_ctx(desc);

	if (dctx->bytes) {
		if (dctx->bytes + srclen < GHASH_DIGEST_SIZE) {
			memcpy(dctx->buffer + dctx->bytes, src,
				srclen);
			dctx->bytes += srclen;
			return 0;
		}
		memcpy(dctx->buffer + dctx->bytes, src,
			GHASH_DIGEST_SIZE - dctx->bytes);

		__ghash_block(ctx, dctx);

		src += GHASH_DIGEST_SIZE - dctx->bytes;
		srclen -= GHASH_DIGEST_SIZE - dctx->bytes;
		dctx->bytes = 0;
	}
	len = srclen & ~(GHASH_DIGEST_SIZE - 1);

	if (len) {
		__ghash_blocks(ctx, dctx, src, len);
		src += len;
		srclen -= len;
	}

	if (srclen) {
		memcpy(dctx->buffer, src, srclen);
		dctx->bytes = srclen;
	}
	return 0;
}

static int riscv64_zvk_ghash_final(struct shash_desc *desc, u8 *out)
{
	struct riscv64_ghash_ctx *ctx = crypto_tfm_ctx(crypto_shash_tfm(desc->tfm));
	struct riscv64_ghash_desc_ctx *dctx = shash_desc_ctx(desc);
	int i;

	if (dctx->bytes) {
		for (i = dctx->bytes; i < GHASH_DIGEST_SIZE; i++)
			dctx->buffer[i] = 0;
		__ghash_block(ctx, dctx);
		dctx->bytes = 0;
	}

	memcpy(out, dctx->shash, GHASH_DIGEST_SIZE);
	return 0;
}

struct shash_alg riscv64_zvbb_zvbc_ghash_alg = {
	.digestsize = GHASH_DIGEST_SIZE,
	.init = riscv64_ghash_init,
	.update = riscv64_zvk_ghash_update,
	.final = riscv64_zvk_ghash_final,
	.setkey = riscv64_zvk_ghash_setkey_zvbb_zvbc,
	.descsize = sizeof(struct riscv64_ghash_desc_ctx)
		    + sizeof(struct ghash_desc_ctx),
	.base = {
		 .cra_name = "ghash",
		 .cra_driver_name = "riscv64_zvbb_zvbc_ghash",
		 .cra_priority = 300,
		 .cra_blocksize = GHASH_BLOCK_SIZE,
		 .cra_ctxsize = sizeof(struct riscv64_ghash_ctx),
		 .cra_module = THIS_MODULE,
	},
};

struct shash_alg riscv64_zvkg_ghash_alg = {
	.digestsize = GHASH_DIGEST_SIZE,
	.init = riscv64_ghash_init,
	.update = riscv64_zvk_ghash_update,
	.final = riscv64_zvk_ghash_final,
	.setkey = riscv64_zvk_ghash_setkey_zvkg,
	.descsize = sizeof(struct riscv64_ghash_desc_ctx)
		    + sizeof(struct ghash_desc_ctx),
	.base = {
		 .cra_name = "ghash",
		 .cra_driver_name = "riscv64_zvkg_ghash",
		 .cra_priority = 301,
		 .cra_blocksize = GHASH_BLOCK_SIZE,
		 .cra_ctxsize = sizeof(struct riscv64_ghash_ctx),
		 .cra_module = THIS_MODULE,
	},
};

struct shash_alg riscv64_zvkg_zvbb_ghash_alg = {
	.digestsize = GHASH_DIGEST_SIZE,
	.init = riscv64_ghash_init,
	.update = riscv64_zvk_ghash_update,
	.final = riscv64_zvk_ghash_final,
	.setkey = riscv64_zvk_ghash_setkey_zvkg_zvbb,
	.descsize = sizeof(struct riscv64_ghash_desc_ctx)
		    + sizeof(struct ghash_desc_ctx),
	.base = {
		 .cra_name = "ghash",
		 .cra_driver_name = "riscv64_zvkg_zvbb_ghash",
		 .cra_priority = 303,
		 .cra_blocksize = GHASH_BLOCK_SIZE,
		 .cra_ctxsize = sizeof(struct riscv64_ghash_ctx),
		 .cra_module = THIS_MODULE,
	},
};

#endif /* CONFIG_RISCV_ISA_V */

#ifdef CONFIG_RISCV_ISA_ZBC

void gcm_init_rv64i_zbc(u128 Htable[16], const u64 Xi[2]);
void gcm_init_rv64i_zbc__zbb(u128 Htable[16], const u64 Xi[2]);
void gcm_init_rv64i_zbc__zbkb(u128 Htable[16], const u64 Xi[2]);

/* Zbc (optional with zbkb improvements) */
void gcm_ghash_rv64i_zbc(u64 Xi[2], const u128 Htable[16],
			 const u8 *inp, size_t len);
void gcm_ghash_rv64i_zbc__zbkb(u64 Xi[2], const u128 Htable[16],
			       const u8 *inp, size_t len);


static int riscv64_zbc_ghash_setkey_zbc(struct crypto_shash *tfm,
					   const u8 *key,
					   unsigned int keylen)
{
	struct riscv64_ghash_ctx *ctx = crypto_tfm_ctx(crypto_shash_tfm(tfm));
	const u64 k[2] = { cpu_to_be64(((const u64 *)key)[0]),
			   cpu_to_be64(((const u64 *)key)[1]) };

	if (keylen != GHASH_BLOCK_SIZE)
		return -EINVAL;

	gcm_init_rv64i_zbc(ctx->htable, k);

	ctx->ghash_func = gcm_ghash_rv64i_zbc;

	return 0;
}

static int riscv64_zbc_ghash_setkey_zbc__zbb(struct crypto_shash *tfm,
					   const u8 *key,
					   unsigned int keylen)
{
	struct riscv64_ghash_ctx *ctx = crypto_tfm_ctx(crypto_shash_tfm(tfm));
	const u64 k[2] = { cpu_to_be64(((const u64 *)key)[0]),
			   cpu_to_be64(((const u64 *)key)[1]) };

	if (keylen != GHASH_BLOCK_SIZE)
		return -EINVAL;

	gcm_init_rv64i_zbc__zbb(ctx->htable, k);

	ctx->ghash_func = gcm_ghash_rv64i_zbc;

	return 0;
}

static int riscv64_zbc_ghash_setkey_zbc__zbkb(struct crypto_shash *tfm,
					   const u8 *key,
					   unsigned int keylen)
{
	struct riscv64_ghash_ctx *ctx = crypto_tfm_ctx(crypto_shash_tfm(tfm));
	const u64 k[2] = { cpu_to_be64(((const u64 *)key)[0]),
			   cpu_to_be64(((const u64 *)key)[1]) };

	if (keylen != GHASH_BLOCK_SIZE)
		return -EINVAL;

	gcm_init_rv64i_zbc__zbkb(ctx->htable, k);

	ctx->ghash_func = gcm_ghash_rv64i_zbc__zbkb;

	return 0;
}

static int riscv64_zbc_ghash_update(struct shash_desc *desc,
			   const u8 *src, unsigned int srclen)
{
	unsigned int len;
	struct riscv64_ghash_ctx *ctx = crypto_tfm_ctx(crypto_shash_tfm(desc->tfm));
	struct riscv64_ghash_desc_ctx *dctx = shash_desc_ctx(desc);

	if (dctx->bytes) {
		if (dctx->bytes + srclen < GHASH_DIGEST_SIZE) {
			memcpy(dctx->buffer + dctx->bytes, src,
				srclen);
			dctx->bytes += srclen;
			return 0;
		}
		memcpy(dctx->buffer + dctx->bytes, src,
			GHASH_DIGEST_SIZE - dctx->bytes);

		ctx->ghash_func(dctx->shash, ctx->htable,
				dctx->buffer, GHASH_DIGEST_SIZE);

		src += GHASH_DIGEST_SIZE - dctx->bytes;
		srclen -= GHASH_DIGEST_SIZE - dctx->bytes;
		dctx->bytes = 0;
	}
	len = srclen & ~(GHASH_DIGEST_SIZE - 1);

	if (len) {
		ctx->ghash_func(dctx->shash, ctx->htable,
				src, len);
		src += len;
		srclen -= len;
	}

	if (srclen) {
		memcpy(dctx->buffer, src, srclen);
		dctx->bytes = srclen;
	}
	return 0;
}

static int riscv64_zbc_ghash_final(struct shash_desc *desc, u8 *out)
{
	int i;
	struct riscv64_ghash_ctx *ctx = crypto_tfm_ctx(crypto_shash_tfm(desc->tfm));
	struct riscv64_ghash_desc_ctx *dctx = shash_desc_ctx(desc);

	if (dctx->bytes) {
		for (i = dctx->bytes; i < GHASH_DIGEST_SIZE; i++)
			dctx->buffer[i] = 0;
		ctx->ghash_func(dctx->shash, ctx->htable,
				dctx->buffer, GHASH_DIGEST_SIZE);
		dctx->bytes = 0;
	}
	memcpy(out, dctx->shash, GHASH_DIGEST_SIZE);
	return 0;
}

struct shash_alg riscv64_zbc_ghash_alg = {
	.digestsize = GHASH_DIGEST_SIZE,
	.init = riscv64_ghash_init,
	.update = riscv64_zbc_ghash_update,
	.final = riscv64_zbc_ghash_final,
	.setkey = riscv64_zbc_ghash_setkey_zbc,
	.descsize = sizeof(struct riscv64_ghash_desc_ctx)
		    + sizeof(struct ghash_desc_ctx),
	.base = {
		 .cra_name = "ghash",
		 .cra_driver_name = "riscv64_zbc_ghash",
		 .cra_priority = 250,
		 .cra_blocksize = GHASH_BLOCK_SIZE,
		 .cra_ctxsize = sizeof(struct riscv64_ghash_ctx),
		 .cra_module = THIS_MODULE,
	},
};

struct shash_alg riscv64_zbc_zbb_ghash_alg = {
	.digestsize = GHASH_DIGEST_SIZE,
	.init = riscv64_ghash_init,
	.update = riscv64_zbc_ghash_update,
	.final = riscv64_zbc_ghash_final,
	.setkey = riscv64_zbc_ghash_setkey_zbc__zbb,
	.descsize = sizeof(struct riscv64_ghash_desc_ctx)
		    + sizeof(struct ghash_desc_ctx),
	.base = {
		 .cra_name = "ghash",
		 .cra_driver_name = "riscv64_zbc_zbb_ghash",
		 .cra_priority = 251,
		 .cra_blocksize = GHASH_BLOCK_SIZE,
		 .cra_ctxsize = sizeof(struct riscv64_ghash_ctx),
		 .cra_module = THIS_MODULE,
	},
};

struct shash_alg riscv64_zbc_zbkb_ghash_alg = {
	.digestsize = GHASH_DIGEST_SIZE,
	.init = riscv64_ghash_init,
	.update = riscv64_zbc_ghash_update,
	.final = riscv64_zbc_ghash_final,
	.setkey = riscv64_zbc_ghash_setkey_zbc__zbkb,
	.descsize = sizeof(struct riscv64_ghash_desc_ctx)
		    + sizeof(struct ghash_desc_ctx),
	.base = {
		 .cra_name = "ghash",
		 .cra_driver_name = "riscv64_zbc_zbkb_ghash",
		 .cra_priority = 252,
		 .cra_blocksize = GHASH_BLOCK_SIZE,
		 .cra_ctxsize = sizeof(struct riscv64_ghash_ctx),
		 .cra_module = THIS_MODULE,
	},
};

#endif /* CONFIG_RISCV_ISA_ZBC */

#define RISCV64_DEFINED_GHASHES		3

static struct shash_alg *riscv64_ghashes[RISCV64_DEFINED_GHASHES];
static int num_riscv64_ghashes;

static int __init riscv64_ghash_register(struct shash_alg *ghash)
{
	int ret;

	ret = crypto_register_shash(ghash);
	if (ret < 0) {
		int i;

		for (i = num_riscv64_ghashes - 1; i >= 0 ; i--)
			crypto_unregister_shash(riscv64_ghashes[i]);

		num_riscv64_ghashes = 0;

		return ret;
	}

	pr_debug("Registered RISC-V ghash %s\n", ghash->base.cra_driver_name);
	riscv64_ghashes[num_riscv64_ghashes] = ghash;
	num_riscv64_ghashes++;
	return 0;
}

static int __init riscv64_ghash_mod_init(void)
{
	int ret = 0;

#ifdef CONFIG_RISCV_ISA_ZBC
	if (riscv_isa_extension_available(NULL, ZBC)) {
		ret = riscv64_ghash_register(&riscv64_zbc_ghash_alg);
		if (ret < 0)
			return ret;

		if (riscv_isa_extension_available(NULL, ZBB)) {
			ret = riscv64_ghash_register(&riscv64_zbc_zbb_ghash_alg);
			if (ret < 0)
				return ret;
		}

		if (riscv_isa_extension_available(NULL, ZBKB)) {
			ret = riscv64_ghash_register(&riscv64_zbc_zbkb_ghash_alg);
			if (ret < 0)
				return ret;
		}
	}
#endif

#ifdef CONFIG_RISCV_ISA_V
	if (riscv_isa_extension_available(NULL, ZVBB) && 
	    riscv_isa_extension_available(NULL, ZVBC) &&
	    riscv_vector_vlen() >= 128) {
		ret = riscv64_ghash_register(&riscv64_zvbb_zvbc_ghash_alg);
		if (ret < 0)
			return ret;
	}

	if (riscv_isa_extension_available(NULL, ZVKG) &&
	    riscv_vector_vlen() >= 128) {
		ret = riscv64_ghash_register(&riscv64_zvkg_ghash_alg);
		if (ret < 0)
			return ret;

		if (riscv_isa_extension_available(NULL, ZVBB)) {
			ret = riscv64_ghash_register(&riscv64_zvkg_zvbb_ghash_alg);
			if (ret < 0)
				return ret;
		}
	}
#endif

	return 0;
}

static void __exit riscv64_ghash_mod_fini(void)
{
	int i;

	for (i = num_riscv64_ghashes - 1; i >= 0 ; i--)
		crypto_unregister_shash(riscv64_ghashes[i]);

	num_riscv64_ghashes = 0;
}

module_init(riscv64_ghash_mod_init);
module_exit(riscv64_ghash_mod_fini);

MODULE_DESCRIPTION("GSM GHASH (accelerated)");
MODULE_AUTHOR("Heiko Stuebner <heiko.stuebner@vrull.eu>");
MODULE_LICENSE("GPL");
MODULE_ALIAS_CRYPTO("ghash");
