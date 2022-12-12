// SPDX-License-Identifier: GPL-2.0-only
/*
 * Accelerated GHASH implementation with ARMv8 vmull.p64 instructions.
 *
 * Copyright (C) 2015 - 2018 Linaro Ltd. <ard.biesheuvel@linaro.org>
 */

#include <asm/hwcap.h>
#include <asm/neon.h>
#include <asm/simd.h>
#include <asm/unaligned.h>
#include <crypto/aes.h>
#include <crypto/gcm.h>
#include <crypto/b128ops.h>
#include <crypto/cryptd.h>
#include <crypto/internal/aead.h>
#include <crypto/internal/hash.h>
#include <crypto/internal/simd.h>
#include <crypto/internal/skcipher.h>
#include <crypto/gf128mul.h>
#include <crypto/scatterwalk.h>
#include <linux/cpufeature.h>
#include <linux/crypto.h>
#include <linux/module.h>

MODULE_DESCRIPTION("GHASH hash function using ARMv8 Crypto Extensions");
MODULE_AUTHOR("Ard Biesheuvel <ard.biesheuvel@linaro.org>");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS_CRYPTO("ghash");

#define GHASH_BLOCK_SIZE	16
#define GHASH_DIGEST_SIZE	16
#define GCM_IV_SIZE		12

struct ghash_key {
	u64	h[2];
	u64	h2[2];
	u64	h3[2];
	u64	h4[2];
};

struct gcm_key {
	struct ghash_key gk;
	u32	rk[AES_MAX_KEYLENGTH_U32];
	int	rounds;
};

struct ghash_desc_ctx {
	u64 digest[GHASH_DIGEST_SIZE/sizeof(u64)];
	u8 buf[GHASH_BLOCK_SIZE];
	u32 count;
};

struct ghash_async_ctx {
	struct cryptd_ahash *cryptd_tfm;
};

asmlinkage void pmull_ghash_update_p64(int blocks, u64 dg[], const char *src,
				       struct ghash_key const *k,
				       const char *head);

asmlinkage void pmull_ghash_update_p8(int blocks, u64 dg[], const char *src,
				      struct ghash_key const *k,
				      const char *head);

static void (*pmull_ghash_update)(int blocks, u64 dg[], const char *src,
				  struct ghash_key const *k,
				  const char *head);

static int ghash_init(struct shash_desc *desc)
{
	struct ghash_desc_ctx *ctx = shash_desc_ctx(desc);

	*ctx = (struct ghash_desc_ctx){};
	return 0;
}

static int ghash_update(struct shash_desc *desc, const u8 *src,
			unsigned int len)
{
	struct ghash_desc_ctx *ctx = shash_desc_ctx(desc);
	unsigned int partial = ctx->count % GHASH_BLOCK_SIZE;

	ctx->count += len;

	if ((partial + len) >= GHASH_BLOCK_SIZE) {
		struct ghash_key *key = crypto_shash_ctx(desc->tfm);
		int blocks;

		if (partial) {
			int p = GHASH_BLOCK_SIZE - partial;

			memcpy(ctx->buf + partial, src, p);
			src += p;
			len -= p;
		}

		blocks = len / GHASH_BLOCK_SIZE;
		len %= GHASH_BLOCK_SIZE;

		kernel_neon_begin();
		pmull_ghash_update(blocks, ctx->digest, src, key,
				   partial ? ctx->buf : NULL);
		kernel_neon_end();
		src += blocks * GHASH_BLOCK_SIZE;
		partial = 0;
	}
	if (len)
		memcpy(ctx->buf + partial, src, len);
	return 0;
}

static int ghash_final(struct shash_desc *desc, u8 *dst)
{
	struct ghash_desc_ctx *ctx = shash_desc_ctx(desc);
	unsigned int partial = ctx->count % GHASH_BLOCK_SIZE;

	if (partial) {
		struct ghash_key *key = crypto_shash_ctx(desc->tfm);

		memset(ctx->buf + partial, 0, GHASH_BLOCK_SIZE - partial);
		kernel_neon_begin();
		pmull_ghash_update(1, ctx->digest, ctx->buf, key, NULL);
		kernel_neon_end();
	}
	put_unaligned_be64(ctx->digest[1], dst);
	put_unaligned_be64(ctx->digest[0], dst + 8);

	*ctx = (struct ghash_desc_ctx){};
	return 0;
}

static void ghash_reflect(u64 h[], const be128 *k)
{
	u64 carry = be64_to_cpu(k->a) >> 63;

	h[0] = (be64_to_cpu(k->b) << 1) | carry;
	h[1] = (be64_to_cpu(k->a) << 1) | (be64_to_cpu(k->b) >> 63);

	if (carry)
		h[1] ^= 0xc200000000000000UL;
}

static int ghash_setkey(struct crypto_shash *tfm,
			const u8 *inkey, unsigned int keylen)
{
	struct ghash_key *key = crypto_shash_ctx(tfm);
	be128 h, k;

	if (keylen != GHASH_BLOCK_SIZE) {
		crypto_shash_set_flags(tfm, CRYPTO_TFM_RES_BAD_KEY_LEN);
		return -EINVAL;
	}

	memcpy(&k, inkey, GHASH_BLOCK_SIZE);
	ghash_reflect(key->h, &k);

	h = k;
	gf128mul_lle(&h, &k);
	ghash_reflect(key->h2, &h);

	gf128mul_lle(&h, &k);
	ghash_reflect(key->h3, &h);

	gf128mul_lle(&h, &k);
	ghash_reflect(key->h4, &h);

	return 0;
}

static struct shash_alg ghash_alg = {
	.digestsize		= GHASH_DIGEST_SIZE,
	.init			= ghash_init,
	.update			= ghash_update,
	.final			= ghash_final,
	.setkey			= ghash_setkey,
	.descsize		= sizeof(struct ghash_desc_ctx),
	.base			= {
		.cra_name	= "__ghash",
		.cra_driver_name = "__driver-ghash-ce",
		.cra_priority	= 0,
		.cra_flags	= CRYPTO_ALG_INTERNAL,
		.cra_blocksize	= GHASH_BLOCK_SIZE,
		.cra_ctxsize	= sizeof(struct ghash_key),
		.cra_module	= THIS_MODULE,
	},
};

static int ghash_async_init(struct ahash_request *req)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct ghash_async_ctx *ctx = crypto_ahash_ctx(tfm);
	struct ahash_request *cryptd_req = ahash_request_ctx(req);
	struct cryptd_ahash *cryptd_tfm = ctx->cryptd_tfm;
	struct shash_desc *desc = cryptd_shash_desc(cryptd_req);
	struct crypto_shash *child = cryptd_ahash_child(cryptd_tfm);

	desc->tfm = child;
	return crypto_shash_init(desc);
}

static int ghash_async_update(struct ahash_request *req)
{
	struct ahash_request *cryptd_req = ahash_request_ctx(req);
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct ghash_async_ctx *ctx = crypto_ahash_ctx(tfm);
	struct cryptd_ahash *cryptd_tfm = ctx->cryptd_tfm;

	if (!crypto_simd_usable() ||
	    (in_atomic() && cryptd_ahash_queued(cryptd_tfm))) {
		memcpy(cryptd_req, req, sizeof(*req));
		ahash_request_set_tfm(cryptd_req, &cryptd_tfm->base);
		return crypto_ahash_update(cryptd_req);
	} else {
		struct shash_desc *desc = cryptd_shash_desc(cryptd_req);
		return shash_ahash_update(req, desc);
	}
}

static int ghash_async_final(struct ahash_request *req)
{
	struct ahash_request *cryptd_req = ahash_request_ctx(req);
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct ghash_async_ctx *ctx = crypto_ahash_ctx(tfm);
	struct cryptd_ahash *cryptd_tfm = ctx->cryptd_tfm;

	if (!crypto_simd_usable() ||
	    (in_atomic() && cryptd_ahash_queued(cryptd_tfm))) {
		memcpy(cryptd_req, req, sizeof(*req));
		ahash_request_set_tfm(cryptd_req, &cryptd_tfm->base);
		return crypto_ahash_final(cryptd_req);
	} else {
		struct shash_desc *desc = cryptd_shash_desc(cryptd_req);
		return crypto_shash_final(desc, req->result);
	}
}

static int ghash_async_digest(struct ahash_request *req)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct ghash_async_ctx *ctx = crypto_ahash_ctx(tfm);
	struct ahash_request *cryptd_req = ahash_request_ctx(req);
	struct cryptd_ahash *cryptd_tfm = ctx->cryptd_tfm;

	if (!crypto_simd_usable() ||
	    (in_atomic() && cryptd_ahash_queued(cryptd_tfm))) {
		memcpy(cryptd_req, req, sizeof(*req));
		ahash_request_set_tfm(cryptd_req, &cryptd_tfm->base);
		return crypto_ahash_digest(cryptd_req);
	} else {
		struct shash_desc *desc = cryptd_shash_desc(cryptd_req);
		struct crypto_shash *child = cryptd_ahash_child(cryptd_tfm);

		desc->tfm = child;
		return shash_ahash_digest(req, desc);
	}
}

static int ghash_async_import(struct ahash_request *req, const void *in)
{
	struct ahash_request *cryptd_req = ahash_request_ctx(req);
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct ghash_async_ctx *ctx = crypto_ahash_ctx(tfm);
	struct shash_desc *desc = cryptd_shash_desc(cryptd_req);

	desc->tfm = cryptd_ahash_child(ctx->cryptd_tfm);

	return crypto_shash_import(desc, in);
}

static int ghash_async_export(struct ahash_request *req, void *out)
{
	struct ahash_request *cryptd_req = ahash_request_ctx(req);
	struct shash_desc *desc = cryptd_shash_desc(cryptd_req);

	return crypto_shash_export(desc, out);
}

static int ghash_async_setkey(struct crypto_ahash *tfm, const u8 *key,
			      unsigned int keylen)
{
	struct ghash_async_ctx *ctx = crypto_ahash_ctx(tfm);
	struct crypto_ahash *child = &ctx->cryptd_tfm->base;
	int err;

	crypto_ahash_clear_flags(child, CRYPTO_TFM_REQ_MASK);
	crypto_ahash_set_flags(child, crypto_ahash_get_flags(tfm)
			       & CRYPTO_TFM_REQ_MASK);
	err = crypto_ahash_setkey(child, key, keylen);
	crypto_ahash_set_flags(tfm, crypto_ahash_get_flags(child)
			       & CRYPTO_TFM_RES_MASK);

	return err;
}

static int ghash_async_init_tfm(struct crypto_tfm *tfm)
{
	struct cryptd_ahash *cryptd_tfm;
	struct ghash_async_ctx *ctx = crypto_tfm_ctx(tfm);

	cryptd_tfm = cryptd_alloc_ahash("__driver-ghash-ce",
					CRYPTO_ALG_INTERNAL,
					CRYPTO_ALG_INTERNAL);
	if (IS_ERR(cryptd_tfm))
		return PTR_ERR(cryptd_tfm);
	ctx->cryptd_tfm = cryptd_tfm;
	crypto_ahash_set_reqsize(__crypto_ahash_cast(tfm),
				 sizeof(struct ahash_request) +
				 crypto_ahash_reqsize(&cryptd_tfm->base));

	return 0;
}

static void ghash_async_exit_tfm(struct crypto_tfm *tfm)
{
	struct ghash_async_ctx *ctx = crypto_tfm_ctx(tfm);

	cryptd_free_ahash(ctx->cryptd_tfm);
}

static struct ahash_alg ghash_async_alg = {
	.init			= ghash_async_init,
	.update			= ghash_async_update,
	.final			= ghash_async_final,
	.setkey			= ghash_async_setkey,
	.digest			= ghash_async_digest,
	.import			= ghash_async_import,
	.export			= ghash_async_export,
	.halg.digestsize	= GHASH_DIGEST_SIZE,
	.halg.statesize		= sizeof(struct ghash_desc_ctx),
	.halg.base		= {
		.cra_name	= "ghash",
		.cra_driver_name = "ghash-ce",
		.cra_priority	= 300,
		.cra_flags	= CRYPTO_ALG_ASYNC,
		.cra_blocksize	= GHASH_BLOCK_SIZE,
		.cra_ctxsize	= sizeof(struct ghash_async_ctx),
		.cra_module	= THIS_MODULE,
		.cra_init	= ghash_async_init_tfm,
		.cra_exit	= ghash_async_exit_tfm,
	},
};


void pmull_gcm_encrypt(int blocks, u64 dg[], const char *src,
		       struct gcm_key const *k, char *dst,
		       char *iv, int rounds, u32 counter);

void pmull_gcm_enc_final(int blocks, u64 dg[], char *tag,
			 struct gcm_key const *k, char *head,
			 char *iv, int rounds, u32 counter);

void pmull_gcm_decrypt(int bytes, u64 dg[], const char *src,
		       struct gcm_key const *k, char *dst,
		       char *iv, int rounds, u32 counter);

int pmull_gcm_dec_final(int bytes, u64 dg[], char *tag,
			struct gcm_key const *k, char *head,
			char *iv, int rounds, u32 counter,
			const char *otag, int authsize);

static int gcm_setkey(struct crypto_aead *tfm, const u8 *inkey,
		      unsigned int keylen)
{
	struct gcm_key *ctx = crypto_aead_ctx(tfm);
	struct crypto_aes_ctx aes_ctx;
	be128 h, k;
	int ret;

	ret = aes_expandkey(&aes_ctx, inkey, keylen);
	if (ret)
		return -EINVAL;

	aes_encrypt(&aes_ctx, (u8 *)&k, (u8[AES_BLOCK_SIZE]){});

	memcpy(ctx->rk, aes_ctx.key_enc, sizeof(ctx->rk));
	ctx->rounds = 6 + keylen / 4;

	memzero_explicit(&aes_ctx, sizeof(aes_ctx));

	ghash_reflect(ctx->gk.h, &k);

	h = k;
	gf128mul_lle(&h, &k);
	ghash_reflect(ctx->gk.h2, &h);

	gf128mul_lle(&h, &k);
	ghash_reflect(ctx->gk.h3, &h);

	gf128mul_lle(&h, &k);
	ghash_reflect(ctx->gk.h4, &h);

	return 0;
}

static int gcm_setauthsize(struct crypto_aead *tfm, unsigned int authsize)
{
	switch (authsize) {
	case 4:
	case 8:
	case 12 ... 16:
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static void gcm_update_mac(u64 dg[], const u8 *src, int count, u8 buf[],
			   int *buf_count, struct gcm_key *ctx)
{
	if (*buf_count > 0) {
		int buf_added = min(count, GHASH_BLOCK_SIZE - *buf_count);

		memcpy(&buf[*buf_count], src, buf_added);

		*buf_count += buf_added;
		src += buf_added;
		count -= buf_added;
	}

	if (count >= GHASH_BLOCK_SIZE || *buf_count == GHASH_BLOCK_SIZE) {
		int blocks = count / GHASH_BLOCK_SIZE;

		pmull_ghash_update_p64(blocks, dg, src, &ctx->gk,
				       *buf_count ? buf : NULL);

		src += blocks * GHASH_BLOCK_SIZE;
		count %= GHASH_BLOCK_SIZE;
		*buf_count = 0;
	}

	if (count > 0) {
		memcpy(buf, src, count);
		*buf_count = count;
	}
}

static void gcm_calculate_auth_mac(struct aead_request *req, u64 dg[])
{
	struct crypto_aead *aead = crypto_aead_reqtfm(req);
	struct gcm_key *ctx = crypto_aead_ctx(aead);
	u8 buf[GHASH_BLOCK_SIZE];
	struct scatter_walk walk;
	u32 len = req->assoclen;
	int buf_count = 0;

	scatterwalk_start(&walk, req->src);

	do {
		u32 n = scatterwalk_clamp(&walk, len);
		u8 *p;

		if (!n) {
			scatterwalk_start(&walk, sg_next(walk.sg));
			n = scatterwalk_clamp(&walk, len);
		}
		p = scatterwalk_map(&walk);

		gcm_update_mac(dg, p, n, buf, &buf_count, ctx);

		scatterwalk_unmap(p);

		if (unlikely(len / SZ_4K > (len - n) / SZ_4K)) {
                        kernel_neon_end();
                        kernel_neon_begin();
                }

		len -= n;
		scatterwalk_advance(&walk, n);
		scatterwalk_done(&walk, 0, len);
	} while (len);

	if (buf_count) {
		memset(&buf[buf_count], 0, GHASH_BLOCK_SIZE - buf_count);
		pmull_ghash_update_p64(1, dg, buf, &ctx->gk, NULL);
	}
}

static int gcm_encrypt(struct aead_request *req)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(req);
	struct gcm_key *ctx = crypto_aead_ctx(aead);
	struct skcipher_walk walk;
	u8 buf[AES_BLOCK_SIZE];
	u32 counter = 2;
	u64 dg[2] = {};
	be128 lengths;
	const u8 *src;
	u8 *tag, *dst;
	int tail, err;

	if (WARN_ON_ONCE(!may_use_simd()))
		return -EBUSY;

	err = skcipher_walk_aead_encrypt(&walk, req, false);

	kernel_neon_begin();

	if (req->assoclen)
		gcm_calculate_auth_mac(req, dg);

	src = walk.src.virt.addr;
	dst = walk.dst.virt.addr;

	while (walk.nbytes >= AES_BLOCK_SIZE) {
		int nblocks = walk.nbytes / AES_BLOCK_SIZE;

		pmull_gcm_encrypt(nblocks, dg, src, ctx, dst, req->iv,
				  ctx->rounds, counter);
		counter += nblocks;

		if (walk.nbytes == walk.total && walk.nbytes % AES_BLOCK_SIZE) {
			src += nblocks * AES_BLOCK_SIZE;
			dst += nblocks * AES_BLOCK_SIZE;
			break;
		}

		kernel_neon_end();

		err = skcipher_walk_done(&walk,
					 walk.nbytes % AES_BLOCK_SIZE);
		if (err)
			return err;

		src = walk.src.virt.addr;
		dst = walk.dst.virt.addr;

		kernel_neon_begin();
	}


	lengths.a = cpu_to_be64(req->assoclen * 8);
	lengths.b = cpu_to_be64(req->cryptlen * 8);

	tag = (u8 *)&lengths;
	tail = walk.nbytes % AES_BLOCK_SIZE;

	/*
	 * Bounce via a buffer unless we are encrypting in place and src/dst
	 * are not pointing to the start of the walk buffer. In that case, we
	 * can do a NEON load/xor/store sequence in place as long as we move
	 * the plain/ciphertext and keystream to the start of the register. If
	 * not, do a memcpy() to the end of the buffer so we can reuse the same
	 * logic.
	 */
	if (unlikely(tail && (tail == walk.nbytes || src != dst)))
		src = memcpy(buf + sizeof(buf) - tail, src, tail);

	pmull_gcm_enc_final(tail, dg, tag, ctx, (u8 *)src, req->iv,
			    ctx->rounds, counter);
	kernel_neon_end();

	if (unlikely(tail && src != dst))
		memcpy(dst, src, tail);

	if (walk.nbytes) {
		err = skcipher_walk_done(&walk, 0);
		if (err)
			return err;
	}

	/* copy authtag to end of dst */
	scatterwalk_map_and_copy(tag, req->dst, req->assoclen + req->cryptlen,
				 crypto_aead_authsize(aead), 1);

	return 0;
}

static int gcm_decrypt(struct aead_request *req)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(req);
	struct gcm_key *ctx = crypto_aead_ctx(aead);
	int authsize = crypto_aead_authsize(aead);
	struct skcipher_walk walk;
	u8 otag[AES_BLOCK_SIZE];
	u8 buf[AES_BLOCK_SIZE];
	u32 counter = 2;
	u64 dg[2] = {};
	be128 lengths;
	const u8 *src;
	u8 *tag, *dst;
	int tail, err, ret;

	if (WARN_ON_ONCE(!may_use_simd()))
		return -EBUSY;

	scatterwalk_map_and_copy(otag, req->src,
				 req->assoclen + req->cryptlen - authsize,
				 authsize, 0);

	err = skcipher_walk_aead_decrypt(&walk, req, false);

	kernel_neon_begin();

	if (req->assoclen)
		gcm_calculate_auth_mac(req, dg);

	src = walk.src.virt.addr;
	dst = walk.dst.virt.addr;

	while (walk.nbytes >= AES_BLOCK_SIZE) {
		int nblocks = walk.nbytes / AES_BLOCK_SIZE;

		pmull_gcm_decrypt(nblocks, dg, src, ctx, dst, req->iv,
				  ctx->rounds, counter);
		counter += nblocks;

		if (walk.nbytes == walk.total && walk.nbytes % AES_BLOCK_SIZE) {
			src += nblocks * AES_BLOCK_SIZE;
			dst += nblocks * AES_BLOCK_SIZE;
			break;
		}

		kernel_neon_end();

		err = skcipher_walk_done(&walk,
					 walk.nbytes % AES_BLOCK_SIZE);
		if (err)
			return err;

		src = walk.src.virt.addr;
		dst = walk.dst.virt.addr;

		kernel_neon_begin();
	}

	lengths.a = cpu_to_be64(req->assoclen * 8);
	lengths.b = cpu_to_be64((req->cryptlen - authsize) * 8);

	tag = (u8 *)&lengths;
	tail = walk.nbytes % AES_BLOCK_SIZE;

	if (unlikely(tail && (tail == walk.nbytes || src != dst)))
		src = memcpy(buf + sizeof(buf) - tail, src, tail);

	ret = pmull_gcm_dec_final(tail, dg, tag, ctx, (u8 *)src, req->iv,
				  ctx->rounds, counter, otag, authsize);
	kernel_neon_end();

	if (unlikely(tail && src != dst))
		memcpy(dst, src, tail);

	if (walk.nbytes) {
		err = skcipher_walk_done(&walk, 0);
		if (err)
			return err;
	}

	return ret ? -EBADMSG : 0;
}

static struct aead_alg gcm_aes_alg = {
	.ivsize			= GCM_IV_SIZE,
	.chunksize		= AES_BLOCK_SIZE,
	.maxauthsize		= AES_BLOCK_SIZE,
	.setkey			= gcm_setkey,
	.setauthsize		= gcm_setauthsize,
	.encrypt		= gcm_encrypt,
	.decrypt		= gcm_decrypt,

	.base.cra_name		= "gcm(aes)",
	.base.cra_driver_name	= "gcm-aes-ce",
	.base.cra_priority	= 400,
	.base.cra_blocksize	= 1,
	.base.cra_ctxsize	= sizeof(struct gcm_key),
	.base.cra_module	= THIS_MODULE,
};

static int __init ghash_ce_mod_init(void)
{
	int err;

	if (!(elf_hwcap & HWCAP_NEON))
		return -ENODEV;

	if (elf_hwcap2 & HWCAP2_PMULL) {
		err = crypto_register_aead(&gcm_aes_alg);
		if (err)
			return err;
		pmull_ghash_update = pmull_ghash_update_p64;
	} else {
		pmull_ghash_update = pmull_ghash_update_p8;
	}

	err = crypto_register_shash(&ghash_alg);
	if (err)
		goto err_aead;
	err = crypto_register_ahash(&ghash_async_alg);
	if (err)
		goto err_shash;

	return 0;
err_shash:
	crypto_unregister_shash(&ghash_alg);
err_aead:
	if (elf_hwcap2 & HWCAP2_PMULL)
		crypto_unregister_aead(&gcm_aes_alg);
	return err;
}

static void __exit ghash_ce_mod_exit(void)
{
	crypto_unregister_ahash(&ghash_async_alg);
	crypto_unregister_shash(&ghash_alg);
	if (elf_hwcap2 & HWCAP2_PMULL)
		crypto_unregister_aead(&gcm_aes_alg);
}

module_init(ghash_ce_mod_init);
module_exit(ghash_ce_mod_exit);
