// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Synchronous Compression operations
 *
 * Copyright 2015 LG Electronics Inc.
 * Copyright (c) 2016, Intel Corporation
 * Author: Giovanni Cabiddu <giovanni.cabiddu@intel.com>
 */

#include <crypto/internal/acompress.h>
#include <crypto/internal/scompress.h>
#include <crypto/scatterwalk.h>
#include <linux/cryptouser.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <net/netlink.h>

#include "compress.h"

static const struct crypto_type crypto_scomp_type;

static int __maybe_unused crypto_scomp_report(
	struct sk_buff *skb, struct crypto_alg *alg)
{
	struct crypto_report_comp rscomp;

	memset(&rscomp, 0, sizeof(rscomp));

	strscpy(rscomp.type, "scomp", sizeof(rscomp.type));

	return nla_put(skb, CRYPTOCFGA_REPORT_COMPRESS,
		       sizeof(rscomp), &rscomp);
}

static void crypto_scomp_show(struct seq_file *m, struct crypto_alg *alg)
	__maybe_unused;

static void crypto_scomp_show(struct seq_file *m, struct crypto_alg *alg)
{
	seq_puts(m, "type         : scomp\n");
}

static int crypto_scomp_init_tfm(struct crypto_tfm *tfm)
{
	return 0;
}

/**
 * scomp_map_sg - Return virtual address of memory described by a scatterlist
 *
 * @sg:		The address of the scatterlist in memory
 * @len:	The length of the buffer described by the scatterlist
 *
 * If the memory region described by scatterlist @sg consists of @len
 * contiguous bytes in memory and is accessible via the linear mapping or via a
 * single kmap(), return its virtual address.  Otherwise, return NULL.
 */
static void *scomp_map_sg(struct scatterlist *sg, unsigned int len)
{
	struct page *page;
	unsigned int offset;

	while (sg_is_chain(sg))
		sg = sg_next(sg);

	if (!sg || sg_nents_for_len(sg, len) != 1)
		return NULL;

	page   = sg_page(sg) + (sg->offset >> PAGE_SHIFT);
	offset = offset_in_page(sg->offset);

	if (PageHighMem(page) && (offset + sg->length) > PAGE_SIZE)
		return NULL;

	return kmap_local_page(page) + offset;
}

static void scomp_unmap_sg(const void *addr)
{
	if (is_kmap_addr(addr))
		kunmap_local(addr);
}

static int scomp_acomp_comp_decomp(struct acomp_req *req, int dir)
{
	struct crypto_acomp *tfm = crypto_acomp_reqtfm(req);
	void **tfm_ctx = acomp_tfm_ctx(tfm);
	struct crypto_scomp *scomp = *tfm_ctx;
	void **ctx = acomp_request_ctx(req);
	void *src_alloc = NULL;
	void *dst_alloc = NULL;
	const u8 *src;
	u8 *dst;
	int ret;

	if (!req->src || !req->slen || !req->dst || !req->dlen)
		return -EINVAL;

	dst = scomp_map_sg(req->dst, req->dlen);
	if (!dst) {
		dst = dst_alloc = kvmalloc(req->dlen, GFP_KERNEL);
		if (!dst_alloc)
			return -ENOMEM;
	}

	src = scomp_map_sg(req->src, req->slen);
	if (!src) {
		src = src_alloc = kvmalloc(req->slen, GFP_KERNEL);
		if (!src_alloc) {
			ret = -ENOMEM;
			goto out;
		}
		scatterwalk_map_and_copy(src_alloc, req->src, 0, req->slen, 0);
	}

	if (dir)
		ret = crypto_scomp_compress(scomp, src, req->slen, dst,
					    &req->dlen, *ctx);
	else
		ret = crypto_scomp_decompress(scomp, src, req->slen, dst,
					      &req->dlen, *ctx);

	if (src_alloc)
		kvfree(src_alloc);
	else
		scomp_unmap_sg(src);

	if (!ret && dst == dst_alloc)
		scatterwalk_map_and_copy(dst, req->dst, 0, req->dlen, 1);
out:
	if (dst_alloc)
		kvfree(dst_alloc);
	else
		scomp_unmap_sg(dst);

	return ret;
}

static int scomp_acomp_compress(struct acomp_req *req)
{
	return scomp_acomp_comp_decomp(req, 1);
}

static int scomp_acomp_decompress(struct acomp_req *req)
{
	return scomp_acomp_comp_decomp(req, 0);
}

static void crypto_exit_scomp_ops_async(struct crypto_tfm *tfm)
{
	struct crypto_scomp **ctx = crypto_tfm_ctx(tfm);

	crypto_free_scomp(*ctx);
}

int crypto_init_scomp_ops_async(struct crypto_tfm *tfm)
{
	struct crypto_alg *calg = tfm->__crt_alg;
	struct crypto_acomp *crt = __crypto_acomp_tfm(tfm);
	struct crypto_scomp **ctx = crypto_tfm_ctx(tfm);
	struct crypto_scomp *scomp;

	if (!crypto_mod_get(calg))
		return -EAGAIN;

	scomp = crypto_create_tfm(calg, &crypto_scomp_type);
	if (IS_ERR(scomp)) {
		crypto_mod_put(calg);
		return PTR_ERR(scomp);
	}

	*ctx = scomp;
	tfm->exit = crypto_exit_scomp_ops_async;

	crt->compress = scomp_acomp_compress;
	crt->decompress = scomp_acomp_decompress;
	crt->reqsize = sizeof(void *);

	return 0;
}

struct acomp_req *crypto_acomp_scomp_alloc_ctx(struct acomp_req *req)
{
	struct crypto_acomp *acomp = crypto_acomp_reqtfm(req);
	struct crypto_tfm *tfm = crypto_acomp_tfm(acomp);
	struct crypto_scomp **tfm_ctx = crypto_tfm_ctx(tfm);
	struct crypto_scomp *scomp = *tfm_ctx;
	void *ctx;

	ctx = crypto_scomp_alloc_ctx(scomp);
	if (IS_ERR(ctx)) {
		kfree(req);
		return NULL;
	}

	*req->__ctx = ctx;

	return req;
}

void crypto_acomp_scomp_free_ctx(struct acomp_req *req)
{
	struct crypto_acomp *acomp = crypto_acomp_reqtfm(req);
	struct crypto_tfm *tfm = crypto_acomp_tfm(acomp);
	struct crypto_scomp **tfm_ctx = crypto_tfm_ctx(tfm);
	struct crypto_scomp *scomp = *tfm_ctx;
	void *ctx = *req->__ctx;

	if (ctx)
		crypto_scomp_free_ctx(scomp, ctx);
}

static const struct crypto_type crypto_scomp_type = {
	.extsize = crypto_alg_extsize,
	.init_tfm = crypto_scomp_init_tfm,
#ifdef CONFIG_PROC_FS
	.show = crypto_scomp_show,
#endif
#if IS_ENABLED(CONFIG_CRYPTO_USER)
	.report = crypto_scomp_report,
#endif
#ifdef CONFIG_CRYPTO_STATS
	.report_stat = crypto_acomp_report_stat,
#endif
	.maskclear = ~CRYPTO_ALG_TYPE_MASK,
	.maskset = CRYPTO_ALG_TYPE_MASK,
	.type = CRYPTO_ALG_TYPE_SCOMPRESS,
	.tfmsize = offsetof(struct crypto_scomp, base),
};

int crypto_register_scomp(struct scomp_alg *alg)
{
	struct crypto_alg *base = &alg->calg.base;

	comp_prepare_alg(&alg->calg);

	base->cra_type = &crypto_scomp_type;
	base->cra_flags |= CRYPTO_ALG_TYPE_SCOMPRESS;

	return crypto_register_alg(base);
}
EXPORT_SYMBOL_GPL(crypto_register_scomp);

void crypto_unregister_scomp(struct scomp_alg *alg)
{
	crypto_unregister_alg(&alg->base);
}
EXPORT_SYMBOL_GPL(crypto_unregister_scomp);

int crypto_register_scomps(struct scomp_alg *algs, int count)
{
	int i, ret;

	for (i = 0; i < count; i++) {
		ret = crypto_register_scomp(&algs[i]);
		if (ret)
			goto err;
	}

	return 0;

err:
	for (--i; i >= 0; --i)
		crypto_unregister_scomp(&algs[i]);

	return ret;
}
EXPORT_SYMBOL_GPL(crypto_register_scomps);

void crypto_unregister_scomps(struct scomp_alg *algs, int count)
{
	int i;

	for (i = count - 1; i >= 0; --i)
		crypto_unregister_scomp(&algs[i]);
}
EXPORT_SYMBOL_GPL(crypto_unregister_scomps);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Synchronous compression type");
