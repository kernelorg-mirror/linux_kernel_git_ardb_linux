// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Cryptographic API.
 *
 * Deflate algorithm (RFC 1951), implemented here primarily for use
 * by IPCOMP (RFC 3173 & RFC 2394).
 *
 * Copyright (c) 2003 James Morris <jmorris@intercode.com.au>
 * Copyright (c) 2023 Google, LLC. <ardb@kernel.org>
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/crypto.h>
#include <linux/zlib.h>
#include <linux/net.h>
#include <linux/scatterlist.h>
#include <crypto/scatterwalk.h>
#include <crypto/internal/acompress.h>

#define DEFLATE_DEF_LEVEL		Z_DEFAULT_COMPRESSION
#define DEFLATE_DEF_WINBITS		11
#define DEFLATE_DEF_MEMLEVEL		MAX_MEM_LEVEL

struct deflate_req_ctx {
	struct z_stream_s stream;
	u8 workspace[];
};

static int deflate_process(struct acomp_req *req, struct z_stream_s *stream,
			   int (*process)(struct z_stream_s *, int))
{
	unsigned int slen = req->slen;
	unsigned int dlen = req->dlen;
	struct scatter_walk src, dst;
	unsigned int scur, dcur;
	int ret;

	stream->avail_in = stream->avail_out = 0;

	scatterwalk_start(&src, req->src);
	scatterwalk_start(&dst, req->dst);

	scur = dcur = 0;

	do {
		if (stream->avail_in == 0) {
			if (scur) {
				slen -= scur;

				scatterwalk_unmap(stream->next_in - scur);
				scatterwalk_advance(&src, scur);
				scatterwalk_done(&src, 0, slen);
			}

			scur = scatterwalk_clamp(&src, slen);
			if (scur) {
				stream->next_in = scatterwalk_map(&src);
				stream->avail_in = scur;
			}
		}

		if (stream->avail_out == 0) {
			if (dcur) {
				dlen -= dcur;

				scatterwalk_unmap(stream->next_out - dcur);
				scatterwalk_advance(&dst, dcur);
				scatterwalk_done(&dst, 1, dlen);
			}

			dcur = scatterwalk_clamp(&dst, dlen);
			if (!dcur)
				break;

			stream->next_out = scatterwalk_map(&dst);
			stream->avail_out = dcur;
		}

		ret = process(stream, (slen == scur) ? Z_FINISH : Z_SYNC_FLUSH);
	} while (ret == Z_OK);

	if (scur)
		scatterwalk_unmap(stream->next_in - scur);
	if (dcur)
		scatterwalk_unmap(stream->next_out - dcur);

	if (ret != Z_STREAM_END)
		return -EINVAL;

	req->dlen = stream->total_out;
	return 0;
}

static int deflate_compress(struct acomp_req *req)
{
	struct deflate_req_ctx *ctx = acomp_request_ctx(req);
	struct z_stream_s *stream = &ctx->stream;
	int ret;

        if (!req->src || !req->slen || !req->dst || !req->dlen)
                return -EINVAL;

	stream->workspace = ctx->workspace;
	ret = zlib_deflateInit2(stream, DEFLATE_DEF_LEVEL, Z_DEFLATED,
	                        -DEFLATE_DEF_WINBITS, DEFLATE_DEF_MEMLEVEL,
	                        Z_DEFAULT_STRATEGY);
	if (ret != Z_OK)
		return -EINVAL;

	ret = deflate_process(req, stream, zlib_deflate);
	zlib_deflateEnd(stream);
	return ret;
}

static int deflate_decompress(struct acomp_req *req)
{
	struct deflate_req_ctx *ctx = acomp_request_ctx(req);
	struct z_stream_s *stream = &ctx->stream;
	int ret;

        if (!req->src || !req->slen || !req->dst || !req->dlen)
                return -EINVAL;

	stream->workspace = ctx->workspace;
	ret = zlib_inflateInit2(stream, -DEFLATE_DEF_WINBITS);
	if (ret != Z_OK)
		return -EINVAL;

	ret = deflate_process(req, stream, zlib_inflate);
	req->dlen = stream->total_out;
	zlib_inflateEnd(stream);
	return ret;
}

static struct acomp_alg alg = {
	.compress		= deflate_compress,
	.decompress		= deflate_decompress,

	.base.cra_name		= "deflate",
	.base.cra_driver_name	= "deflate-generic",
	.base.cra_module	= THIS_MODULE,
};

static int __init deflate_mod_init(void)
{
	size_t size = max(zlib_inflate_workspacesize(),
			  zlib_deflate_workspacesize(-DEFLATE_DEF_WINBITS,
						     DEFLATE_DEF_MEMLEVEL));

	alg.reqsize = struct_size_t(struct deflate_req_ctx, workspace, size);
	return crypto_register_acomp(&alg);
}

static void __exit deflate_mod_fini(void)
{
	crypto_unregister_acomp(&alg);
}

subsys_initcall(deflate_mod_init);
module_exit(deflate_mod_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Deflate Compression Algorithm for IPCOMP");
MODULE_AUTHOR("James Morris <jmorris@intercode.com.au>");
MODULE_AUTHOR("Ard Biesheuvel <ardb@kernel.org>");
MODULE_ALIAS_CRYPTO("deflate");
