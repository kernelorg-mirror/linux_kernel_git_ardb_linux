// SPDX-License-Identifier: GPL-2.0-only
/*
 * This file is part of UBIFS.
 *
 * Copyright (C) 2006-2008 Nokia Corporation.
 * Copyright (C) 2006, 2007 University of Szeged, Hungary
 *
 * Authors: Adrian Hunter
 *          Artem Bityutskiy (Битюцкий Артём)
 *          Zoltan Sogor
 */

/*
 * This file provides a single place to access to compression and
 * decompression.
 */

#include <linux/crypto.h>
#include "ubifs.h"

/* Fake description object for the "none" compressor */
static struct ubifs_compressor none_compr = {
	.compr_type = UBIFS_COMPR_NONE,
	.name = "none",
	.capi_name = "",
};

#ifdef CONFIG_UBIFS_FS_LZO
static DEFINE_MUTEX(lzo_mutex);

static struct ubifs_compressor lzo_compr = {
	.compr_type = UBIFS_COMPR_LZO,
	.comp_mutex = &lzo_mutex,
	.name = "lzo",
	.capi_name = "lzo",
};
#else
static struct ubifs_compressor lzo_compr = {
	.compr_type = UBIFS_COMPR_LZO,
	.name = "lzo",
};
#endif

#ifdef CONFIG_UBIFS_FS_ZLIB
static DEFINE_MUTEX(deflate_mutex);
static DEFINE_MUTEX(inflate_mutex);

static struct ubifs_compressor zlib_compr = {
	.compr_type = UBIFS_COMPR_ZLIB,
	.comp_mutex = &deflate_mutex,
	.decomp_mutex = &inflate_mutex,
	.name = "zlib",
	.capi_name = "deflate",
};
#else
static struct ubifs_compressor zlib_compr = {
	.compr_type = UBIFS_COMPR_ZLIB,
	.name = "zlib",
};
#endif

#ifdef CONFIG_UBIFS_FS_ZSTD
static DEFINE_MUTEX(zstd_enc_mutex);
static DEFINE_MUTEX(zstd_dec_mutex);

static struct ubifs_compressor zstd_compr = {
	.compr_type = UBIFS_COMPR_ZSTD,
	.comp_mutex = &zstd_enc_mutex,
	.decomp_mutex = &zstd_dec_mutex,
	.name = "zstd",
	.capi_name = "zstd",
};
#else
static struct ubifs_compressor zstd_compr = {
	.compr_type = UBIFS_COMPR_ZSTD,
	.name = "zstd",
};
#endif

/* All UBIFS compressors */
struct ubifs_compressor *ubifs_compressors[UBIFS_COMPR_TYPES_CNT];

/**
 * ubifs_compress - compress data.
 * @in_sg: data to compress
 * @in_len: length of the data to compress
 * @out_buf: output buffer where compressed data should be stored
 * @out_len: output buffer length is returned here
 * @compr_type: type of compression to use on enter, actually used compression
 *              type on exit
 *
 * This function compresses input scatterlist @in_sg of length @in_len and
 * stores the result in the output buffer @out_buf and the resulting length in
 * @out_len. If the input buffer does not compress, it is just copied to the
 * @out_buf. The same happens if @compr_type is %UBIFS_COMPR_NONE or if
 * compression error occurred.
 *
 * Note, if the input buffer was not compressed, it is copied to the output
 * buffer and %UBIFS_COMPR_NONE is returned in @compr_type.
 */
void ubifs_compress(const struct ubifs_info *c, struct scatterlist *in_sg,
		    int in_len, void *out_buf, int *out_len, int *compr_type)
{
	int err;
	struct ubifs_compressor *compr = ubifs_compressors[*compr_type];
	struct scatterlist out_sg;

	if (*compr_type == UBIFS_COMPR_NONE)
		goto no_compr;

	/* If the input data is small, do not even try to compress it */
	if (in_len < UBIFS_MIN_COMPR_LEN)
		goto no_compr;

	sg_init_one(&out_sg, out_buf, *out_len);

	if (compr->comp_mutex)
		mutex_lock(compr->comp_mutex);
	acomp_request_set_params(compr->req, in_sg, &out_sg, in_len, *out_len);
	err = crypto_acomp_compress(compr->req);
	*out_len = compr->req->dlen;
	if (compr->comp_mutex)
		mutex_unlock(compr->comp_mutex);
	if (unlikely(err)) {
		ubifs_warn(c, "cannot compress %d bytes, compressor %s, error %d, leave data uncompressed",
			   in_len, compr->name, err);
		goto no_compr;
	}

	/*
	 * If the data compressed only slightly, it is better to leave it
	 * uncompressed to improve read speed.
	 */
	if (in_len - *out_len < UBIFS_MIN_COMPRESS_DIFF)
		goto no_compr;

	return;

no_compr:
	sg_copy_to_buffer(in_sg, 1, out_buf, in_len);
	*out_len = in_len;
	*compr_type = UBIFS_COMPR_NONE;
}

/**
 * ubifs_decompress - decompress data.
 * @in_buf: data to decompress
 * @in_len: length of the data to decompress
 * @out_sg: output buffer where decompressed data should be stored
 * @out_len: output length is returned here
 * @compr_type: type of compression
 *
 * This function decompresses data from buffer @in_buf into scatterlist @out_sg.
 * The length of the uncompressed data is returned in @out_len. This functions
 * returns %0 on success or a negative error code on failure.
 */
int ubifs_decompress(const struct ubifs_info *c, const void *in_buf, int in_len,
		     struct scatterlist *out_sg, int *out_len, int compr_type)
{
	int err;
	struct ubifs_compressor *compr;
	struct scatterlist in_sg;

	if (unlikely(compr_type < 0 || compr_type >= UBIFS_COMPR_TYPES_CNT)) {
		ubifs_err(c, "invalid compression type %d", compr_type);
		return -EINVAL;
	}

	compr = ubifs_compressors[compr_type];

	if (unlikely(!compr->capi_name)) {
		ubifs_err(c, "%s compression is not compiled in", compr->name);
		return -EINVAL;
	}

	if (compr_type == UBIFS_COMPR_NONE) {
		sg_copy_from_buffer(out_sg, 1, in_buf, in_len);
		*out_len = in_len;
		return 0;
	}

	sg_init_one(&in_sg, in_buf, in_len);

	if (compr->decomp_mutex)
		mutex_lock(compr->decomp_mutex);
	acomp_request_set_params(compr->req, &in_sg, out_sg, in_len, *out_len);
	err = crypto_acomp_decompress(compr->req);
	*out_len = compr->req->dlen;
	if (compr->decomp_mutex)
		mutex_unlock(compr->decomp_mutex);
	if (err)
		ubifs_err(c, "cannot decompress %d bytes, compressor %s, error %d",
			  in_len, compr->name, err);

	return err;
}

/**
 * compr_init - initialize a compressor.
 * @compr: compressor description object
 *
 * This function initializes the requested compressor and returns zero in case
 * of success or a negative error code in case of failure.
 */
static int __init compr_init(struct ubifs_compressor *compr)
{
	if (compr->capi_name) {
		long ret;

		compr->cc = crypto_alloc_acomp(compr->capi_name, 0,
					       CRYPTO_ALG_ASYNC);
		if (IS_ERR(compr->cc)) {
			ret = PTR_ERR(compr->cc);
		} else {
			compr->req = acomp_request_alloc(compr->cc);
			if (!compr->req) {
				crypto_free_acomp(compr->cc);
				ret = -ENOMEM;
			}
		}

		if (ret) {
			pr_err("UBIFS error (pid %d): cannot initialize compressor %s, error %ld",
			       current->pid, compr->name, ret);
			return ret;
		}
	}

	ubifs_compressors[compr->compr_type] = compr;
	return 0;
}

/**
 * compr_exit - de-initialize a compressor.
 * @compr: compressor description object
 */
static void compr_exit(struct ubifs_compressor *compr)
{
	if (compr->capi_name) {
		acomp_request_free(compr->req);
		crypto_free_acomp(compr->cc);
	}
}

/**
 * ubifs_compressors_init - initialize UBIFS compressors.
 *
 * This function initializes the compressor which were compiled in. Returns
 * zero in case of success and a negative error code in case of failure.
 */
int __init ubifs_compressors_init(void)
{
	int err;

	err = compr_init(&lzo_compr);
	if (err)
		return err;

	err = compr_init(&zstd_compr);
	if (err)
		goto out_lzo;

	err = compr_init(&zlib_compr);
	if (err)
		goto out_zstd;

	ubifs_compressors[UBIFS_COMPR_NONE] = &none_compr;
	return 0;

out_zstd:
	compr_exit(&zstd_compr);
out_lzo:
	compr_exit(&lzo_compr);
	return err;
}

/**
 * ubifs_compressors_exit - de-initialize UBIFS compressors.
 */
void ubifs_compressors_exit(void)
{
	compr_exit(&lzo_compr);
	compr_exit(&zlib_compr);
	compr_exit(&zstd_compr);
}
