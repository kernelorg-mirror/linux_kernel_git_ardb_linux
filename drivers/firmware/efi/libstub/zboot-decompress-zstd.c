// SPDX-License-Identifier: GPL-2.0

#include <linux/efi.h>
#include <linux/zstd.h>

#include <asm/efi.h>

#include "decompress_sources.h"
#include "efistub.h"

extern unsigned char _gzdata_start[], _gzdata_end[];

static zstd_frame_header header;
static zstd_in_buffer zstd_buf;
static zstd_dstream *dstream;
static size_t zstd_rc;
static size_t wksp_size;
static void *wksp;

/* Decompress the next outlen bytes of the payload into out. */
static bool zstd_decompress_slice(u8 *out, unsigned long outlen)
{
	zstd_out_buffer zstd_dec = { .dst = out, .size = outlen };

	zstd_rc = zstd_decompress_stream(dstream, &zstd_dec, &zstd_buf);
	if (zstd_is_error(zstd_rc)) {
		efi_err("ZSTD-decompression failed with status %d\n",
			zstd_get_error_code(zstd_rc));
		return false;
	}

	/* a truncated stream leaves part of the slice unwritten */
	if (zstd_dec.pos != outlen) {
		efi_err("ZSTD-compressed data is truncated\n");
		return false;
	}

	return true;
}

efi_status_t efi_zboot_decompress_init(unsigned long *alloc_size)
{
	efi_status_t status;
	size_t ret;

	zstd_buf.src = _gzdata_start;
	zstd_buf.pos = 0;
	zstd_buf.size = _gzdata_end - _gzdata_start;

	ret = zstd_get_frame_header(&header, zstd_buf.src, zstd_buf.size);
	if (ret != 0 ||
	    header.frameContentSize == 0 ||
	    header.frameContentSize == ZSTD_CONTENTSIZE_UNKNOWN ||
	    header.frameContentSize != (unsigned long)header.frameContentSize) {
		efi_err("ZSTD-compressed data has an invalid frame header\n");
		return EFI_LOAD_ERROR;
	}

	/* streaming decompression needs a buffer the size of the window */
	if (header.windowSize > (1UL << ZSTD_WINDOWLOG_LIMIT_DEFAULT)) {
		efi_err("ZSTD-compressed data has too large a window size\n");
		return EFI_LOAD_ERROR;
	}

	wksp_size = zstd_dstream_workspace_bound(header.windowSize);
	status = efi_allocate_pages(wksp_size, (unsigned long *)&wksp, ULONG_MAX);
	if (status != EFI_SUCCESS)
		return status;

	dstream = zstd_init_dstream(header.windowSize, wksp, wksp_size);
	if (!dstream) {
		efi_err("failed to initialize ZSTD decompressor\n");
		status = EFI_LOAD_ERROR;
		goto out;
	}

	*alloc_size = header.frameContentSize;
	return EFI_SUCCESS;
out:
	efi_free(wksp_size, (unsigned long)wksp);
	return status;
}

efi_status_t efi_zboot_decompress(u8 *out, unsigned long outlen)
{
	bool ret;

	ret = zstd_decompress_slice(out, outlen);

	/* the payload must take up the entire frame */
	if (ret && zstd_rc != 0) {
		efi_err("ZSTD-compressed data exceeds the recorded size\n");
		ret = false;
	}

	efi_free(wksp_size, (unsigned long)wksp);

	return ret ? EFI_SUCCESS : EFI_LOAD_ERROR;
}
