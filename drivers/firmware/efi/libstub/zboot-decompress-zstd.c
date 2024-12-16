// SPDX-License-Identifier: GPL-2.0

#include <linux/efi.h>
#include <linux/zstd.h>

#include <asm/efi.h>

#include "decompress_sources.h"
#include "efistub.h"

extern unsigned char _gzdata_start[], _gzdata_end[];
extern u32 __aligned(1) payload_size;

static zstd_frame_header header;
static ZSTD_inBuffer zstd_buf;
static ZSTD_DStream *dstream;
static size_t wksp_size;
static void *wksp;

static bool zstd_decompress_slice(u8 *out, unsigned long outlen)
{
	ZSTD_outBuffer zstd_dec;
	size_t ret;

	zstd_dec.dst = out;
	zstd_dec.pos = 0;
	zstd_dec.size = outlen;

	ret = zstd_decompress_stream(dstream, &zstd_dec, &zstd_buf);

	return zstd_get_error_code(ret) == 0;
}

static efi_status_t zstd_get_workspace_size(size_t *size)
{
	size_t ret;

	if (!IS_ENABLED(CONFIG_EFI_ZBOOT_ELF)) {
		*size = zstd_dctx_workspace_bound();
		return EFI_SUCCESS;
	}

	zstd_buf.src = _gzdata_start;
	zstd_buf.pos = 0;
	zstd_buf.size = _gzdata_end - _gzdata_start - 4;

	ret = zstd_get_frame_header(&header, zstd_buf.src, zstd_buf.size);
	if (ret != 0) {
		efi_err("ZSTD-compressed data has an incomplete frame header\n");
		return EFI_LOAD_ERROR;
	}

	if (header.windowSize > (1 << ZSTD_WINDOWLOG_MAX)) {
		efi_err("ZSTD-compressed data has too large a window size\n");
		return EFI_LOAD_ERROR;
	}

	*size = zstd_dstream_workspace_bound(header.windowSize);
	return EFI_SUCCESS;
}

efi_status_t efi_zboot_decompress_init(unsigned long *alloc_size,
				       unsigned long *entry)
{
	efi_status_t status;

	status = zstd_get_workspace_size(&wksp_size) ?:
		 efi_allocate_pages(wksp_size, (unsigned long *)&wksp, ULONG_MAX);
	if (status != EFI_SUCCESS)
		return status;

	if (!IS_ENABLED(CONFIG_EFI_ZBOOT_ELF)) {
		*alloc_size = payload_size;
		*entry = 0;
		return EFI_SUCCESS;
	}

	dstream = zstd_init_dstream(header.windowSize, wksp, wksp_size);

	if (!efi_zboot_check_elf(alloc_size, entry, zstd_decompress_slice)) {
		efi_free(wksp_size, (unsigned long)wksp);
		return EFI_LOAD_ERROR;
	}

	return EFI_SUCCESS;
}

efi_status_t efi_zboot_decompress(u8 *out, unsigned long outlen,
				  unsigned long va_shift)
{
	bool ret;

	if (!IS_ENABLED(CONFIG_EFI_ZBOOT_ELF)) {
		zstd_dctx *dctx = zstd_init_dctx(wksp, wksp_size);
		int err = zstd_decompress_dctx(dctx, out, outlen, _gzdata_start,
					       _gzdata_end - _gzdata_start - 4);

		ret = !zstd_get_error_code(err);
		if (ret)
			efi_cache_sync_image((unsigned long)out, outlen);
	} else {
		ret = efi_zboot_decompress_segments(out, outlen, va_shift,
						    zstd_decompress_slice);
	}

	efi_free(wksp_size, (unsigned long)wksp);

	if (!ret) {
		efi_err("ZSTD-decompression failed\n");
		return EFI_LOAD_ERROR;
	}

	return EFI_SUCCESS;
}
