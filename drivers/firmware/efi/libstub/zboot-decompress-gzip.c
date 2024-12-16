// SPDX-License-Identifier: GPL-2.0

#include <linux/efi.h>
#include <linux/zlib.h>

#include <asm/efi.h>

#include "efistub.h"

#include "inftrees.c"
#include "inffast.c"
#include "inflate.c"

extern unsigned char _gzdata_start[], _gzdata_end[];
extern u32 __aligned(1) payload_size;

static struct z_stream_s stream;

static bool gzip_decompress_slice(u8 *out, unsigned long outlen)
{
	int rc;

	stream.next_out = out;
	stream.avail_out = outlen;

	rc = zlib_inflate(&stream, 0);

	return rc == Z_OK || rc == Z_STREAM_END;
}

efi_status_t efi_zboot_decompress_init(unsigned long *alloc_size,
				       unsigned long *entry)
{
	efi_status_t status;
	int rc;

	/* skip the 10 byte header, assume no recorded filename */
	stream.next_in = _gzdata_start + 10;
	stream.avail_in = _gzdata_end - stream.next_in;

	status = efi_allocate_pages(zlib_inflate_workspacesize(),
				    (unsigned long *)&stream.workspace,
				    ULONG_MAX);
	if (status != EFI_SUCCESS)
		return status;

	rc = zlib_inflateInit2(&stream, -MAX_WBITS);
	if (rc != Z_OK) {
		efi_err("failed to initialize GZIP decompressor: %d\n", rc);
		status = EFI_LOAD_ERROR;
		goto out;
	}

	if (!IS_ENABLED(CONFIG_EFI_ZBOOT_ELF)) {
		*alloc_size = payload_size;
		*entry = 0;
		return EFI_SUCCESS;
	}

	if (!efi_zboot_check_elf(alloc_size, entry, gzip_decompress_slice)) {
		status = EFI_LOAD_ERROR;
		goto out;
	}

	return EFI_SUCCESS;
out:
	efi_free(zlib_inflate_workspacesize(), (unsigned long)stream.workspace);
	return status;
}

efi_status_t efi_zboot_decompress(u8 *out, unsigned long outlen,
				  unsigned long va_shift)
{
	bool ret;

	if (!IS_ENABLED(CONFIG_EFI_ZBOOT_ELF)) {
		ret = gzip_decompress_slice(out, outlen);
		if (ret)
			efi_cache_sync_image((unsigned long)out, outlen);
	} else {
		ret = efi_zboot_decompress_segments(out, outlen, va_shift,
						    gzip_decompress_slice);
	}

	zlib_inflateEnd(&stream);
	efi_free(zlib_inflate_workspacesize(), (unsigned long)stream.workspace);

	if (!ret) {
		efi_err("GZIP decompression failed\n");
		return EFI_LOAD_ERROR;
	}

	return EFI_SUCCESS;
}
