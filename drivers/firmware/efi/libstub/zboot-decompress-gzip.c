// SPDX-License-Identifier: GPL-2.0

#include <linux/efi.h>
#include <linux/unaligned.h>
#include <linux/zlib.h>

#include <asm/efi.h>

#include "efistub.h"

#include "inftrees.c"
#include "inffast.c"
#include "inflate.c"

extern unsigned char _gzdata_start[], _gzdata_end[];

static struct z_stream_s stream;
static int inflate_rc;

/* Decompress the next outlen bytes of the payload into out. */
static bool gzip_decompress_slice(u8 *out, unsigned long outlen)
{
	stream.next_out = out;
	stream.avail_out = outlen;

	inflate_rc = zlib_inflate(&stream, 0);
	if (inflate_rc != Z_OK && inflate_rc != Z_STREAM_END) {
		efi_err("GZIP decompression failed with status %d\n", inflate_rc);
		return false;
	}

	/* a truncated stream leaves part of the slice unwritten */
	if (stream.avail_out) {
		efi_err("GZIP-compressed data is truncated\n");
		return false;
	}

	return true;
}

efi_status_t efi_zboot_decompress_init(unsigned long *alloc_size)
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
		/* the last 4 bytes of a GZIP stream carry the uncompressed size */
		*alloc_size = get_unaligned_le32(_gzdata_end - 4);
		return EFI_SUCCESS;
	}

	if (!efi_zboot_check_elf(alloc_size, gzip_decompress_slice)) {
		status = EFI_LOAD_ERROR;
		goto out;
	}

	return EFI_SUCCESS;
out:
	efi_free(zlib_inflate_workspacesize(), (unsigned long)stream.workspace);
	return status;
}

efi_status_t efi_zboot_decompress(u8 *out, unsigned long outlen)
{
	bool ret;

	if (!IS_ENABLED(CONFIG_EFI_ZBOOT_ELF))
		ret = gzip_decompress_slice(out, outlen);
	else
		ret = efi_zboot_decompress_segments(out, outlen,
						    get_unaligned_le32(_gzdata_end - 4),
						    gzip_decompress_slice);

	/* the payload must take up the entire stream */
	if (ret && inflate_rc != Z_STREAM_END) {
		efi_err("GZIP-compressed data exceeds the recorded size\n");
		ret = false;
	}

	zlib_inflateEnd(&stream);

	efi_free(zlib_inflate_workspacesize(), (unsigned long)stream.workspace);

	return ret ? EFI_SUCCESS : EFI_LOAD_ERROR;
}
