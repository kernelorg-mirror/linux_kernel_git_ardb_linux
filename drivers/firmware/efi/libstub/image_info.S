/* SPDX-License-Identifier: GPL-2.0 */

#define REL_REF(sym)	.long	sym - 0b

	.globl		__efistub_efistub_image_info
	.p2align	3
__efistub_efistub_image_info:
0:	REL_REF(_text)
	REL_REF(__inittext_end)
	REL_REF(_edata)
	REL_REF(_end)
	REL_REF(efi_primary_entry)
