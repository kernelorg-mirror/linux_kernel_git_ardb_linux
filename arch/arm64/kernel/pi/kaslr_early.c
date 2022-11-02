// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2022 Google LLC
// Author: Ard Biesheuvel <ardb@google.com>

// NOTE: code in this file runs *very* early, and is not permitted to use
// global variables or anything that relies on absolute addressing.

#include <linux/libfdt.h>
#include <linux/init.h>
#include <linux/linkage.h>
#include <linux/types.h>
#include <linux/sizes.h>
#include <linux/string.h>

#include <asm/archrandom.h>
#include <asm/memory.h>

static u64 __init get_kaslr_seed(void *fdt)
{
	static char const chosen_str[] __initconst = "chosen";
	static char const seed_str[] __initconst = "kaslr-seed";
	int node, len;
	fdt64_t *prop;
	u64 ret;

	node = fdt_path_offset(fdt, chosen_str);
	if (node < 0)
		return 0;

	prop = fdt_getprop_w(fdt, node, seed_str, &len);
	if (!prop || len != sizeof(u64))
		return 0;

	ret = fdt64_to_cpu(*prop);
	*prop = 0;
	return ret;
}

asmlinkage u64 __init kaslr_early_init(void *fdt)
{
	u64 seed;

	if (cpuid_feature_extract_unsigned_field(arm64_sw_feature_override.val,
						 ARM64_SW_FEATURE_OVERRIDE_NOKASLR))
		return 0;

	seed = get_kaslr_seed(fdt);
	if (!seed) {
		if (!__early_cpu_has_rndr() ||
		    !__arm64_rndr((unsigned long *)&seed))
			return 0;
	}

	/*
	 * OK, so we are proceeding with KASLR enabled. Calculate a suitable
	 * kernel image offset from the seed. Let's place the kernel in the
	 * middle half of the VMALLOC area (VA_BITS_MIN - 2), and stay clear of
	 * the lower and upper quarters to avoid colliding with other
	 * allocations.
	 */
	return BIT(VA_BITS_MIN - 3) + (seed & GENMASK(VA_BITS_MIN - 3, 0));
}
