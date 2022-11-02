// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2022 Google LLC
// Author: Ard Biesheuvel <ardb@google.com>

#include <linux/types.h>

extern bool dynamic_scs_is_enabled;

void init_feature_override(u64 boot_status, const void *fdt, int chosen);
u64 kaslr_early_init(void *fdt, int chosen);
void relocate_kernel(u64 offset);
int scs_patch(const u8 eh_frame[], int size);
