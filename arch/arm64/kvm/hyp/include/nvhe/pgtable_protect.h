// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021 Google LLC
 * Author: Ard Biesheuvel <ardb@google.com>
 */

#ifndef __KVM_NVHE_PGTABLE_PROTECT__
#define __KVM_NVHE_PGTABLE_PROTECT__

#include <linux/kvm_host.h>

void handle___pkvm_xchg_ro_pte(struct kvm_cpu_context *host_ctxt);
void handle___pkvm_cmpxchg_ro_pte(struct kvm_cpu_context *host_ctxt);

void handle___pkvm_assign_pgroot(struct kvm_cpu_context *host_ctxt);
void handle___pkvm_release_pgroot(struct kvm_cpu_context *host_ctxt);

#endif
