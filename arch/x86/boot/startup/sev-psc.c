// SPDX-License-Identifier: GPL-2.0

#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/limits.h>
#include <asm/pgtable_types.h>
#include <asm/sev.h>
#include <asm/msr-index.h>

bool sev_snp_needs_sfw;

static inline u64 sev_es_rd_ghcb_msr(void)
{
	struct msr m;

	raw_rdmsr(MSR_AMD64_SEV_ES_GHCB, &m);

	return m.q;
}

static inline void sev_es_wr_ghcb_msr(u64 val)
{
	struct msr m;

	m.q = val;
	raw_wrmsr(MSR_AMD64_SEV_ES_GHCB, &m);
}

#include "sev-shared-psc.c"
