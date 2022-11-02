// SPDX-License-Identifier: GPL-2.0
/*
 * Early cpufeature override framework
 *
 * Copyright (C) 2020 Google LLC
 * Author: Marc Zyngier <maz@kernel.org>
 */

#include <linux/build_bug.h>
#include <linux/ctype.h>
#include <linux/kernel.h>
#include <linux/libfdt.h>

#include <asm/cacheflush.h>
#include <asm/cpufeature.h>
#include <asm/setup.h>

#include "pi.h"

#define FTR_DESC_NAME_LEN	20	// must remain multiple of 4
#define FTR_DESC_FIELD_LEN	10	// must remain multiple of 4 +/- 2
#define FTR_ALIAS_NAME_LEN	30
#define FTR_ALIAS_OPTION_LEN	116

static u64 __boot_status;

struct ftr_set_desc {
	s32		override_offset; 	// must remain first
	char 		name[FTR_DESC_NAME_LEN];
	struct {
		s32	filter_offset;		// must remain first
		char	name[FTR_DESC_FIELD_LEN];
		u8	shift;
		u8	width;
	} 		fields[];
};

static_assert(offsetof(struct ftr_set_desc, override_offset) == 0);
static_assert(offsetof(struct ftr_set_desc, fields[0].filter_offset) ==
	      4 + FTR_DESC_NAME_LEN);
static_assert(offsetof(struct ftr_set_desc, fields[1].filter_offset) ==
	      4 + FTR_DESC_NAME_LEN + 4 + FTR_DESC_FIELD_LEN + 2);

#define FIELD(n, s)	{ .name = n, .shift = s, .width = 4 }

#define DEFINE_OVERRIDE(__idx, __id, __name, __ovr, ...)		\
	asmlinkage const struct ftr_set_desc __initconst __id = {	\
		.name	= __name,					\
		.fields = { __VA_ARGS__ },				\
	};								\
	asm(".globl " #__ovr "; "					\
	    ".reloc " #__id ", R_AARCH64_PREL32, " #__ovr "; "		\
	    ".reloc regs + (4 * " #__idx "), R_AARCH64_PREL32, " #__id)

#define DEFINE_OVERRIDE_FILTER(__id, __idx, __filter)			      \
	asm(".reloc " #__id " + 4 + " __stringify(FTR_DESC_NAME_LEN)	      \
	    "  + " #__idx " * (4 + " __stringify(FTR_DESC_FIELD_LEN) " + 2)," \
	    "R_AARCH64_PREL32, " #__filter)

asmlinkage bool __init mmfr1_vh_filter(u64 val)
{
	/*
	 * If we ever reach this point while running VHE, we're
	 * guaranteed to be on one of these funky, VHE-stuck CPUs. If
	 * the user was trying to force nVHE on us, proceed with
	 * attitude adjustment.
	 */
	return !(__boot_status == (BOOT_CPU_FLAG_E2H | BOOT_CPU_MODE_EL2) &&
		 val == 0);
}

DEFINE_OVERRIDE(0, mmfr1, "id_aa64mmfr1", id_aa64mmfr1_override,
		FIELD("vh", ID_AA64MMFR1_EL1_VH_SHIFT),
		{});
DEFINE_OVERRIDE_FILTER(mmfr1, 0, mmfr1_vh_filter);

asmlinkage bool __init pfr0_sve_filter(u64 val)
{
	/*
	 * Disabling SVE also means disabling all the features that
	 * are associated with it. The easiest way to do it is just to
	 * override id_aa64zfr0_el1 to be 0.
	 */
	if (!val) {
		id_aa64zfr0_override.val = 0;
		id_aa64zfr0_override.mask = GENMASK(63, 0);
	}

	return true;
}

DEFINE_OVERRIDE(1, pfr0, "id_aa64pfr0", id_aa64pfr0_override,
	        FIELD("sve", ID_AA64PFR0_EL1_SVE_SHIFT),
		{});
DEFINE_OVERRIDE_FILTER(pfr0, 0, pfr0_sve_filter);

asmlinkage bool __init pfr1_sme_filter(u64 val)
{
	/*
	 * Similarly to SVE, disabling SME also means disabling all
	 * the features that are associated with it. Just set
	 * id_aa64smfr0_el1 to 0 and don't look back.
	 */
	if (!val) {
		id_aa64smfr0_override.val = 0;
		id_aa64smfr0_override.mask = GENMASK(63, 0);
	}

	return true;
}

DEFINE_OVERRIDE(2, pfr1, "id_aa64pfr1", id_aa64pfr1_override,
		FIELD("bt", ID_AA64PFR1_EL1_BT_SHIFT ),
		FIELD("mte", ID_AA64PFR1_EL1_MTE_SHIFT),
		FIELD("sme", ID_AA64PFR1_EL1_SME_SHIFT),
		{});
DEFINE_OVERRIDE_FILTER(pfr1, 2, pfr1_sme_filter);

DEFINE_OVERRIDE(3, isar1, "id_aa64isar1", id_aa64isar1_override,
		FIELD("gpi", ID_AA64ISAR1_EL1_GPI_SHIFT),
		FIELD("gpa", ID_AA64ISAR1_EL1_GPA_SHIFT),
		FIELD("api", ID_AA64ISAR1_EL1_API_SHIFT),
		FIELD("apa", ID_AA64ISAR1_EL1_APA_SHIFT),
		{});

DEFINE_OVERRIDE(4, isar2, "id_aa64isar2", id_aa64isar2_override,
		FIELD("gpa3", ID_AA64ISAR2_EL1_GPA3_SHIFT),
		FIELD("apa3", ID_AA64ISAR2_EL1_APA3_SHIFT),
		{});

DEFINE_OVERRIDE(5, smfr0, "id_aa64smfr0", id_aa64smfr0_override,
		/* FA64 is a one bit field... :-/ */
		{ 0, "fa64", ID_AA64SMFR0_EL1_FA64_SHIFT, 1, },
		{});

DEFINE_OVERRIDE(6, sw_features, "arm64_sw", arm64_sw_feature_override,
		FIELD("nokaslr", ARM64_SW_FEATURE_OVERRIDE_NOKASLR),
		FIELD("rodataoff", ARM64_SW_FEATURE_OVERRIDE_RODATA_OFF),
		{});

/*
 * regs[] is populated by R_AARCH64_PREL32 directives invisible to the compiler
 * so it cannot be static or const, or the compiler might try to use constant
 * propagation on the values.
 */
asmlinkage s32 regs[7] __initdata = { [0 ... ARRAY_SIZE(regs) - 1] = S32_MAX };

static struct arm64_ftr_override * __init reg_override(int i)
{
	const struct ftr_set_desc *reg = offset_to_ptr(&regs[i]);

	return offset_to_ptr(&reg->override_offset);
}

static const struct {
	char	alias[FTR_ALIAS_NAME_LEN];
	char	feature[FTR_ALIAS_OPTION_LEN];
} aliases[] __initconst = {
	{ "kvm_arm.mode=nvhe",		"id_aa64mmfr1.vh=0" },
	{ "kvm_arm.mode=protected",	"id_aa64mmfr1.vh=0" },
	{ "arm64.nosve",		"id_aa64pfr0.sve=0 id_aa64pfr1.sme=0" },
	{ "arm64.nosme",		"id_aa64pfr1.sme=0" },
	{ "arm64.nobti",		"id_aa64pfr1.bt=0" },
	{ "arm64.nopauth",
	  "id_aa64isar1.gpi=0 id_aa64isar1.gpa=0 "
	  "id_aa64isar1.api=0 id_aa64isar1.apa=0 "
	  "id_aa64isar2.gpa3=0 id_aa64isar2.apa3=0"	   },
	{ "arm64.nomte",		"id_aa64pfr1.mte=0" },
	{ "nokaslr",			"arm64_sw.nokaslr=1" },
	{ "rodata=off",			"arm64_sw.rodataoff=1" },
};

static int __init find_field(const char *cmdline, char *opt, int len,
			     const struct ftr_set_desc *reg, int f, u64 *v)
{
	int flen = strlen(reg->fields[f].name);
	const char *p;

	// append '<fieldname>=' to obtain '<name>.<fieldname>='
	memcpy(opt + len, reg->fields[f].name, flen);
	len += flen;
	opt[len++] = '=';

	if (memcmp(cmdline, opt, len))
		return -1;

	p = cmdline + len;

	// skip "0x" if it comes next
	if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
		p += 2;

	// check whether the RHS is a single non-whitespace character
	if (*p == '\0' || (p[1] && !isspace(p[1])))
		return -1;

	// only accept a single hex character as the value
	switch (*p) {
	case '0' ... '9':
		*v = *p - '0';
		break;
	case 'a' ... 'f':
		*v = *p - 'a' + 10;
		break;
	case 'A' ... 'F':
		*v = *p - 'A' + 10;
		break;
	default:
		return -1;
	}
	return 0;
}

static const void * __init get_filter(const struct ftr_set_desc *reg, int idx)
{
	const s32 *offset = &reg->fields[idx].filter_offset;

	return *offset ? offset_to_ptr(offset) : NULL;
}

static void __init match_options(const char *cmdline)
{
	char opt[FTR_DESC_NAME_LEN + FTR_DESC_FIELD_LEN + 2];
	int i;

	for (i = 0; i < ARRAY_SIZE(regs); i++) {
		const struct ftr_set_desc *reg = offset_to_ptr(&regs[i]);
		int len = strlen(reg->name);
		int f;

		// set opt[] to '<name>.'
		memcpy(opt, reg->name, len);
		opt[len++] = '.';

		for (f = 0; reg->fields[f].name[0] != '\0'; f++) {
			u64 shift = reg->fields[f].shift;
			u64 width = reg->fields[f].width ?: 4;
			u64 mask = GENMASK_ULL(shift + width - 1, shift);
			bool (*filter)(u64) = get_filter(reg, f);
			u64 v;

			if (find_field(cmdline, opt, len, reg, f, &v))
				continue;

			/*
			 * If an override gets filtered out, advertise
			 * it by setting the value to the all-ones while
			 * clearing the mask... Yes, this is fragile.
			 */
			if (filter && !filter(v)) {
				reg_override(i)->val  |= mask;
				reg_override(i)->mask &= ~mask;
				continue;
			}

			reg_override(i)->val  &= ~mask;
			reg_override(i)->val  |= (v << shift) & mask;
			reg_override(i)->mask |= mask;

			return;
		}
	}
}

static __init void __parse_cmdline(const char *cmdline, bool parse_aliases)
{
	do {
		char buf[256];
		size_t len;
		int i;

		cmdline = skip_spaces(cmdline);

		/* terminate on "--" appearing on the command line by itself */
		if (cmdline[0] == '-' && cmdline[1] == '-' && isspace(cmdline[2]))
			return;

		for (len = 0; cmdline[len] && !isspace(cmdline[len]); len++) {
			if (len >= sizeof(buf) - 1)
				break;
			if (cmdline[len] == '-')
				buf[len] = '_';
			else
				buf[len] = cmdline[len];
		}
		if (!len)
			return;

		buf[len] = 0;

		cmdline += len;

		match_options(buf);

		for (i = 0; parse_aliases && i < ARRAY_SIZE(aliases); i++)
			if (!memcmp(buf, aliases[i].alias, len + 1))
				__parse_cmdline(aliases[i].feature, false);
	} while (1);
}

static __init const u8 *get_bootargs_cmdline(const void *fdt, int node)
{
	static char const bootargs[] __initconst = "bootargs";
	const u8 *prop;

	if (node < 0)
		return NULL;

	prop = fdt_getprop(fdt, node, bootargs, NULL);
	if (!prop)
		return NULL;

	return strlen(prop) ? prop : NULL;
}

static __init void parse_cmdline(const void *fdt, int chosen)
{
	static char const cmdline[] __initconst = CONFIG_CMDLINE;
	const u8 *prop = get_bootargs_cmdline(fdt, chosen);

	if (IS_ENABLED(CONFIG_CMDLINE_FORCE) || !prop)
		__parse_cmdline(cmdline, true);

	if (!IS_ENABLED(CONFIG_CMDLINE_FORCE) && prop)
		__parse_cmdline(prop, true);
}

void __init init_feature_override(u64 boot_status, const void *fdt,
				  int chosen)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(regs); i++) {
		reg_override(i)->val  = 0;
		reg_override(i)->mask = 0;
	}

	__boot_status = boot_status;

	parse_cmdline(fdt, chosen);

	for (i = 0; i < ARRAY_SIZE(regs); i++) {
		dcache_clean_inval_poc((unsigned long)reg_override(i),
				       (unsigned long)reg_override(i) +
				       sizeof(struct arm64_ftr_override));
	}
}

char * __init skip_spaces(const char *str)
{
	while (isspace(*str))
		++str;
	return (char *)str;
}
