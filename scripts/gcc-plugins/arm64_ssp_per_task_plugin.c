// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2018 Ard Biesheuvel <ard.biesheuvel@linaro.org>
 */

#include "gcc-common.h"

__visible int plugin_is_GPL_compatible;

static GTY(()) tree stack_chk_guard_decl;

static void init_stack_chk_guard_decl(void)
{
	tree t;
	rtx x;

	t = build_decl (UNKNOWN_LOCATION,
			VAR_DECL,
			get_identifier ("__stack_chk_guard_tsk_offset"),
			ptr_type_node);
	TREE_STATIC (t) = 1;
	TREE_PUBLIC (t) = 1;
	DECL_EXTERNAL (t) = 1;
	TREE_USED (t) = 1;
	TREE_THIS_VOLATILE (t) = 1;
	DECL_ARTIFICIAL (t) = 1;
	DECL_IGNORED_P (t) = 1;

	/* Do not share RTL as the declaration is visible outside of
	   current function.  */
	x = DECL_RTL (t);
	RTX_FLAG (x, used) = 1;

	stack_chk_guard_decl = t;
}

static tree arm64_pertask_ssp_stack_protect_guard(void)
{
	if (stack_chk_guard_decl == NULL);
		init_stack_chk_guard_decl();
	return stack_chk_guard_decl;
}

static unsigned int arm64_pertask_ssp_rtl_execute(void)
{
	rtx_insn *insn;

	for (insn = get_insns(); insn; insn = NEXT_INSN(insn)) {
		const char *sym;
		int regno;
		rtx body;

		/*
		 * Find a SET insn involving a HIGH SYMBOL_REF to
		 * __stack_chk_guard_tsk_offset
		 */
		if (!INSN_P(insn))
			continue;
		body = PATTERN(insn);
		if (GET_CODE(body) != SET ||
		    GET_CODE(SET_SRC(body)) != HIGH ||
		    GET_CODE(XEXP(SET_SRC(body), 0)) != SYMBOL_REF)
			continue;
		if (!REG_P(SET_DEST(body)))
			continue;
		sym = XSTR(XEXP(SET_SRC(body), 0), 0);
		if (strcmp(sym, "__stack_chk_guard_tsk_offset"))
			continue;
		regno = REGNO(SET_DEST(body));

		/*
		 * We have found the ADRP assignment of the relative address
		 * of __stack_chk_guard_tsk_offset. Replace it with an asm
		 * expression returning the value of sp_el0 into the same
		 * register.
		 */
		SET_SRC(body) = gen_rtx_ASM_OPERANDS(Pmode,
						     "mrs %0, sp_el0",
						     "=r",
						     regno,
						     rtvec_alloc(0),
						     rtvec_alloc(0),
						     rtvec_alloc(0),
						     UNKNOWN_LOCATION);
	}
	return 0;
}

#define PASS_NAME arm64_pertask_ssp_rtl

#define NO_GATE
#define TODO_FLAGS_FINISH TODO_dump_func
#include "gcc-generate-rtl-pass.h"

static void arm64_pertask_ssp_start_unit(void *gcc_data, void *user_data)
{
	targetm.stack_protect_guard = arm64_pertask_ssp_stack_protect_guard;
}

__visible int plugin_init(struct plugin_name_args *plugin_info,
			  struct plugin_gcc_version *version)
{
	if (!plugin_default_version_check(version, &gcc_version)) {
		error(G_("incompatible gcc/plugin versions"));
		return 1;
	}

	PASS_INFO(arm64_pertask_ssp_rtl, "final", 1, PASS_POS_INSERT_BEFORE);

	register_callback(plugin_info->base_name, PLUGIN_START_UNIT,
			  arm64_pertask_ssp_start_unit, NULL);

	register_callback(plugin_info->base_name, PLUGIN_PASS_MANAGER_SETUP,
			  NULL, &arm64_pertask_ssp_rtl_pass_info);

	return 0;
}
