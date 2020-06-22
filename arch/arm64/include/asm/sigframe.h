/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012-2020 ARM Ltd.
 */
#ifndef __ASM_SIGFRAME_H
#define __ASM_SIGFRAME_H

#include <linux/types.h>

#include <asm/siginfo.h>
#include <asm/ucontext.h>

/*
 * Do a signal return; undo the signal stack. These are aligned to 128-bit.
 */
struct rt_sigframe {
	struct siginfo info;
	struct ucontext uc;
};

#endif /* __ASM_SIGFRAME_H */
