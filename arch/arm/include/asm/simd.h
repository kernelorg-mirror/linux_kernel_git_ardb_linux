/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/hardirq.h>

/*
 * may_use_simd - whether it is allowable at this time to issue SIMD
 *                instructions or access the SIMD register file
 */
static __must_check inline bool may_use_simd(void)
{
	return !in_irq() && !irqs_disabled() && !in_nmi();
}
