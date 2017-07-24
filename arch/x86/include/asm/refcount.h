#ifndef __ASM_X86_REFCOUNT_H
#define __ASM_X86_REFCOUNT_H
/*
 * x86-specific implementation of refcount_t. Based on PAX_REFCOUNT from
 * PaX/grsecurity.
 */
#include <linux/refcount.h>

/*
 * This is the first portion of the refcount error handling, which lives in
 * .text.unlikely, and is jumped to from the CPU flag check (in the
 * following macros). This saves the refcount value location into CX for
 * the exception handler to use (in mm/extable.c), and then triggers the
 * central refcount exception. The fixup address for the exception points
 * back to the regular execution flow in .text.
 */
#define _REFCOUNT_EXCEPTION				\
	".pushsection .text.unlikely\n"			\
	"111:\tlea %[counter], %%" _ASM_CX "\n"		\
	"112:\t" ASM_UD0 "\n"				\
	ASM_UNREACHABLE					\
	".popsection\n"					\
	"113:\n"					\
	_ASM_EXTABLE_REFCOUNT(112b, 113b)

/* Trigger refcount exception if refcount result is negative. */
#define REFCOUNT_CHECK_LT_ZERO				\
	"js 111f\n\t"					\
	_REFCOUNT_EXCEPTION

/* Trigger refcount exception if refcount result is zero or negative. */
#define REFCOUNT_CHECK_LE_ZERO				\
	"jz 111f\n\t"					\
	REFCOUNT_CHECK_LT_ZERO

static __always_inline void refcount_add(unsigned int i, refcount_t *r)
{
	asm volatile(LOCK_PREFIX "addl %1,%0\n\t"
		REFCOUNT_CHECK_LT_ZERO
		: [counter] "+m" (r->refs.counter)
		: "ir" (i)
		: "cc", "cx");
}

static __always_inline void refcount_inc(refcount_t *r)
{
	asm volatile(LOCK_PREFIX "incl %0\n\t"
		REFCOUNT_CHECK_LT_ZERO
		: [counter] "+m" (r->refs.counter)
		: : "cc", "cx");
}

static __always_inline void refcount_dec(refcount_t *r)
{
	asm volatile(LOCK_PREFIX "decl %0\n\t"
		REFCOUNT_CHECK_LE_ZERO
		: [counter] "+m" (r->refs.counter)
		: : "cc", "cx");
}

static __always_inline __must_check
bool refcount_sub_and_test(unsigned int i, refcount_t *r)
{
	GEN_BINARY_SUFFIXED_RMWcc(LOCK_PREFIX "subl", REFCOUNT_CHECK_LT_ZERO,
				  r->refs.counter, "er", i, "%0", e);
}

static __always_inline __must_check bool refcount_dec_and_test(refcount_t *r)
{
	GEN_UNARY_SUFFIXED_RMWcc(LOCK_PREFIX "decl", REFCOUNT_CHECK_LT_ZERO,
				 r->refs.counter, "%0", e);
}

/**
 * __refcount_add_unless - add unless the number is already a given value
 * @r: pointer of type refcount_t
 * @a: the amount to add to v...
 * @u: ...unless v is equal to u.
 *
 * Atomically adds @a to @r, so long as @r was not already @u.
 * Returns the old value of @r.
 */
static __always_inline __must_check
int __refcount_add_unless(refcount_t *r, int a, int u)
{
	int c, new;

	c = atomic_read(&(r->refs));
	do {
		if (unlikely(c == u))
			break;

		asm volatile("addl %2,%0\n\t"
			REFCOUNT_CHECK_LT_ZERO
			: "=r" (new)
			: "0" (c), "ir" (a),
			  [counter] "m" (r->refs.counter)
			: "cc", "cx");

	} while (!atomic_try_cmpxchg(&(r->refs), &c, new));

	return c;
}

static __always_inline __must_check
bool refcount_add_not_zero(unsigned int i, refcount_t *r)
{
	return __refcount_add_unless(r, i, 0) != 0;
}

static __always_inline __must_check bool refcount_inc_not_zero(refcount_t *r)
{
	return refcount_add_not_zero(1, r);
}

#endif
