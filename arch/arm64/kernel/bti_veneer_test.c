
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>

static int noinline static_noninit_function(void)
{
	static volatile int ret;
	return ret;
}

static int __init bti_veneer_test_init(void)
{
	return static_noninit_function();
}
module_init(bti_veneer_test_init);

static void bti_veneer_test_exit(void)
{
}
module_exit(bti_veneer_test_exit);

/* Make the init code region too big to fit in 128M 'near' module region */
asm(".section .init.padding, \"ax\", %progbits; .space (128 << 20) - 64; .previous");

MODULE_LICENSE("GPL");
