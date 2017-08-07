/*
 * GCC assumes that we are building shared libraries or hosted binaries
 * when the -fpic or -fpie switches are used. This results in all references
 * to symbols with external linkage to be redirected via entries in the global
 * offset table (GOT), which keeps .text pages clean and reduces the footprint
 * of CoWed dirty pages to the GOT itself. It also allows symbol preemption,
 * which is mandatory under ELF rules for shared libraries.
 *
 * For the kernel, we use PIC so that we can relocate the executable image at
 * runtime. This does not involve CoW or symbol preemption, and we'd rather
 * have relative references instead of absolute ones whenever possible.
 * So set the default visibility to hidden: this informs the compiler that
 * none of our symbols will ever be exported from a shared library, allowing
 * it to use relative references where possible.
 *
 * Note that simply passing -fvisibility=hidden is not sufficient to achieve
 * this: In that case, definitions will be marked hidden, but declarations
 * will not, and we still end up with GOT entries unnecessarily.
 */
#pragma GCC visibility push(hidden)
