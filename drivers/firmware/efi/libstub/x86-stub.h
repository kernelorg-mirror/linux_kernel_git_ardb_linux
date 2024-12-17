/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/efi.h>

extern void trampoline_32bit_src(void *, bool);
extern const u16 trampoline_ljmp_imm_offset;

efi_status_t efi_adjust_memory_range_protection(unsigned long start,
						unsigned long size);

void __noreturn efi_stub_entry(efi_handle_t handle,
			       efi_system_table_t *sys_table_arg,
			       struct boot_params *boot_params);

efi_status_t efi_decompress_kernel(unsigned long *kernel_entry,
				   struct boot_params *boot_params);
efi_status_t efi_allocate_kernel(unsigned long alloc_size,
				 unsigned long *virt_addr,
				 unsigned long *alloc,
				 struct boot_params *boot_params);

void efi_get_seed(void *seed, size_t size);

#ifdef CONFIG_X86_64
efi_status_t efi_setup_5level_paging(void);
void efi_5level_switch(void);
#else
static inline efi_status_t efi_setup_5level_paging(void) { return EFI_SUCCESS; }
static inline void efi_5level_switch(void) {}
#endif
