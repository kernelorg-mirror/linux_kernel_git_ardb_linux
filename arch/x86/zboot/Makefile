# SPDX-License-Identifier: GPL-2.0

EFI_ZBOOT_BFD_TARGET	:= elf64-x86-64
EFI_ZBOOT_MACH_TYPE	:= AMD64
EFI_ZBOOT_FORWARD_CFI	:= $(CONFIG_X86_KERNEL_IBT)
EFI_ZBOOT_LIBS		:= $(objtree)/arch/x86/boot/startup/lib.a

include $(srctree)/drivers/firmware/efi/libstub/Makefile.zboot
