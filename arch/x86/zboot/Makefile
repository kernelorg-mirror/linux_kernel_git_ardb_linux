# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2023 Google LLC. <ardb@google.com>
#

$(obj)/Image: OBJCOPYFLAGS := -O binary -S \
			      -R .note -R .note.gnu.build-id -R .comment
$(obj)/Image: vmlinux FORCE
	$(call if_changed,objcopy)

CMD_RELOCS := arch/x86/tools/relocs

quiet_cmd_relocs = RELOCS  $@
      cmd_relocs = $(CMD_RELOCS) $< > $@

$(obj)/vmlinux.relocs: vmlinux FORCE
	$(call if_changed,relocs)

efi-zboot-relocs-$(CONFIG_X86_NEED_RELOCS)	:= $(obj)/vmlinux.relocs
EFI_ZBOOT_PAYLOAD_TRAILER			:= $(efi-zboot-relocs-y)

EFI_ZBOOT_PAYLOAD				:= Image
EFI_ZBOOT_BFD_TARGET				:= elf64-x86-64
EFI_ZBOOT_MACH_TYPE				:= AMD64
EFI_ZBOOT_FORWARD_CFI				:= $(CONFIG_X86_KERNEL_IBT)

targets := Image vmlinux.relocs

include $(srctree)/drivers/firmware/efi/libstub/Makefile.zboot
