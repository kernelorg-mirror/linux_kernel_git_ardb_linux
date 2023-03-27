#
# arch/arm64/boot/Makefile
#
# This file is included by the global makefile so that you can add your own
# architecture-specific flags and dependencies.
#
# This file is subject to the terms and conditions of the GNU General Public
# License.  See the file "COPYING" in the main directory of this archive
# for more details.
#
# Copyright (C) 2012, ARM Ltd.
# Author: Will Deacon <will.deacon@arm.com>
#
# Based on the ia64 boot/Makefile.
#

OBJCOPYFLAGS_Image :=-O binary -R .note -R .note.gnu.build-id -R .comment -S

targets := Image Image.bz2 Image.gz Image.lz4 Image.lzma Image.lzo Image.zst

$(obj)/Image: vmlinux FORCE
	$(call if_changed,objcopy)

$(obj)/Image.bz2: $(obj)/Image FORCE
	$(call if_changed,bzip2)

$(obj)/Image.gz: $(obj)/Image FORCE
	$(call if_changed,gzip)

$(obj)/Image.lz4: $(obj)/Image FORCE
	$(call if_changed,lz4)

$(obj)/Image.lzma: $(obj)/Image FORCE
	$(call if_changed,lzma)

$(obj)/Image.lzo: $(obj)/Image FORCE
	$(call if_changed,lzo)

$(obj)/Image.zst: $(obj)/Image FORCE
	$(call if_changed,zstd)

EFI_ZBOOT_PAYLOAD	:= Image.zboot
EFI_ZBOOT_BFD_TARGET	:= elf64-littleaarch64
EFI_ZBOOT_MACH_TYPE	:= ARM64
EFI_ZBOOT_FORWARD_CFI	:= $(CONFIG_ARM64_BTI_KERNEL)

#
# The EFI zboot logic needs to know the size of the executable region in the
# image, so let's poke that into the text_offset field of the image header of
# the zboot payload, as that field is no longer used and can thus be repurposed
# for other, purely internal uses.
#
quiet_cmd_copy_and_poke = $(quiet_cmd_objcopy)
      cmd_copy_and_poke = $(cmd_objcopy) && /bin/echo -ne "$(POKE_DATA)" | dd bs=1 \
				status=none conv=notrunc seek=$(POKE_OFFSET) of=$@

# grab the code size and convert it into something we can echo
$(obj)/$(EFI_ZBOOT_PAYLOAD): POKE_DATA = $(shell $(NM) $<|grep _kernel_codesize|\
				sed -E 's/0+(..)(..)(..)(..) .+/\\x\4\\x\3\\x\2\\x\1/')
$(obj)/$(EFI_ZBOOT_PAYLOAD): POKE_OFFSET := 8
$(obj)/$(EFI_ZBOOT_PAYLOAD): vmlinux FORCE
	$(call if_changed,copy_and_poke)

OBJCOPYFLAGS_$(EFI_ZBOOT_PAYLOAD) := $(OBJCOPYFLAGS_Image)

targets += $(EFI_ZBOOT_PAYLOAD)

include $(srctree)/drivers/firmware/efi/libstub/Makefile.zboot
