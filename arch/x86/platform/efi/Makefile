# SPDX-License-Identifier: GPL-2.0
KASAN_SANITIZE := n
GCOV_PROFILE := n

obj-$(CONFIG_EFI) 		+= memmap.o quirks.o efi.o efi_$(BITS).o
obj-$(CONFIG_X86_32)		+= efi_stub_32.o
obj-$(CONFIG_EFI_MIXED)		+= efi_thunk_$(BITS).o
obj-$(CONFIG_EFI_FAKE_MEMMAP)	+= fake_mem.o
obj-$(CONFIG_EFI_RUNTIME_MAP)	+= runtime-map.o

CFLAGS_efi_64.o			:= $(EFI_STACK_ALIGN)
