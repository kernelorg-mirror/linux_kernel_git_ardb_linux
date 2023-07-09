# SPDX-License-Identifier: GPL-2.0-only
#
# linux/arch/riscv/crypto/Makefile
#

obj-$(CONFIG_CRYPTO_GHASH_RISCV64) += ghash-riscv64.o
ghash-riscv64-y := ghash-riscv64-glue.o
ifdef CONFIG_RISCV_ISA_ZBC
ghash-riscv64-y += ghash-riscv64-zbc.o
endif

quiet_cmd_perlasm = PERLASM $@
      cmd_perlasm = $(PERL) $(<) void $(@)

$(obj)/ghash-riscv64-zbc.S: $(src)/ghash-riscv64-zbc.pl
	$(call cmd,perlasm)

clean-files += ghash-riscv64-zbc.S
