# SPDX-License-Identifier: GPL-2.0-only
#
# linux/arch/riscv/crypto/Makefile
#

obj-$(CONFIG_CRYPTO_GHASH_RISCV64) += ghash-riscv64.o
ghash-riscv64-y := ghash-riscv64-glue.o
ifdef CONFIG_RISCV_ISA_ZBC
ghash-riscv64-y += ghash-riscv64-zbc.o
endif
ifdef CONFIG_RISCV_ISA_V
ghash-riscv64-y += ghash-riscv64-zvbb-zvbc.o ghash-riscv64-zvkg.o
endif

obj-$(CONFIG_CRYPTO_SHA256_RISCV64) += sha256-riscv64.o
sha256-riscv64-y := sha256-riscv64-glue.o sha256-riscv64-zvbb-zvknha.o

quiet_cmd_perlasm = PERLASM $@
      cmd_perlasm = $(PERL) $(<) void $(@)

$(obj)/ghash-riscv64-zbc.S: $(src)/ghash-riscv64-zbc.pl
	$(call cmd,perlasm)

$(obj)/ghash-riscv64-zvbb-zvbc.S: $(src)/ghash-riscv64-zvbb-zvbc.pl
	$(call cmd,perlasm)

$(obj)/ghash-riscv64-zvkg.S: $(src)/ghash-riscv64-zvkg.pl
	$(call cmd,perlasm)

$(obj)/sha256-riscv64-zvbb-zvknha.S: $(src)/sha256-riscv64-zvbb-zvknha.pl
	$(call cmd,perlasm)

clean-files += ghash-riscv64-zbc.S ghash-riscv64-zvkb.S ghash-riscv64-zvkg.S
clean-files += sha256-riscv64-zvknha.S
