/* SPDX-License-Identifier: GPL-2.0-only */

PHDRS
{
	text PT_LOAD FLAGS(7) FILEHDR PHDRS;
}

SECTIONS
{
	. = SIZEOF_HEADERS;

	.text : {
		*(.text .rodata* .kexec-purgatory .data*)
		*(.got* .plt*)
	} :text

	.bss : {
		*(.bss .dynbss)
	} :text

	.rela.dyn : {
		*(.rela.*)
	}

	.symtab 0 : { *(.symtab) }
	.strtab 0 : { *(.strtab) }
	.shstrtab 0 : { *(.shstrtab) }

	/DISCARD/ : {
		*(.interp .modinfo .dynsym .dynstr .hash .gnu.* .dynamic .comment)
		*(.note.* .eh_frame .riscv.attributes)
		*(.alternative __bug_table)
	}
}

ASSERT(SIZEOF(.rela.dyn) == 0, "Absolute relocations detected");
