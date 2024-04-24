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
		*(.got .plt .got.plt .plt.got .note.* .eh_frame .sframe)
	}
}

ASSERT(SIZEOF(.rela.dyn) == 0, "Absolute relocations detected");
