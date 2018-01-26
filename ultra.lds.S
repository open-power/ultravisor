// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2014-2019 IBM Corp.  */

#include <config.h>
#include <mem-map.h>

ENTRY(boot_entry)
SECTIONS
{
	. = 0x0;

	.head : {
		KEEP(*(.head))
	}

	. = ALIGN(0x10);
	_stext = .;
	.text : {
		*(.text*)
		*(.sfpr)
	}
	_etext = .;

	.rodata : {
		__rodata_start = .;
		*(.rodata .rodata.*)
		__rodata_end = .;
	}

	.data : {
		/*
		 * A couple of things that need to be 4K aligned and
		 * to reside in their own pages for the sake of TCE
		 * mappings
		 */
		. = ALIGN(0x1000);
		*(.data*)
		*(.force.data)
	}

	. = ALIGN(0x10);
	.init : {
		__ctors_start = .;
		KEEP(*(.ctors))
		KEEP(*(.init_array))
		__ctors_end = .;
	}
	. = ALIGN(0x100);
	.got : {
		__toc_start = . + 0x8000;
		*(.got)
		*(.toc)
	}

	. = ALIGN(0x10);
        .dynamic : {
                __dynamic_start = .;
                *(.dynamic)
                __dynamic_end = .;
        }

        . = ALIGN(0x10);
        .rela.dyn : {
                __rela_dyn_start = .;
                *(.rela*)
                __rela_dyn_end = .;
        }

        . = ALIGN(0x10);
	.svm_ops : {
		__svm_ops_start = .;
		KEEP(*(.svm_ops))
		__svm_ops_end = .;
        }

        .hash   : { *(.hash)   }
        .dynsym : { *(.dynsym) }
        .dynstr : { *(.dynstr) }

        . = ALIGN(0x10);
        .sym_map : {
        	__sym_map_start = . ;
        	KEEP(*(.sym_map))
        	__sym_map_end = . ;
        }

        /* We locate the BSS plus 1M to leave room for the symbol map */

        . = . + 0x100000;
        
	_sbss = .;
	.bss : {
		*(.bss*)
	}

	. = ALIGN(0x10000);
	_ebss = .;
	_end = .;

	/* Discards */
	/DISCARD/ : {
		*(.comment)
		*(.interp)
	}
}
