ENTRY(_start)

/**
 * This is a GNU linker script designed for production of an ELF-format executable, complete
 * with exception tables/headers, suitable for conversion to PE format and execution in a
 * UEFI environment.
 *
 * See also the companion script, link-efi-efi.lds.
 */

PHDRS {
    text     PT_LOAD   FLAGS(0x1 | 0x4);  /* executable, readable */
    rodata   PT_LOAD   FLAGS(0x4);
    data     PT_LOAD   FLAGS(0x4 | 0x2);  /* readable, writable */
    dynamic PT_DYNAMIC  FLAGS(0x4 | 0x2); /* ?? flags needed? */
}

SECTIONS {

    /* We'll start .text at the 4kb mark and align later sections on a 4kb
     * boundary. This doesn't seem to be strictly necessary. */
    
    . = 0;
    __image_base = ABSOLUTE(.); /* ??? need ABSOLUTE? */ 
    .text 0x0 : {
        *(.pe_header)

        . = ALIGN(0x1000);
        __text_start = ABSOLUTE(.);
        *(.text .text.*)
    } :text

    . = ALIGN(0x1000);
    __text_end = ABSOLUTE(.); /* ??? move up? */
    __text_size = ABSOLUTE(__text_end - __text_start);

    .rodata : {
        *(.dummy_reloc)

        . = ALIGN(0x1000);

        __data_start = ABSOLUTE(.);
        *(.rodata .rodata.*)
        *(.gcc_except_table .gcc_except_table.*)
    } :rodata

    . = ALIGN(8);

    /* Note, eh_frame and eh_frame_hdr would naturally fit well in .rodata. However, binutils
     * .eh_frame_hdr generation seemingly works only if the section .eh_frame exists in the
     * output.  */

    .eh_frame : {
        PROVIDE (__eh_frame_start = .);
        KEEP(*(.eh_frame .eh_frame.*))
        PROVIDE (__eh_frame_end = .);
        LONG (0);
    }

    .eh_frame_hdr : {
        PROVIDE (__eh_frame_hdr_start = .);
        KEEP(*(.eh_frame_hdr .eh_frame_hdr.*))
        PROVIDE (__eh_frame_hdr_end = .);
    }
    
    . = ALIGN(0x1000);

    .data : {
        *(.data .data.*)
    } :data

    .bss . : {
        *(.bss .bss.*)
    } :data

    .dynamic : {
        *(.dynamic)
        . = ALIGN(0x1000);  /* must have this inside section to pad out file */
    } :data :dynamic

    __data_end = ABSOLUTE(.);
    __data_size = __data_end - __data_start;

    /* Debug sections: */

/*
    .debug_aranges 0 :  { *(.debug_aranges)  }
    .debug_str 0 :      { *(.debug_str)      }
    .debug_loc 0 :      { *(.debug_loc)      }
    .debug_abbrev 0 :   { *(.debug_abbrev)   }
    .debug_info 0 :     { *(.debug_info)     }
    .debug_ranges 0 :   { *(.debug_ranges)   }
    .debug_macinfo 0 :  { *(.debug_macinfo)  }
    .debug_pubnames 0 : { *(.debug_pubnames) }
    .debug_pubtypes 0 : { *(.debug_pubtypes) }
    .debug_frame 0 :    { *(.debug_frame)    }
    .debug_line 0 :     { *(.debug_line)     }
*/

    __image_end = ABSOLUTE(.);
    __image_size = ABSOLUTE(__image_end - __image_base);

    /* sections to discard */

    /DISCARD/ : {
        
        /* discard some stuff that's not needed or problematic */
        *(.comment)
        *(.note.gnu.property)
        *(.note.GNU-stack)
        *(.dynamic)
    }
}
