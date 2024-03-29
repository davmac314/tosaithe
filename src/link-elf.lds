ENTRY(EfiMain)

/**
 * This is a GNU linker script designed for production of an ELF-format executable, complete
 * with exception tables/headers, suitable for conversion to PE format and execution in a
 * UEFI environment.
 *
 * See also the companion script, link-efi-efi.lds.
 */

SECTIONS {

    /* We'll start .text at the 4kb mark and align later sections on a 4kb
     * boundary. This doesn't seem to be strictly necessary. */

    .text 0x1000 : {
        *(.text .text.*)
    }

    . = ALIGN(0x1000);

    .rodata : {
        *(.rodata .rodata.*)

        *(.gcc_except_table .gcc_except_table.*)
    }

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
    }

    .bss . : {
        *(.bss .bss.*)
    }

    /* Debug sections: */

    /* Unfortunately, these cannot be retained in the PE format image. You must use --strip-debug
     * at link time or binutils produces a binary that OVMF (at least) refuses to load. */

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

    /* sections to discard */

    /DISCARD/ : {
        
        /* discard some stuff that's not needed or problematic */
        *(.comment)
        *(.note.gnu.property)
        *(.note.GNU-stack)
        *(.dynamic)
    }
}
