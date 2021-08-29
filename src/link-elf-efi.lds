ENTRY(EfiMain)

SECTIONS {

    /* We'll start .text at the 4kb mark and align later sections on a 4kb
     * boundary. This doesn't seem to be strictly necessary. */

    .text 0x1000 : {
        *(.text)
    }

    .rodata : {
        *(.rodata)
    }

    . = ALIGN(8);

    .eh_frame : {
        KEEP(*(.eh_frame))
    }
    
    /* https://refspecs.linuxfoundation.org/LSB_1.3.0/gLSB/gLSB/ehframehdr.html */
    .eh_frame_hdr : {
        KEEP(*(.eh_frame_hdr))
    }

    . = ALIGN(0x1000);

    .data : {
        *(.data)
    }

    . = ALIGN(0x1000);

    .bss . : {
        *(.bss)
    }

    /* Relocations at the end. We could also put them before .bss, but this theoretically gives
     * the option of disposing of relocations after load (without leaving a hole). We must put
     * .reloc after .text/.data/.rodata since it must come after sections it contains relocations
     * for, apparently. */

    . = ALIGN(0x1000);

    .reloc . : {
        *(.reloc)
    }

    /* sections to discard */

    /DISCARD/ : {
        *(.comment)
        *(.note.gnu.property)
        *(.note.GNU-stack)
        *(.dynamic)
    }
}
