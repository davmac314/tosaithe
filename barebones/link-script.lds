PHDRS
{
  text PT_LOAD FILEHDR PHDRS FLAGS(0x5) ; /* 0x5 = READ (0x4) + EXECUTE (0x1) */
  data PT_LOAD ;
  tsbp_hdr 0x64534250 ;
}

SECTIONS
{
  /* load in the top-half "negative" address space, specifically -2GB, with a +2MB offset */
  . = SEGMENT_START("text-segment", 0xffffffff80200000) + SIZEOF_HEADERS;
  
  .tsbp_hdr : {
    KEEP(*(.tsbp_hdr))
  } :tsbp_hdr :text

  /* Uncomment if you will use static initialisers (needs runtime support): */
  /*
  . = ALIGN(8);
  .init_array : {
    PROVIDE_HIDDEN(__init_array_start = .);
    KEEP(*(.init_array .ctors))
    PROVIDE_HIDDEN(__init_array_end = .);
  }
  */

  .text : {
    *(.text)
    *(.text.*)
  } :text
  .rodata : {
    *(.rodata)
    *(.rodata.*)
    *(.rdata.*)
  }

  . = ALIGN(0x1000);
  .data : {
    *(.data)
    *(.data.*)
  } :data
  .bss : {
    START_BSS = .;
    *(.bss)
    *(.bss.*)
    *(COMMON)
    . = ALIGN(0x1000);
    KERNEL_STACK_BOTTOM = .;
    . = . + 8192;
    KERNEL_STACK_TOP = .;
    END_BSS = .;
  }

  /* Debug sections */
  .debug_aranges 0 : { *(.debug_aranges) }
  .debug_str 0 : { *(.debug_str) }
  .debug_loc 0 : { *(.debug_loc) }
  .debug_abbrev 0 : { *(.debug_abbrev) }
  .debug_info 0 : { *(.debug_info) }
  .debug_ranges 0 : { *(.debug_ranges) }
  .debug_macinfo 0 : { *(.debug_macinfo) }
  .debug_pubnames 0 : { *(.debug_pubnames) }
  .debug_pubtypes 0 : { *(.debug_pubtypes) }
  .debug_frame 0 : { *(.debug_frame) }
  .debug_line 0 : { *(.debug_line) }
  
  /DISCARD/ : {
    /* discard some stuff that's not needed or problematic. */
    *(.comment)
    *(.note.gnu.property)
    *(.note.GNU-stack)
    *(.dynamic)
    *(.eh_frame)
  }
}
