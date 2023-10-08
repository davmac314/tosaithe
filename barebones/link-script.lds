SECTIONS
{
  /* load in the top-half "negative" address space, specifically -2GB, with a +2MB offset */
  . = 0xffffffff80200000;
  
  .tsbp_hdr : {
    KEEP(*(.tsbp_hdr))
  }

  /* Uncomment if you will use static initialisers (needs runtime support): */
  /*
  . = ALIGN(8);
  .init_array : {
    PROVIDE_HIDDEN(__init_array_start = .);
    KEEP(*(.init_array .ctors))
    PROVIDE_HIDDEN(__init_array_end = .);
  }
  */

  . = ALIGN(0x1000);
  .text : {
    *(.text)
    *(.text.*)
  }
  .rodata : {
    *(.rodata)
    *(.rodata.*)
    *(.rdata.*)
  }

  . = ALIGN(0x1000);
  .data : {
    *(.data)
    *(.data.*)
  }
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
}
