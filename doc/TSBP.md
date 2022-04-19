# TSBP - TOSAITHE BOOT PROTOCOL

This is boot protocol for handover between boot loaders and OS kernels, on x86-64 architecture.
It is a WIP.

 * Kernel must be structured as an ELF file.
 * The first data (i.e. at offset 0) in the first segment must be a tosaithe_entry_header
   structure, including valid signature.
 * Kernel virtual address must be somewhere in the top 2GB of the top-half of the address space
   (i.e. from 0xFFFF_FFFF_8000_0000 to 0xFFFF_FFFF_FFFF_FFFF).
 * The kernel will be loaded into physically contiguous memory, but at an arbitrary address.
 * Segment alignment must be 4kb, 2mb or 1gb. The alignment is honoured, i.e. the kernel will
   be loaded at a physical address with the required alignment.
 * On entry to kernel, physical memory (as described in the memory map provided) is mapped
   linearly at address 0 and again at 0xFFFF800000000000 (lowest top-half address in 4-level
   paging mode).
   
   Regardless of the memory map provided, at least the entire first 4GB will be mapped;
   this allows for LAPIC/IOAPIC access for example.
 * The entry point receives a single argument, a pointer to the tosaithe_loader_data structure.
