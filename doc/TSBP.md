# TSBP - TOSAITHE BOOT PROTOCOL

This is boot protocol for handover between boot loaders and OS kernels, on x86-64 architecture.
It is a WIP.

Kernel file requirements:

 * Kernel must be structured as an ELF file.
 * The first data (i.e. at offset 0) in the first segment must be a tosaithe_entry_header
   structure, including valid signature.
 * Kernel virtual address must be somewhere in the top 2GB of the top-half of the address space
   (i.e. from 0xFFFF_FFFF_8000_0000 to 0xFFFF_FFFF_FFFF_FFFF).
 * Loadable segments must not overlap.
 * Segment alignment must be 4kb, 2mb or 1gb; all segments must have the same alignment.

How the kernel is loaded:

 * The kernel will be loaded into physically contiguous memory, but at an arbitrary physical
   address. Segment alignment will be honoured.
 * Any parts of a loadable segment that are not present in the file (i.e. for segments where the
   size in memory is larger than the size in file) will be zero-filled. (Note: this allows for
   a standard ".bss" section).

Address mapping (page table setup):

 * On entry to kernel, physical memory (as described in the memory map provided) is mapped
   linearly at address 0 and again at 0xFFFF800000000000 (lowest top-half address in 4-level
   paging mode).
 * Regardless of the memory map provided, the entire first 4GB will be identity mapped (with
   mapping mirrored in the top-half); this allows for LAPIC/IOAPIC access for example.
 * The kernel is mapped in the top-half according to its virtual load address (masking any
   mapping that would otherwise be visible at that address).
 * Any mapped memory is mapped using pages of an unspecified (and possibly heterogeneous) size.

Entry to kernel:

 * UEFI Boot Services are not available.
 * The entry point receives a single argument, a pointer to the tosaithe_loader_data structure.
