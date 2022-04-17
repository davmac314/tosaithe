# TSBP - TOSAITHE BOOT PROTOCOL

This is boot protocol for handover between boot loaders and OS kernels, on x86-64 architecture.
It is a WIP.

 * Kernel must be structured as an ELF file with (details to come).

 * Kernel virtual address must be somewhere in the top 2GB of the top-half of the address space.
 * The kernel will be loaded into physically contiguous memory, but at an arbitrary address.
 * On entry to kernel, physical memory (as described in the memory map provided) is mapped
   linearly at address 0 and again at 0xFFFF800000000000 (lowest top-half address in 4-level
   paging mode).
   Regardless of the memory map provided, at least the entire first 4GB will be mapped.
   This allows for LAPIC/IOAPIC access for example.
