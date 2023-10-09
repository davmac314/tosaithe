# TSBP - TOSAITHE BOOT PROTOCOL

_Preliminary revision_

Tosaithe, or _TSBP_, is a boot protocol for handover between bootloaders and OS kernels, on x86-64
architecture. It is designed to minimise implementation requirements on both loader and kernel
sides, but provides a range of features that may be required by advanced systems.

This document defines the protocol requirements for the bootloader and kernel.

## TSBP Header for C and C++

A header file for C and C++ is provided defining the types and constants used by this
specification. The header is named `tosaithe-proto.h`.

In some case this specification refers to scoped names such as `tbsp_mmap_flags::CACHE_MASK`.
These names are usable in C++ code; for C code, a usuable name can be derived by substituting
an underscore (`_`) for the scope operator (`::`). For the `CACHE_MASK` example, the usable C
name is `tbsp_mmap_flags_CACHE_MASK`.

## Kernel File Requirements

 * Kernel must be structured as an ELF file, with no relocations.
 * At offset 0 in any loadable ELF segment (i.e. of type `PT_LOAD`) a `tosaithe_entry_header`
   structure, including valid signature, must be present. Alternatively, a non-loadable segment
   of type `0x64534250` must be present and contain the header (which must also be present in a
   loadable segment). The header must be aligned on an 8-byte boundary. See the **Tosaithe Entry
   Header** section below.
 * Kernel virtual address must be somewhere in the top 2GB of the "negative" portion of the
   address space (i.e. from `0xFFFF_FFFF_8000_0000` to `0xFFFF_FFFF_FFFF_FFFF`). Note: the
   "negative" portion is also referred to as the "higher half".
 * Loadable segments must not overlap.
 * Segment alignment must be 4kb, 2mb or 1gb; all segments must have the same alignment.

Note: many of these requirements will be satisfied as a natural outcome of the usual linking
process.

## How the Kernel is Loaded

 * The kernel will be loaded into physically contiguous memory, but at an arbitrary physical
   address. Segment alignment will be honoured.
 * Any parts of a loadable segment that are not present in the file (i.e. for segments where the
   size in memory is larger than the size in file) will be zero-filled. (Note: this allows for
   a standard ".bss" section).

## Tosaithe Entry Header

The Tosaithe Entry Header (`tosaithe_entry_header` structure) must be present at the beginning of
the first segment in the kernel executable. This structure statically communicates information
from the kernel to the bootloader.

It contains the following fields:

- `uint32_t signature` - the Tosaithe Boot Protocol signature, corresponding to the byte sequence
  of "TSBP". The correct value can be specified as `'T' + ('S' << 8) + ('B' << 16) + ('P' << 24)`.
- `uint32_t version` - the version of the protocol that the kernel implements. This should be 0 to
  match the version of the protocol documented here.
- `uint32_t min_reqd_version` - the minimum version of the protocol that the bootloader must
  support in order to be able to load the kernel. This should be 0.
- `uint32_t flags` - flags specifying kernel requirements. Currently the following are defined:
  - bits 0-1: framebuffer requirement. `00b` = not required, `01b` = required; other values
    reserved.
  - other bits are reserved and should be set to 0. 
- `uintptr_t stack_ptr` - the stack pointer that should be established on entry to the kernel.

## Entry To Kernel

 * The processor is in 64-bit long mode (IA-32e mode).
 * The CS/DS/SS descriptors select 64-bit segments. CS will select the first segment (after the
   null segment) from the GDT and DS/SS will second the following segment. Note: it is recommended
   that the kernel establish its own GDT early.
 * The stack pointer is set as per required by the kernel (as specified in the entry header). A
   single value (an invalid return address) will be pushed onto the stack. Note: the kernel should
   specify a stack pointer that ensures any required alignment of the stack pointer for the entry
   function.
 * Interrupts are disabled at the processor level (i.e. the interrupt enable bit in the EFLAGS
   register is clear).
 * The direction flag (DF) is clear.
 * Other processor state is unspecified.
 * The entry point receives a single argument, a pointer to the `tosaithe_loader_data` structure
   (see **Loader data structure** below). Pointers within the `tosaithe_loader_data` structure
   (and any referenced structures) use physical addresses.
 * UEFI Boot Services are not available. Note: UEFI Runtime services may be available.

## Address Mappings

 * On entry to kernel, physical memory (as described in the memory map provided) is mapped
   linearly at address 0 and again at `0xFFFF_8000_0000_0000` (i.e. the lowest higher-half address
   in 4-level paging mode).
 * Regardless of the memory map provided, the entire first 4GB will be identity mapped (with
   mapping mirrored in the top-half); this allows for LAPIC/IOAPIC access for example.
 * The kernel is mapped according to its virtual load address, which must be 0xFFFF_FFFF_8000_0000
   or greater, putting it in the range (-2gb, 0). Note: this allows for efficient code generation
   using the "kernel" model provided by GCC (`-mcmodel=kernel`) for example, and prevents conflict
   with other mappings.
 * Any mapped memory is mapped using pages of an unspecified (and possibly heterogeneous) size.
 * The kernel is free to modify the bootloader-provided page tables, but there are no guarantees
   made as to their location or structure. It is recommended that the kernel establish its own
   page tables as early as possible.


## Loader Data Structure

The kernel entry point is provided with a pointer to an instance of a `tosaithe_loader_data`
structure, which the bootloader fills to provide system information to the kernel.

It contains the following fields:

- `uint32_t signature` - the loader signature, should be "TSLD" (from first i.e. least-significant
  to last i.e. most-significant byte)
- `uint32_t version` - the version of the protocol being used by the bootloader.
- `uint32_t flags` - currently unused.
- `const char *cmdline` - a pointer to the command line string, a nul-terminated string in UTF-8
  encoding.
- `tsbp_mmap_entry *memmap` - pointer to the system-provided memory map; see below.
- `uint32_t memmap_entries` - number of entries in memory map (via `memmap`)
- `tsbp_kernel_mapping *kern_map` - pointer to kernel segment mapping table. Specifies where each
  ELF segment was loaded and its attributes; see below.
- `void *ramdisk` - pointer to a ramdisk image that was loaded by the bootloader, or null if none.
  If present the ramdisk image will be page-aligned.
- `uint64_t ramdisk_size` - size of the ramdisk image that was loaded by the bootloader, or zero
  if none.

### Firmware Information

The following fields provide firmware such as pointers to firmware-provided tables:

- `void *acpi_rdsp` - pointer to the ACPI RDSP, if it can be determined by the bootloader.
- `void *smbios3_entry` - pointer to SMBIOS 3+ "entry" table, if it can be determined by the
  bootloader.
- `void *efi_memmap`, `uint32_t efi_memmap_descr_size`, `uint32_t efi_memmap_size` - pointer to
  the UEFI-firmware-provided memory map, if available; the size of each entry in bytes
  (`efi_memmap_descr_size`); and the total size in bytes (`efi_memmap_size`). Note: the memory map
  provided via `memmap` is intended to make this redundant; this map is provided as a fail-safe.
- `void *efi_system_table` - pointer to the UEFI firmware system table, if available. Note: Boot
  services will not be available to the kernel.

### Framebuffer

The following fields provide information about a framebuffer established by the firmware or
bootloader. Fields are set to 0 if there is no framebuffer available.

If provided, the framebuffer allows access to individual pixels on the display. Each pixel
is represented by a value, stored in one or more bytes, which can be broken into three components:
red, green, and blue, each of which is represented via a contiguous set of bits at a particular
position within the pixel value. The pixel at the top-left is at offset 0, followed by pixels in
the same row in order left to right; the row is packed so that there are no bytes between pixel
values. Each row of pixels is evenly spaced according to a pitch value (there may be extra bytes
between pixel rows).

Note: typical arrangements include 24-bits per pixel and 32-bits per pixel, with between 5 and 8
bits per colour channel (R/G/B). A 32bpp arrangement is normally preferred.

The following fields provide framebuffer information:

- `uintptr_t framebuffer_addr` - physical address of the framebuffer.
- `uintptr_t framebuffer_size` - size in bytes of the framebuffer, rounded up to the nearest 4kb.
- `uint16_t framebuffer_width` - width in pixels.
- `uint16_t framebuffer_height` - height in pixels.
- `uint16_t framebuffer_pitch` - pitch in bytes. This is the number of bytes between pixels in
  successive rows.
- `uint16_t framebuffer_bpp` - bits per pixel. This must be a multiple of 8, less than or equal to
  32.
- `uint8_t red_mask_size` - the number of bits used to represent the red component
- `uint8_t red_mask_shift` - the position of the red component within the pixel value
- `uint8_t green_mask_size` - the number of bits used to represent the green component
- `uint8_t green_mask_shift` - the position of the green component within the pixel value
- `uint8_t blue_mask_size` - the number of bits used to represent the blue component
- `uint8_t blue_mask_shift` - the position of the blue component within the pixel value

## Tosaithe Memory Map

The memory map provided via the loader data is a map of physical memory, comprising entries of
type `tsbp_mmap_entry`, ordered from low to high address. The map indicates available memory,
reclaimable memory (which holds information useful to the kernel, but which may be used by the
kernel once it has processed the information), and reserved address ranges.

Note that the memory map does not include address ranges currently used by CPU-specific devices
such as Local APIC and IOAPIC, or MMIO ranges for PCI devices or other devices that the firmware
expects the OS to enumerate. 

The `tsbp_mmap_entry` type comprises the following fields:

- `uintptr_t base` - the physical base address of the memory region (page-aligned).
- `uintptr_t length` - the length of the memory region.
- `tsbp_mmap_type type` - the type of the region.
- `uint32_t flags` - flags for the region.

The `tbsp_mmap_type` field takes one of the following values:

- `tbsp_mmap_type::USABLE` - the memory is available for use by the OS kernel.
- `tbsp_mmap_type::RESERVED` - the address range is reserved; any memory in the range should not
  be accessed by the OS. No device should have its MMIO space mapped to the address by the OS.
- `tbsp_mmap_type::ACPI_RECLAIMABLE` - the memory contains ACPI tables, and is usable by the OS
  once it no longer needs the tables.
- `tbsp_mmap_type::ACPI_NVS` - the memory is used by ACPI firmware and the OS should not use the
  memory or map MMIO into the address range.
- `tbsp_mmap_type::UEFI_RUNTIME_CODE`, `tbsp_mmap_type::UEFI_RUNTIME_DATA` - the memory contains
  UEFI firmware code or data; it can be used by the OS if it will not use UEFI runtime services.
  Note: if the OS will use UEFI runtime services with an alternative address map established via
  the `SetVirtualAddressMap()` UEFI runtime service function, it must provide a mapping for this
  memory region as part of that call.
- `tbsp_mmap_type::BAD_MEMORY` - the memory in this region is known to be faulty, and should not
  be used.
- `tbsp_mmap_type::PERSISTENT_MEMORY` - the memory in this range is persistent (the contents
  should survive system reboots and downtime). The precise nature of the range is dependent upon
  the system. In general, the OS should not make use of this memory unless it has particular
  knowledge of the underlying system or if requested by the user to do so.
- `tbsp_mmap_type::BOOTLOADER_RECLAIMABLE` - the memory contains information passed from the
  bootloader to the OS kernel. This includes the loader data structure, memory maps, command line,
  and any other data or tables provided by the bootloader (as opposed to the firmware). The kernel
  may use this memory once it no longer needs the information provided by the bootloader.
- `tbsp_mmap_type::KERNEL` - the memory contains the loaded kernel. Note: the kernel is also
  mapped at a virtual address, as described by the `kern_map` table via the loader entry data.
- `tbsp_mmap_type::RAMDISK` - the memory contains a ramdisk image, passed to the kernel via the
  `ramdisk` pointer.
- `tbsp_mmap_type::FRAMEBUFFER` - the memory contains a graphics framebuffer, passed to the kernel
  via the `framebuffer_addr` pointer.

## Kernel Mappings

The kernel mappings table, found via the `kern_map` (and `kern_map_entries`) field in the loader
data, specifies where each segment of the kernel ELF image is located in physical memory as well
as where it was mapped in the address space, and the permission flags associated with the segment.
The order of entries matches the order of their corresponding segments.
Note: the kernel mappings are provided mainly as a convenience. 

The entries are of type `tsbp_kernel_mapping`, with the following fields:

- `uintptr_t base_phys` - base physical address (page aligned).
- `uintptr_t base_virt` - base virtual address (page aligned).
- `uintptr_t length` - length, rounded up to page boundary.
- `unsigned flags` - segment flags, as specified in ELF header.

The flags field is a bitmask with the following possible values set:

- `tsbp_kernel_mapping_flags::EXEC` (0x1) - execute permission
- `tsbp_kernel_mapping_flags::WRITE` (0x2) - write permission
- `tsbp_kernel_mapping_flags::READ` (0x4) - read permission

Note: the segments may be mapped by the bootloader with more permissions than what is specified by
the `flags` field. The kernel is expected to create its own page table structure and may (at its
option) use the `kern_map` table to choose appropriate permissions for mapped pages.
