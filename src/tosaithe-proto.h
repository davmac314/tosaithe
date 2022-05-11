#ifndef INCLUDED_TOSAITHE_PROTO_H
#define INCLUDED_TOSAITHE_PROTO_H 1

// Tosaithe boot protocol definitions.
// This may show influence from Stivale2, but is a much simpler protocol.

#include <cstdint>

static_assert(sizeof(void *) == 8, "this code needs adjusting for 32-bit environment");
template <typename T> using ptr64 = T *;
template <typename T> using funcptr64 = T;

struct tosaithe_loader_data;
struct tsbp_mmap_entry;

// Entry header is a static structure which must be at offset 0 within the first segment of the
// ELF file. Other details (including entry point) are in the ELF metadata.
struct tosaithe_entry_header {
    uint32_t signature; // = "TSBP"
    uint32_t version; // protocol version for this structure (= 0)
    uint32_t min_reqd_version; // the minimum required protocol version that loader must support
    uintptr_t stack_ptr; // stack pointer on entry
};

// The entry point receives a single argument: a pointer to a tosaithe_loader_data structure
// provided by the loader.
struct tosaithe_loader_data {

    uint32_t signature; // = "TSLD"
    uint32_t version; // = 0
    uint32_t flags;  // (currently unused)

    char *   cmdline; // nul-terminated, UTF-8 (or subset) encoded

    tsbp_mmap_entry *memmap;
    uint32_t memmap_entries;

    void *   acpi_rdsp;  // ACPI RDSP (Root Data Structure Pointer), if known by boot loader

    // EFI info. Following are 0/nullptr if not available:

    void *   efi_memmap; // EFI-firmware provided memory map
    uint32_t efi_memmap_descr_size;  // size of entries in EFI memory map
    void *   efi_system_table; // EFI system table

    // Framebuffer info

    uintptr_t framebuffer_addr;   // physical address of the framebuffer (0 if none available)
    uint16_t framebuffer_width;   // width in pixels
    uint16_t framebuffer_height;  // height in pixels
    uint16_t framebuffer_pitch;   // pitch (bytes per line)
    uint16_t framebuffer_bpp;     // bits per pixel

    // pixel format: bitmasks and position (shift) for R/G/B component
    uint8_t  red_mask_size;
    uint8_t  red_mask_shift;
    uint8_t  green_mask_size;
    uint8_t  green_mask_shift;
    uint8_t  blue_mask_size;
    uint8_t  blue_mask_shift;
};

enum class tsbp_mmap_type : uint32_t {
    USABLE                 = 1,
    RESERVED               = 2,
    ACPI_RECLAIMABLE       = 3,  // stores ACPI tables/data
    ACPI_NVS               = 4,
    BAD_MEMORY             = 5,
    BOOTLOADER_RECLAIMABLE = 0x1000, // tosaithe loader data structure, memory map, command line, etc
    KERNEL_AND_MODULES     = 0x1001,
    FRAMEBUFFER            = 0x1002
};

struct tsbp_mmap_flags {
    static const uint32_t CACHE_MASK = 0x7;  // mask for isolating cache mode

    // Cache mode. The numbering is designed to match (for 0-2, designed to match equivalent PCD-PWT combination)
    static const uint32_t CACHE_WB = 0x0; // write-back (full caching)
    static const uint32_t CACHE_WT = 0x1; // write-thru (allows reads from cache)
    static const uint32_t CACHE_UC = 0x2; // uncacheable
    // for the following types, generally should map to uncacheable if PAT is not available
    // (which then may be overwridden via MTRRs)
    static const uint32_t CACHE_WP = 0x4; // write-protect (allow reads from cache, writes don't go to cache)
    static const uint32_t CACHE_WC = 0x5; // write-combining (writes go through store buffer, not cached)
};

struct tsbp_mmap_entry {
    uintptr_t base;
    uintptr_t length;
    tsbp_mmap_type type;
    uint32_t flags;
};

// Entry point details:

// x86-64 (the only currently supported architecture). A GDT with a null entry, code segment and
// data segment is provided.
static const int TOSAITHE_CS_SEG = 1*8; // 2nd 8-byte entry
static const int TOSAITHE_DS_SEG = 2*8; // 3rd 8-byte entry

#endif
