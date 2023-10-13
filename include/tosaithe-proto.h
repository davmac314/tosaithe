#ifndef INCLUDED_TOSAITHE_PROTO_H
#define INCLUDED_TOSAITHE_PROTO_H 1

// Tosaithe boot protocol definitions.

#ifdef __cplusplus
#include <cstdint>
#else
#include <stdint.h>
#endif

#ifdef __cplusplus

static_assert(sizeof(void *) == 8, "this code needs adjusting for 32-bit environment");

// forward declarations:
struct tosaithe_loader_data;
struct tsbp_mmap_entry;
struct tsbp_kernel_mapping;

#else

typedef struct tosaithe_loader_data tosaithe_loader_data;
typedef struct tsbp_mmap_entry tsbp_mmap_entry;
typedef struct tsbp_kernel_mapping tsbp_kernel_mapping;
typedef struct tosaithe_entry_header tosaithe_entry_header;

#endif



#ifdef __cplusplus

struct tosaithe_hdr_flags {
    static const int REQ_FRAMEBUFFER = 1;
};

#else

static const int tosaithe_hdr_flags_REQ_FRAMEBUFFER = 1;

#endif


// Entry header is a static structure which must be at offset 0 within the first segment of the
// ELF file. Other details (including entry point) are in the ELF metadata.
struct tosaithe_entry_header {
    uint32_t signature; // = "TSBP"
    uint32_t version; // protocol version for this structure (= 0)
    uint32_t min_reqd_version; // the minimum required protocol version that loader must support
    uint32_t flags;  //  bits 1-0:  00 = does not require framebuffer
                     //             01 = requires framebuffer
                     //             1x = reserved
    uintptr_t stack_ptr; // stack pointer on entry
};

// The entry point receives a single argument: a pointer to a tosaithe_loader_data structure
// provided by the loader.
struct tosaithe_loader_data {

    uint32_t signature; // = "TSLD"
    uint32_t version; // = 0
    uint32_t flags;  // (currently unused)

    const char *cmdline; // nul-terminated, UTF-8 (or subset) encoded

    tsbp_mmap_entry *memmap;
    uint32_t memmap_entries;  // (count of entries in memory map)

    tsbp_kernel_mapping *kern_map;
    uint32_t kern_map_entries;

    void *   ramdisk;       // initial ramdisk image (or null)
    uint64_t ramdisk_size;  // size in bytes of ramdisk image (or 0)

    void *   acpi_rdsp;  // ACPI RDSP (Root Data Structure Pointer), if available
    void *   smbios3_entry; // SMBIOS 3.0+ (64-bit) "entry point" (table), if available

    // EFI info. Following are 0/nullptr if not available:

    void *   efi_memmap;             // EFI-firmware provided memory map
    uint32_t efi_memmap_descr_size;  // size of each entry in EFI memory map (in bytes)
    uint32_t efi_memmap_size;        // size of the complete EFI memory map (in bytes)
    void *   efi_system_table;       // EFI system table

    // Framebuffer info (addr/size are 0 if not available)

    void * framebuffer_addr;      // physical address of the framebuffer (null if none available)
    uintptr_t framebuffer_size;   // size in bytes of the framebuffer, rounded up to page boundary
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

#ifdef __cplusplus

enum class tsbp_mmap_type : uint32_t {
    USABLE                 = 0,
    RESERVED               = 1,
    ACPI_RECLAIMABLE       = 2,  // stores ACPI tables/data
    ACPI_NVS               = 3,  // reserved for (ACPI) firmware use
    UEFI_RUNTIME_CODE      = 4,
    UEFI_RUNTIME_DATA      = 5,
    BAD_MEMORY             = 6,
    PERSISTENT_MEMORY      = 7,  // persistent; precise meaning/use is system-dependent
    BOOTLOADER_RECLAIMABLE = 0x1000, // tosaithe loader data structure, memory map, command line, etc
    KERNEL                 = 0x1001,
    RAMDISK                = 0x1002,
    FRAMEBUFFER            = 0x1003
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

    static const uint32_t UEFI_RUNTIME = 0x10;  // If set, required to be mapped by UEFI runtime services
};

struct tsbp_kernel_mapping_flags {
    static const unsigned EXEC = 0x1;
    static const unsigned WRITE = 0x2;
    static const unsigned READ = 0x4;
};

#else

static const uint32_t tsbp_mmap_type_USABLE            = 0;
static const uint32_t tsbp_mmap_type_RESERVED          = 1;
static const uint32_t tsbp_mmap_type_ACPI_RECLAIMABLE  = 2;
static const uint32_t tsbp_mmap_type_ACPI_NVS          = 3;
static const uint32_t tsbp_mmap_type_UEFI_RUNTIME_CODE = 4;
static const uint32_t tsbp_mmap_type_UEFI_RUNTIME_DATA = 5;
static const uint32_t tsbp_mmap_type_BAD_MEMORY        = 6;
static const uint32_t tsbp_mmap_type_PERSISTENT_MEMORY = 7;
static const uint32_t tsbp_mmap_type_BOOTLOADER_RECLAIMABLE = 0x1000;
static const uint32_t tsbp_mmap_type_KERNEL            = 0x1001;
static const uint32_t tsbp_mmap_type_RAMDISK           = 0x1002;
static const uint32_t tsbp_mmap_type_FRAMEBUFFER       = 0x1003;

typedef uint32_t tsbp_mmap_type;

static const uint32_t tsbp_mmap_flags_CACHE_MASK       = 0x7;
static const uint32_t tsbp_mmap_flags_CACHE_WB         = 0x0;
static const uint32_t tsbp_mmap_flags_CACHE_WT         = 0x1;
static const uint32_t tsbp_mmap_flags_CACHE_UC         = 0x2;
static const uint32_t tsbp_mmap_flags_CACHE_WP         = 0x4;
static const uint32_t tsbp_mmap_flags_CACHE_WC         = 0x5;

static const uint32_t tsbp_mmap_flags_UEFI_RUNTIME     = 0x10;

static const uint32_t tsbp_kernel_mapping_flags_EXEC   = 0x1;
static const uint32_t tsbp_kernel_mapping_flags_WRITE  = 0x2;
static const uint32_t tsbp_kernel_mapping_flags_READ   = 0x4;

typedef struct tsbp_mmap_entry tsbp_mmap_entry;
typedef struct tsbp_kernel_mapping tsbp_kernel_mapping;

#endif


struct tsbp_mmap_entry {
    uintptr_t base;
    uintptr_t length;
    tsbp_mmap_type type;
    uint32_t flags;
};

// tsbp_kernel_mapping: describes a kernel physical-virtual mapping
struct tsbp_kernel_mapping {
    uintptr_t base_phys;
    uintptr_t base_virt;
    uintptr_t length;
    unsigned flags;
};

// Entry point details:

// x86-64 (the only currently supported architecture). A GDT with a null entry and code segment
// is provided. DS/SS use the null selector.
static const int TOSAITHE_CS_SEG = 1*8; // 2nd 8-byte entry

#endif
