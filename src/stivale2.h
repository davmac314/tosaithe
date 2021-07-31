#ifndef INCLUDED_STIVALE2_H
#define INCLUDED_STIVALE2_H 1

#include <stdint.h>

template <typename T> using ptr64 = T *;


struct stivale2_tag {
    uint64_t identifier;
    ptr64<stivale2_tag> next;
};

struct stivale2_struct {
    char bootloader_brand[64];
    char bootloader_version[64];
    stivale2_tag *tags;
};

enum class stivale2_mmap_type : uint32_t {
    USABLE                 = 1,
    RESERVED               = 2,
    ACPI_RECLAIMABLE       = 3,
    ACPI_NVS               = 4,
    BAD_MEMORY             = 5,
    BOOTLOADER_RECLAIMABLE = 0x1000,
    KERNEL_AND_MODULES     = 0x1001,
    FRAMEBUFFER            = 0x1002
};

struct stivale2_mmap_entry {
    uint64_t base;
    uint64_t length;
    stivale2_mmap_type type;
    uint32_t unused;
};

struct stivale2_struct_tag_memmap {
    stivale2_tag tag;
    uint64_t entries;
    stivale2_mmap_entry memmap[];
};

const uint64_t STIVALE2_ST_MMAP_IDENT = 0x2187f79e8612de07;

struct stivale2_struct_tag_framebuffer {
    stivale2_tag tag;             // STIVALE2_ST_FRAMEBUFFER_IDENT
    uint64_t framebuffer_addr;    // physical address of the framebuffer
    uint16_t framebuffer_width;   // width in pixels
    uint16_t framebuffer_height;  // height in pixels
    uint16_t framebuffer_pitch;   // pitch in bytes
    uint16_t framebuffer_bpp;     // bits per pixel
    uint8_t  memory_model;        // always 1 (RGB)

    // pixel format: bitmasks and position (shift) for R/G/B component
    uint8_t  red_mask_size;
    uint8_t  red_mask_shift;
    uint8_t  green_mask_size;
    uint8_t  green_mask_shift;
    uint8_t  blue_mask_size;
    uint8_t  blue_mask_shift;
};

const uint64_t STIVALE2_ST_FRAMEBUFFER_IDENT = 0x506461d2950408fa;

#endif
