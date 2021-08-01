#ifndef INCLUDED_STIVALE2_H
#define INCLUDED_STIVALE2_H 1

#include <stdint.h>

template <typename T> using ptr64 = T *;
template <typename T> using funcptr64 = T;


// Header tags, i.e. request from OS to bootloader:
constexpr uint64_t STIVALE2_HT_FRAMEBUFFER_IDENT = 0x3ecc1bc43d0f7971;
constexpr uint64_t STIVALE2_HT_TERMINAL_IDENT = 0xa85d499b1823be72U;

// Loader tags, i.e info/feature from bootloader to OS:
constexpr uint64_t STIVALE2_LT_MMAP_IDENT = 0x2187f79e8612de07;
constexpr uint64_t STIVALE2_LT_CMDLINE_IDENT = 0xe5e76a1b4597a781;
constexpr uint64_t STIVALE2_LT_FRAMEBUFFER_IDENT = 0x506461d2950408fa;
constexpr uint64_t STIVALE2_LT_TERMINAL_IDENT = 0xc2b3f4c3233b0974;


struct stivale2_tag {
    uint64_t identifier;
    ptr64<stivale2_tag> next;
};


struct stivale2_header {
    uint64_t entry_point;
    uint64_t stack_top;
    uint64_t flags;
    ptr64<stivale2_tag> tags;
};

struct stivale2_header_tag_framebuffer {
    stivale2_tag tag;             // STIVALE2_ST_FRAMEBUFFER_IDENT
    uint16_t framebuffer_width;
    uint16_t framebuffer_height;
    uint16_t framebuffer_bpp;
};

struct stivale2_header_tag_terminal {
    stivale2_tag tag;         // STIVALE2_ST_TERMINAL_IDENT
    uint64_t flags;           // (all bits 0)
};


// Information from bootloader to kernel
struct stivale2_struct {
    char bootloader_brand[64];
    char bootloader_version[64];
    ptr64<stivale2_tag> tags;
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
    stivale2_tag tag;  // STIVALE2_ST_MMAP_IDENT
    uint64_t entries;
    stivale2_mmap_entry memmap[];
};

struct stivale2_cmdline_info {
    stivale2_tag tag;       // STIVALE2_CMDLINE_LDR_TAG_ID
    ptr64<char> cmdline;
};

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

typedef void (*stivale2_term_write_func_t)(const char *string, uint64_t length);

struct stivale2_terminal_info {
    stivale2_tag tag;           // STIVALE2_TERMINAL_LDR_TAG_ID
    uint32_t flags;             // Bit 0: cols/rows values present
    uint16_t cols;              // Number of character columns
    uint16_t rows;              // Number of character rows
    funcptr64<stivale2_term_write_func_t> term_write;    // stivale2_term_write() function
};


#endif
