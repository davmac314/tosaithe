#include <algorithm>
#include <string>
#include <memory>
#include <new>

#include <elf.h>

#include "uefi.h"
#include "uefi-media-file.h"
#include "uefi-loadedimage.h"
#include "tosaithe-proto.h"

#include "tosaithe-util.h"

extern EFI_BOOT_SERVICES *EBS;
extern EFI_SYSTEM_TABLE *EST;

// Supported page sizes:
static const uintptr_t PAGE4KB = 0x1000u;
static const uintptr_t PAGE2MB = 0x200000u;
static const uintptr_t PAGE1GB = 0x40000000u;

// Top of memory minus 2GB. The kernel virtual address must be within this region.
static const uintptr_t TOP_MINUS_2GB = 0xFFFFFFFF80000000u;


// Class to manage building a tosaithe boot protocol memory map structure
class tosaithe_memmap {
    tsbp_mmap_entry *memmap_entries = nullptr;
    uint32_t entries = 0;
    uint32_t capacity = 0;

    bool increase_capacity() noexcept
    {
        uint32_t newcapacity = capacity + 6; // bump capacity by arbitrary amount
        uint32_t req_size = sizeof(tsbp_mmap_entry) * newcapacity;
        tsbp_mmap_entry *newmap = (tsbp_mmap_entry *) alloc_pool(req_size);
        if (newmap == nullptr) {
            return false;
        }

        // Copy map from old to new storage
        for (uint32_t i = 0; i < entries; i++) {
            new(&newmap[i]) tsbp_mmap_entry(memmap_entries[i]);
        }

        free_pool(memmap_entries);
        memmap_entries = newmap;
        capacity = newcapacity;

        return true;
    }

public:
    void allocate(uint32_t capacity_p)
    {
        uint32_t req_size = sizeof(tsbp_mmap_entry) * capacity_p;
        memmap_entries = (tsbp_mmap_entry *) alloc_pool(req_size);
        if (memmap_entries == nullptr) {
            throw std::bad_alloc();
        }
        capacity = capacity_p;
    }

    void add_entry(tsbp_mmap_type type_p, uint64_t physaddr, uint64_t length, uint32_t flags)
    {
        if (entries == capacity) {
            if (!increase_capacity()) {
                throw std::bad_alloc();
            }
        }

        new(&memmap_entries[entries]) tsbp_mmap_entry();
        memmap_entries[entries].type = type_p;
        memmap_entries[entries].base = physaddr;
        memmap_entries[entries].length = length;
        memmap_entries[entries].flags = flags;
        entries++;
    }

    // Insert an entry into the map. Any existing entries which are overlapped by the new entry are
    // trimmed (or removed in the case of total overlap).
    // On failure, throws std::bad_alloc (map may be invalid)
    // On success: map may require sorting
    void insert_entry(tsbp_mmap_type type_p, uint64_t physaddr, uint64_t length, uint32_t flags)
    {
        uint64_t physend = physaddr + length;

        for (uint32_t i = 0; i < entries; i++) {
            uint64_t ent_base = memmap_entries[i].base;
            uint64_t ent_len = memmap_entries[i].length;
            uint64_t ent_end = ent_base + ent_len;

            if (ent_base >= physaddr && ent_end <= physend) {
                // complete overlap; remove this entry by moving the last entry into its place
                memmap_entries[i] = memmap_entries[--entries];
            }
            else if (ent_end > physaddr && physend > ent_base) {
                // partial overlap, trim or possibly split
                if (physaddr <= ent_base) {
                    // trim start
                    ent_len -= (physend - ent_base);
                    ent_base = physend;
                    memmap_entries[i].base = ent_base;
                    memmap_entries[i].length = ent_len;
                }
                else if (physend >= ent_end) {
                    // trim end
                    ent_len = physaddr - ent_base;
                    memmap_entries[i].length = ent_len;
                }
                else {
                    // split somewhere in the middle
                    uint64_t tail_len = ent_end - physend;
                    add_entry(memmap_entries[i].type, physend, tail_len, memmap_entries[i].flags);
                    ent_len = physaddr - ent_base;
                    memmap_entries[i].length = ent_len;
                }
            }
        }

        // Finally add the new entry:
        add_entry(type_p, physaddr, length, flags);
    }

    void sort() noexcept
    {
        // Ok, so this is bubble sort. But the map shouldn't be too big and will likely be nearly
        // sorted already, so this is a good fit.

        uint32_t end_i = entries - 1; // highest unsorted entry

        while (end_i > 0) {
            uint32_t last_i = 0;
            for (uint32_t i = 0; i < end_i; i++) {
                if (memmap_entries[i].base > memmap_entries[i+1].base) {
                    swap(memmap_entries[i], memmap_entries[i+1]);
                    last_i = i;
                }
            }
            end_i = last_i;
        }
    }

    // Clear all memory map entries, *without* reducing capacity. This is for when we need to
    // rebuild the map from scratch, but don't want to have to perform additional allocations.
    void clear() noexcept
    {
        entries = 0;
    }

    tsbp_mmap_entry *get()
    {
        return memmap_entries;
    }

    uint32_t get_size()
    {
        return entries;
    }

    ~tosaithe_memmap()
    {
        if (memmap_entries != nullptr) {
            free_pool(memmap_entries);
        }
    }
};

// An entry in a descriptor table
struct DT_entry {
    uint64_t data;
};

enum class dt_size_t {
    s16, s32, s64
};

struct GDT_entry_reg {
    uint16_t limit_0_15; // limit bits 0-15
    uint16_t base_0_15;  // base bits 0-15

    // 5th byte (offset 4)
    uint8_t base_16_23;  // base bits 16-23

    // 6th byte
    uint8_t entry_type : 4;
    uint8_t flag_s : 1;  // descriptor type 0=system 1=code/data (affects entry_type meaning)
    uint8_t dpl : 2;  // privilege level required to access (0 = highest privilege)
    uint8_t p : 1;    // segment present (if 0, loading descriptor will trap)

    // 7th byte
    uint8_t limit_16_19 : 4;
    uint8_t available : 1; // available for use by OS
    uint8_t flag_L : 1;    // 1=64-bit code segment, 0=32/16 bit segment or data segment
    uint8_t flag_sz : 1; // 0=16 bit, 1=32 bit; must be 0 for 64-bit segment (i.e. if L is 1)
                         // 32/16 bit: affects eg default operand size for code segments, stack pointer
                         // size for stack segment, upper limit of expand-down segment
    uint8_t flag_gr : 1; // granularity, if set limit is in 4kb granularity (otherwise byte)

    // Final byte
    uint8_t base_24_31;

    // Constructor with a standard set of parameters. Will create an entry with the specified
    // base and limit, type, bit size (16/32/64), and with DPL=0 (i.e. highest privilege level).
    // If g4k_limit is true, the specified limit is adjusted (real_limit = (limit+1) * 4096 - 1).
    constexpr GDT_entry_reg(uint32_t base, uint32_t limit, bool g4k_limit,
            uint16_t entry_type_p, dt_size_t size_p) :
        limit_0_15(limit & 0xFFFFu),
        base_0_15(base & 0xFFFFu),
        base_16_23((base & 0xFF0000u) >> 16),
        entry_type(entry_type_p & 0x0Fu),
        flag_s(((entry_type_p & 0x10u) == 0) ? 0 : 1),
        dpl(0),
        p(1),
        limit_16_19((limit & 0x0F0000u) >> 16),
        available(0),
        flag_L((size_p == dt_size_t::s64) ? 1 : 0),
        flag_sz((size_p == dt_size_t::s16 || size_p == dt_size_t::s64) ? 0 : 1),
        flag_gr(g4k_limit),
        base_24_31((base & 0xFF000000u) >> 24)
    {
    }

    // Constructor with a standard set of parameters. Will create an entry with the specified
    // base and limit, type, bit size (16/32/64), and DPL (privilege level).
    // If g4k_limit is true, the specified limit is adjusted (real_limit = (limit+1) * 4096 - 1).
    constexpr GDT_entry_reg(uint32_t base, uint32_t limit, bool g4k_limit,
            uint16_t entry_type_p, dt_size_t size_p, uint8_t dpl_p) :
        limit_0_15(limit & 0xFFFFu),
        base_0_15(base & 0xFFFFu),
        base_16_23((base & 0xFF0000u) >> 16),
        entry_type(entry_type_p & 0x0Fu),
        flag_s(((entry_type_p & 0x10u) == 0) ? 0 : 1),
        dpl(dpl_p),
        p(1),
        limit_16_19((limit & 0x0F0000u) >> 16),
        available(0),
        flag_L((size_p == dt_size_t::s64) ? 1 : 0),
        flag_sz((size_p == dt_size_t::s16 || size_p == dt_size_t::s64) ? 0 : 1),
        flag_gr(g4k_limit),
        base_24_31((base & 0xFF000000u) >> 24)
    {
    }

    constexpr operator DT_entry()
    {
        return DT_entry
            {
                (uint64_t)limit_0_15
                | (uint64_t(base_0_15) << 16)
                | (uint64_t(base_16_23) << 32)
                | (uint64_t(entry_type) << 40)
                | (uint64_t(flag_s) << 44)
                | (uint64_t(dpl) << 45)
                | (uint64_t(p) << 47)
                | (uint64_t(limit_16_19) << 48)
                | (uint64_t(available) << 52)
                | (uint64_t(flag_L) << 53)
                | (uint64_t(flag_sz) << 54)
                | (uint64_t(flag_gr) << 55)
                | (uint64_t(base_24_31) << 56)
            };
    }
};

// For the following types, bit 0 is "accessed" bit, set by CPU on access. For code/data we set
// the 5th bit (hence "16+" in all values). This is copied into the "S" flag, it isn't technically
// part of the type.

const static uint16_t DT_RWDATA = 16+2;
const static uint16_t DT_ROCODE = 16+10; // code, execute/read (no write)

// readable 16-bit code segment, base 0, 64k limit, non-conforming
inline constexpr GDT_entry_reg cons_DT_code16_descriptor()
{
    return GDT_entry_reg(0, 0xFFFFu, false, DT_ROCODE, dt_size_t::s16);
}

inline constexpr GDT_entry_reg cons_DT_data16_descriptor()
{
    return GDT_entry_reg(0, 0xFFFFu, false, DT_RWDATA, dt_size_t::s16);
}

// readable 32-bit code segment, base 0, 4GB limit (4kb granular), non-conforming
inline constexpr GDT_entry_reg cons_DT_code32_descriptor()
{
    return GDT_entry_reg(0, 0x000FFFFFu, true, DT_ROCODE, dt_size_t::s32);
}

// standard (grows-up) 32-bit data segment, base 0, 4GB limit (4kb granular)
inline constexpr GDT_entry_reg cons_DT_data32_descriptor()
{
    return GDT_entry_reg(0, 0x000FFFFFu, true, DT_RWDATA, dt_size_t::s32);
}

// readable 64-bit code segment, base 0, 4GB limit (ignored), non-conforming
inline constexpr GDT_entry_reg cons_DT_code64_descriptor()
{
    // Note base and limit will be ignored
    return GDT_entry_reg(0, 0x000FFFFFu, true, DT_ROCODE, dt_size_t::s64);
}

// Global Descriptor Table for kernel entry
DT_entry GDT_table[] = {
        {0}, // NULL

        // ---- 1 ----

        cons_DT_code64_descriptor(),
        cons_DT_data32_descriptor(),
};

static const CHAR16 * const OPEN_KERNEL_ERR_FIRMWARE = L"unexpected firmware error";
static const CHAR16 * const OPEN_KERNEL_ERR_VOLUME = L"cannot open volume";
static const CHAR16 * const OPEN_KERNEL_ERR_FILEOPEN = L"cannot open file";

// Open a kernel file for reading, return true if successful.
// Throws: std::bad_alloc
static bool open_kernel_file(EFI_HANDLE image_handle, const CHAR16 *exec_path,
        EFI_FILE_PROTOCOL **kernel_file_p, UINTN *kernel_file_size_p)
{
    EFI_LOADED_IMAGE_PROTOCOL *image_proto;
    EFI_STATUS status = EBS->HandleProtocol(image_handle,
            &EFI_loaded_image_protocol_guid, (void **)&image_proto);
    // status must be EFI_SUCCESS?
    (void)status;

    const CHAR16 * errmsg;

    {
        EFI_DEVICE_PATH_PROTOCOL *image_device_path = nullptr;
        if (EBS->HandleProtocol(image_handle, &EFI_loaded_image_device_path_protocol_guid,
                (void **)&image_device_path) != EFI_SUCCESS) {
            // this support is mandatory...
            errmsg = OPEN_KERNEL_ERR_FIRMWARE; goto error_out;
        }

        if (image_device_path == nullptr) {
            errmsg = OPEN_KERNEL_ERR_FIRMWARE; goto error_out;
        }

        unsigned exec_path_size = (strlen(exec_path) + 1) * sizeof(CHAR16);
        efi_unique_ptr<EFI_DEVICE_PATH_PROTOCOL> kernel_path
                { switch_path(image_device_path, exec_path, exec_path_size) };

        // Try to load the kernel now
        EFI_HANDLE loadDevice;

        auto *remaining_path = kernel_path.get();
        status = EBS->LocateDevicePath(&EFI_simple_file_system_protocol_guid, &remaining_path, &loadDevice);
        kernel_path = nullptr;
        if (EFI_ERROR(status)) {
            errmsg = OPEN_KERNEL_ERR_FIRMWARE; goto error_out;
        }

        EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *sfs_protocol = nullptr;

        status = EBS->HandleProtocol(loadDevice, &EFI_simple_file_system_protocol_guid,
                (void **)&sfs_protocol);
        if (EFI_ERROR(status) || (sfs_protocol == nullptr /* firmware misbehaving */)) {
            errmsg = OPEN_KERNEL_ERR_FIRMWARE; goto error_out;
        }

        EFI_FILE_PROTOCOL *fs_root = nullptr;
        status = sfs_protocol->OpenVolume(sfs_protocol, &fs_root);
        if (EFI_ERROR(status) || (fs_root == nullptr /* firmware misbehaving */)) {
            errmsg = OPEN_KERNEL_ERR_VOLUME; goto error_out;
        }

        efi_file_handle kernel_file_hndl;
        {
            EFI_FILE_PROTOCOL *kernel_file = nullptr;
            status = fs_root->Open(fs_root, &kernel_file, exec_path, EFI_FILE_MODE_READ, 0);
            fs_root->Close(fs_root);
            if (EFI_ERROR(status) || kernel_file == nullptr) {
                errmsg = OPEN_KERNEL_ERR_FILEOPEN; goto error_out;
            }

            kernel_file_hndl.reset(kernel_file);
        }

        EFI_FILE_INFO *kernel_file_info = get_file_info(kernel_file_hndl.get());
        if (kernel_file_info == nullptr) {
            errmsg = OPEN_KERNEL_ERR_FILEOPEN; goto error_out;
        }

        UINTN kernel_file_size = kernel_file_info->FileSize;
        free_pool(kernel_file_info);

        *kernel_file_p = kernel_file_hndl.release();
        *kernel_file_size_p = kernel_file_size;
        return true;
    }

error_out:
    con_write(L"Error loading kernel: ");
    con_write(errmsg);
    con_write(L".\r\n");
    return false;
}

// Check whether a usable framebuffer exists, copy relevant info into 'fbinfo' if so
// and store the framebuffer size (rounded up to page boundary) into '*fb_size'.
static void check_framebuffer(tosaithe_loader_data *fbinfo, uint64_t *fb_size)
{
    EFI_GRAPHICS_OUTPUT_PROTOCOL *graphics =
            (EFI_GRAPHICS_OUTPUT_PROTOCOL *) locate_protocol(EFI_graphics_output_protocol_guid);

    fbinfo->framebuffer_addr = 0;

    if (graphics == nullptr) {
        return;
    }

    switch(graphics->Mode->Info->PixelFormat) {
    case PixelRedGreenBlueReserved8BitPerColor:
        fbinfo->blue_mask_shift = 16;
        fbinfo->blue_mask_size = 8;
        fbinfo->green_mask_shift = 8;
        fbinfo->green_mask_size = 8;
        fbinfo->red_mask_shift = 0;
        fbinfo->red_mask_size = 8;
        fbinfo->framebuffer_bpp = 32;
        break;
    case PixelBlueGreenRedReserved8BitPerColor:
        fbinfo->blue_mask_shift = 0;
        fbinfo->blue_mask_size = 8;
        fbinfo->green_mask_shift = 8;
        fbinfo->green_mask_size = 8;
        fbinfo->red_mask_shift = 16;
        fbinfo->red_mask_size = 8;
        fbinfo->framebuffer_bpp = 32;
        break;
    case PixelBitMask:
    {
        auto count_shift = [](uint32_t mask) {
            uint8_t shift = 0;
            while ((mask & 1) != 1) {
                shift++;
                mask >>= 1;
            }
            return shift;
        };

        auto count_size = [](uint32_t mask, uint8_t shift) {
            uint8_t size = 0;
            mask >>= shift;
            while ((mask & 1) == 1) {
                size++;
                mask >>= 1;
            }
            return size;
        };

        fbinfo->red_mask_shift = count_shift(graphics->Mode->Info->PixelInformation.RedMask);
        fbinfo->red_mask_size = count_size(graphics->Mode->Info->PixelInformation.RedMask, fbinfo->red_mask_shift);
        fbinfo->green_mask_shift = count_shift(graphics->Mode->Info->PixelInformation.GreenMask);
        fbinfo->green_mask_size = count_size(graphics->Mode->Info->PixelInformation.GreenMask, fbinfo->green_mask_shift);
        fbinfo->blue_mask_shift = count_shift(graphics->Mode->Info->PixelInformation.BlueMask);
        fbinfo->blue_mask_size = count_size(graphics->Mode->Info->PixelInformation.BlueMask, fbinfo->blue_mask_shift);

        auto highest_bit = [](uint32_t mask) {
            if (mask == 0) return uint32_t(0);
            uint32_t bitnum = 31;
            uint32_t bit = uint32_t(1) << 31;
            while ((mask & bit) == 0) {
                bit >>= 1;
                bitnum--;
            }
            return bitnum;
        };

        auto max = [](uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
            uint32_t m = a;
            if (b > m) m = b;
            if (c > m) m = c;
            if (d > m) m = d;
            return d;
        };

        fbinfo->framebuffer_bpp = max(highest_bit(graphics->Mode->Info->PixelInformation.RedMask),
                highest_bit(graphics->Mode->Info->PixelInformation.GreenMask),
                highest_bit(graphics->Mode->Info->PixelInformation.BlueMask),
                highest_bit(graphics->Mode->Info->PixelInformation.ReservedMask));

        break;
    }
    default:
        return; // without setting *fb_size, i.e. framebuffer not available
    }

    fbinfo->framebuffer_addr = graphics->Mode->FrameBufferBase;
    fbinfo->framebuffer_width = graphics->Mode->Info->HorizontalResolution;
    fbinfo->framebuffer_height = graphics->Mode->Info->VerticalResolution;
    fbinfo->framebuffer_pitch = graphics->Mode->Info->PixelsPerScanLine
            * ((fbinfo->framebuffer_bpp + 7) / 8u);

    *fb_size = (((uint64_t)graphics->Mode->FrameBufferSize) + 0xFFFu) / 0x1000u * 0x1000u;
}

// Get a copy of the EFI memory map in an allocated buffer. Returns null on general failure or
// throws std::bad_alloc for out-of-memory.
EFI_MEMORY_DESCRIPTOR *get_efi_memmap(UINTN &memMapSize, UINTN &memMapKey, UINTN &memMapDescrSize, uint32_t &memMapDescrVersion)
{
    EFI_STATUS status = EBS->GetMemoryMap(&memMapSize, nullptr, &memMapKey, &memMapDescrSize, &memMapDescrVersion);
    if (status != EFI_BUFFER_TOO_SMALL) {
        con_write(L"*** Could not retrieve EFI memory map ***\r\n");
        return nullptr;
    }

    efi_unique_ptr<EFI_MEMORY_DESCRIPTOR> efi_memmap_ptr;

    {
        EFI_MEMORY_DESCRIPTOR *efiMemMap = (EFI_MEMORY_DESCRIPTOR *) alloc_pool(memMapSize);

        if (efiMemMap == nullptr) {
            throw std::bad_alloc();
        }

        status = EBS->GetMemoryMap(&memMapSize, efiMemMap, &memMapKey, &memMapDescrSize, &memMapDescrVersion);
        while (status == EFI_BUFFER_TOO_SMALL) {
            // Above allocation may have increased size of memory map, so we keep trying
            free_pool(efiMemMap);
            efiMemMap = (EFI_MEMORY_DESCRIPTOR *) alloc_pool(memMapSize);
            if (efiMemMap == nullptr) {
                throw std::bad_alloc();
            }
            status = EBS->GetMemoryMap(&memMapSize, efiMemMap, &memMapKey, &memMapDescrSize, &memMapDescrVersion);
        }

        efi_memmap_ptr.reset(efiMemMap);
    }

    if (EFI_ERROR(status)) {
        con_write(L"*** Could not retrieve EFI memory map ***\r\n");
        return nullptr;
    }

    return efi_memmap_ptr.release();
}

// Sort entries in the EFI memory map (by address).
void sort_efi_memmap(EFI_MEMORY_DESCRIPTOR *memmap, UINTN memMapSize, UINTN memMapKey,
        UINTN memMapDescrSize)
{
    EFI_MEMORY_DESCRIPTOR *last_ent = (EFI_MEMORY_DESCRIPTOR *)
            ((uintptr_t)memmap + memMapSize - memMapDescrSize);

    // Pan me all you want for writing another bubble sort.
    bool did_bubble;
    do {
        did_bubble = false;

        EFI_MEMORY_DESCRIPTOR *ent = memmap;
        while (ent != last_ent) {
            EFI_MEMORY_DESCRIPTOR *next_ent = (EFI_MEMORY_DESCRIPTOR *)
                    ((uintptr_t)ent + memMapDescrSize);
            if (ent->PhysicalStart > next_ent->PhysicalStart) {
                swap(*ent, *next_ent);
                did_bubble = true;
            }

            ent = next_ent;
        }
    } while (did_bubble);
}

// Load a kernel via the TSBP (ToSaithe Boot Protocol)
EFI_STATUS load_tsbp(EFI_HANDLE ImageHandle, const CHAR16 *exec_path, const CHAR16 *cmdLine)
{
    efi_file_handle kernel_handle;
    UINTN kernel_file_size;
    {
        EFI_FILE_PROTOCOL *kernel_file;
        if (!open_kernel_file(ImageHandle, exec_path, &kernel_file, &kernel_file_size)) {
            return EFI_LOAD_ERROR;
        }
        kernel_handle.reset(kernel_file);
    }

    // Allocate space for kernel file
    // For now we'll load a portion at an arbitrary address. We'll allocate 128kb and read at most
    // that much, for now. We'll read more if needed for program headers. Once we've read program
    // headers, we know which other parts of the file need to be loaded.

    // An ELF file consists of "segments" defined by the Program Headers (PHDRs), and also of named
    // "sections". In theory each section should map to at most one segment (note that for example
    // debug sections typically aren't mapped to any segment and aren't loaded by default). For our
    // purposes here we care only about segments and not about sections, and only about loadable
    // ("PT_LOAD") segments at that.

    // Segments have the following relevant attributes:
    //
    // * virtual address (the address where the segment is supposed to reside in the virtual memory
    //   space, once loaded)
    // * file offset
    // * file size
    // * size in memory
    // * alignment
    // * flags (readable, writable, executable)
    //
    // Size in memory may differ from the file size (by being larger), for example if there is a
    // "bss" section which should be initialised to 0's then it is typically not stored in the
    // file.

    // With Tosaithe boot protocol, we require:
    //
    // * each loadable segment has the same difference between file offset and virtual address
    //   and this difference is positive (virtual address > file offset)
    // * each loadable segment is at least page aligned (where "page" is any valid page size
    //   for the architecture)
    //
    // This vastly simplifies loading as we don't have to worry about loading different parts of
    // file in different places, and don't have to worry about handling access rights for pages
    // which overlap two segments.

    // Try to read in chunks of at least 128kb:
    const UINTN min_read_chunk = 128*1024u;

    efi_page_alloc elf_header_alloc;
    UINTN first_chunk = std::min(min_read_chunk, kernel_file_size);

    elf_header_alloc.allocate((first_chunk + 0xFFFu)/0x1000u);

    UINTN read_amount = first_chunk;
    EFI_STATUS status = kernel_handle.read(&read_amount, (void *)elf_header_alloc.get_ptr());

    if (EFI_ERROR(status)) {
        con_write(L"Error: couldn't read kernel file; ");
        if (status == EFI_NO_MEDIA) {
            con_write(L"status: NO_MEDIA\r\n");
        }
        else if (status == EFI_DEVICE_ERROR) {
            con_write(L"status: DEVICE_ERROR\r\n");
        }
        else if (status == EFI_VOLUME_CORRUPTED) {
            con_write(L"status: VOLUME_CORRUPTED\r\n");
        }
        else if (status == EFI_BUFFER_TOO_SMALL) {
            con_write(L"status: BUFFER_TOO_SMALL\r\n");
        }
        else {
            con_write(L"status not recognized\r\n");
            CHAR16 errcode[3];
            errcode[2] = 0;
            errcode[1] = hexdigit(status & 0xFu);
            errcode[0] = hexdigit((status >> 4) & 0xFu);
            con_write(L"    EFI status: 0x");
            con_write(errcode);
            con_write(L"\r\n");
        }
        return EFI_LOAD_ERROR;
    }

    Elf64_Ehdr *elf_hdr = (Elf64_Ehdr *) elf_header_alloc.get_ptr();

    // check e_ident
    if (std::char_traits<char>::compare((const char *)elf_hdr->e_ident, ELFMAGIC, 4) != 0) {
        con_write(L"Error: incorrect ELF header, not a valid ELF file\r\n");
        return EFI_LOAD_ERROR;
    }

    unsigned elf_class = elf_hdr->e_ident[EI_CLASS];
    static_assert(sizeof(void*) == 4 || sizeof(void*) == 8, "pointer size must be 4/8 bytes");
    if ((sizeof(void*) == 4 && elf_class != ELFCLASS32) || (sizeof(void*) == 8 && elf_class != ELFCLASS64)) {
        con_write(L"Wrong ELF class (64/32 bit)\r\n");
        return EFI_LOAD_ERROR;
    }

    unsigned elf_version = elf_hdr->e_ident[EI_VERSION];
    if (elf_version != EV_CURRENT) {
        con_write(L"Unsupported ELF version\r\n");
        return EFI_LOAD_ERROR;
    }

    unsigned elf_data_enc = elf_hdr->e_ident[EI_DATA];
    if (elf_data_enc != ELFDATA2LSB /* && elf_data_enc != ELFDATA2MSB */) {
        con_write(L"Unsupported ELF data encoding\r\n");
        // TODO support non-native encoding?
        return EFI_LOAD_ERROR;
    }

    if (elf_hdr->e_machine != EM_X86_64) {
        con_write(L"Wrong or unsupported ELF machine type\r\n");
        return EFI_LOAD_ERROR;
    }

    if (elf_hdr->e_phnum == PH_XNUM) {
        con_write(L"Too many ELF program headers\r\n");
        return EFI_LOAD_ERROR;
    }

    // check program headers, make sure we have allocated correctly
    uintptr_t elf_ph_off = elf_hdr->e_phoff;
    uint16_t elf_ph_ent_size = elf_hdr->e_phentsize;
    uint16_t elf_ph_ent_num = elf_hdr->e_phnum;

    // sanity check program headers
    if (elf_ph_off >= kernel_file_size
            || ((kernel_file_size - elf_ph_off) / elf_ph_ent_size) < elf_ph_ent_num) {
        con_write(L"Error: bad ELF structure\r\n");
        return EFI_LOAD_ERROR;
    }

    // We want to make sure we have access to all the program headers.
    // Do we need to expand the chunk read? (Typically we won't, the program headers tend to follow
    // immediately after the ELF header. But, we'll allow for the other case).

    uintptr_t kernel_current_limit = elf_header_alloc.get_ptr() + first_chunk;

    uintptr_t elf_ph_end = elf_ph_off + elf_ph_ent_size * elf_ph_ent_num;
    if (elf_ph_end > first_chunk) {
        read_amount = std::max(elf_ph_end - first_chunk, min_read_chunk);
        read_amount = std::min(read_amount, kernel_file_size - first_chunk);

        // Extend allocation. We can assume current kernel limit is on a page boundary.
        UINTN alloc_pages = (read_amount + 0xFFFu) / 0x1000u;
        status = EBS->AllocatePages(AllocateAddress, EfiLoaderCode, alloc_pages, &kernel_current_limit);
        if (EFI_ERROR(status)) {
            // TODO relocate.
            throw std::bad_alloc();
        }

        elf_header_alloc.rezone(elf_header_alloc.get_ptr(), elf_header_alloc.page_count() + alloc_pages);

        status = kernel_handle.read(&read_amount, (void *)(elf_header_alloc.get_ptr() + first_chunk));
        if (EFI_ERROR(status)) {
            con_write(L"Error: couldn't read kernel file\r\n");
            return EFI_LOAD_ERROR;
        }

        kernel_current_limit += read_amount;
        first_chunk += read_amount;
    }

    // Now we want to check:
    // * the total range of memory required (lowest-highest virtual address)
    // * whether the segments are contiguous, i.e. file-vaddr offset is the
    //   same for all segments

    bool found_loadable = false;
    uintptr_t file_voffs = 0;
    uintptr_t lowest_vaddr = 0;
    uintptr_t highest_vaddr = 0;
    uintptr_t seg_alignment = 0;

    struct bss_area {
        uintptr_t begin_offset;
        size_t size;
    };

    // bss areas need to be cleared before entry to kernel
    std::vector<bss_area> bss_areas;

    unsigned num_loadable_segs = 0;

    // Find the total virtual address span of all segments (lowest_vaddr, highest_vaddr)
    for (uint16_t i = 0; i < elf_ph_ent_num; i++) {
        uintptr_t ph_addr = i * elf_ph_ent_size + elf_ph_off + elf_header_alloc.get_ptr();
        Elf64_Phdr phdr;
        std::memcpy(&phdr, (void *)ph_addr, sizeof(phdr));
        if (phdr.p_type == PT_LOAD) {
            num_loadable_segs++; // XXX needed?

            // Do some consistency checks while we are at it:
            auto max_addr = std::numeric_limits<decltype(phdr.p_vaddr)>::max();
            if (phdr.p_vaddr > max_addr - phdr.p_memsz) {
                // size is too large, given the starting address
                con_write(L"Error: bad ELF structure\r\n");
                return EFI_LOAD_ERROR;
            }

            if (phdr.p_vaddr < phdr.p_offset) {
                con_write(L"Error: unsupported ELF structure\r\n");
                return EFI_LOAD_ERROR;
            }

            // Valid page sizes: 4kb, 2mb, 1gb
            if (phdr.p_align != 0x1000u && phdr.p_align != 0x200000 && phdr.p_align != 0x40000000u) {
                con_write(L"Error: unsupported ELF structure\r\n");
                return EFI_LOAD_ERROR;
            }

            if (phdr.p_vaddr & (phdr.p_align - 1)) {
                con_write(L"Error: unsupported ELF structure\r\n");
                return EFI_LOAD_ERROR;
            }

            uintptr_t voffs = phdr.p_vaddr - phdr.p_offset;

            auto vaddr = phdr.p_vaddr;
            auto vaddr_high = vaddr + phdr.p_memsz;

            if (!found_loadable) {
                file_voffs = voffs;
                lowest_vaddr = vaddr;
                highest_vaddr = vaddr_high;
                seg_alignment = phdr.p_align;
                found_loadable = true;
            }
            else {
                if (file_voffs != voffs) {
                    con_write(L"Error: unsupported ELF structure\r\n");
                    return EFI_LOAD_ERROR;
                }
                if (phdr.p_align != seg_alignment) {
                    con_write(L"Error: unsupported ELF structure\r\n");
                    return EFI_LOAD_ERROR;
                }
                lowest_vaddr = std::min(lowest_vaddr, vaddr);
                highest_vaddr = std::max(highest_vaddr, vaddr_high);
            }

            if (phdr.p_memsz > phdr.p_filesz) {
                bss_areas.push_back(bss_area { phdr.p_vaddr + phdr.p_filesz,
                    phdr.p_memsz - phdr.p_filesz });
            }
        }
    }

    if (!found_loadable) {
        con_write(L"Error: no loadable segments in ELF\r\n");
        return EFI_LOAD_ERROR;
    }

    if (lowest_vaddr < TOP_MINUS_2GB) {
        con_write(L"Error: unsupported ELF structure\r\n");
    }

    // Allocate space for kernel; we need to ensure sufficient alignment

    UINTN kernel_pages = (highest_vaddr - lowest_vaddr + 0xFFFu) / 0x1000u;

    efi_page_alloc kernel_alloc;
    kernel_alloc.allocate(kernel_pages);

    // FIXME check alignment, Re-locate if necessary:
    if ((kernel_alloc.get_ptr() & (seg_alignment - 1)) != 0) {
        con_write(L"Error: accidentally allocated misaligned kernel block FIXME\r\n");
        return EFI_LOAD_ERROR;
        // First try to allocate extra at the start:
        // FIXME
        // If that fails, try at the end:
        // FIXME
        // Finally, try to allocate a larger region:
        // FIXME

        //        status = EBS->AllocatePages(AllocateAddress, EfiLoaderCode, alloc_pages, &alloc_from);
    }


    // Actually load kernel (read from disk into memory).

    // TODO if we have first_chunk containing a portion of a segment, copy from the
    // header allocation instead of re-reading.

    tosaithe_entry_header *ts_entry_header = nullptr;

    for (uint16_t i = 0; i < elf_ph_ent_num; i++) {
        uintptr_t ph_addr = i * elf_ph_ent_size + elf_ph_off + elf_header_alloc.get_ptr();
        Elf64_Phdr phdr;
        std::memcpy(&phdr, (void *)ph_addr, sizeof(phdr));
        if (phdr.p_type == PT_LOAD) {
            uintptr_t addr_offs = phdr.p_vaddr - lowest_vaddr;
            status = kernel_handle.seek(phdr.p_offset);
            if (!EFI_ERROR(status)) {
                status = kernel_handle.read(&read_amount, (void *)(kernel_alloc.get_ptr() + addr_offs));
            }
            if (EFI_ERROR(status)) {
                con_write(L"Error: couldn't read kernel file\r\n");
                return EFI_LOAD_ERROR;
            }

            if (ts_entry_header == nullptr) {
                ts_entry_header = (tosaithe_entry_header *)(kernel_alloc.get_ptr() + addr_offs);
            }
        }
    }

    // Check signature
    if (std::memcmp(&ts_entry_header->signature, "TSBP", 4) != 0) {
        con_write(L"Missing Tosaithe boot protocol signature\r\n");
        return EFI_LOAD_ERROR;
    }

    // TODO check suitable version

    uint64_t kern_stack_top = ts_entry_header->stack_ptr;

    typedef void (*tsbp_entry_t)(tosaithe_loader_data *);
    tsbp_entry_t kern_entry = (tsbp_entry_t)elf_hdr->e_entry;


    // Zero out bss (parts of segments which have no corresponding file backing)
    for (bss_area bss : bss_areas) {
        memset((void *)(kernel_alloc.get_ptr() + bss.begin_offset - lowest_vaddr), 0, bss.size);
    }


    // Get the current EFI memory map

    UINTN memMapSize = 0;
    UINTN memMapKey = 0;
    UINTN memMapDescrSize = 0;
    uint32_t memMapDescrVersion = 0;

    efi_unique_ptr<EFI_MEMORY_DESCRIPTOR> efi_memmap_ptr {
            get_efi_memmap(memMapSize, memMapKey, memMapDescrSize, memMapDescrVersion)
        };

    if (efi_memmap_ptr == nullptr) {
        return EFI_LOAD_ERROR;
    }

    sort_efi_memmap(efi_memmap_ptr.get(), memMapSize, memMapKey, memMapDescrSize);


    // Allocate memory for page tables

    struct PDE {
        uint64_t entry;
    };

    // Paging
    //
    // With standard 4-level paging, there are 48 bits of linear address (bits 0-47). Addresses in
    // proper canonical form will duplicate bit 47 up through to bit 63, effectively dividing the
    // address space into a positive (47-63 are 0) and negative (47-63 are 1).
    //
    //                        0 <-- lowest "low half" address
    //         0x7FFF FFFF FFFF <-- highest "low half" address
    //        -----------------------  (+ve/-ve split)
    //    0xFFFF 8000 0000 0000 <-- lowest "high half" address
    //    0xFFFF FFFF 8000 0000 <-- corresponds to (top - 2GB)
    //    0xFFFF FFFF FFFF FFFF <-- top
    //
    // It's quite handy to have all of physical memory mapped into the high half address as well
    // as to have an identity mapping set up in the low half, so that's what TSBP will do. However,
    // we also need to map the kernel from its logical address to its loaded address. Typically the
    // kernel address will be in the (top - 2GB) range as that is efficient (addresses in that
    // range can be accessed via instructions encoded with a 32-bit sign-extended address) and
    // allows the lower half of the address range to be dedicated to user space.
    //
    // - We want to use huge (1GB) pages for most of the mapping but:
    //   - not if they would partially span a page range that isn't fully cacheable
    //   - not for the first 1MB of address, since that almost definitely should be covered by
    //     above cases we'll play it safe. This implies the entire first 1GB must be covered by <1GB
    //     pages.
    // - We can share mappings between low- and high- half if it doesn't overlap kernel mapping
    // - For the page table pages, we'll allocate the pages in chunks and use the chunk from start
    //   to end before allocating another chunk.

    efi_page_alloc page_tables_alloc_pool;
    page_tables_alloc_pool.allocate(8);
    void * alloc_pool_next = (void *)page_tables_alloc_pool.get_ptr();

    auto take_page = [&]() -> void * {
        uintptr_t ap_end = (uintptr_t)page_tables_alloc_pool.get_ptr() + page_tables_alloc_pool.page_count() * PAGE4KB;
        if (alloc_pool_next == (void *)ap_end) {
            // TODO try to extend previous allocation first
            page_tables_alloc_pool.release(); // FIXME this leaks
            page_tables_alloc_pool.allocate(8);
            alloc_pool_next = (void *)page_tables_alloc_pool.get_ptr();
        }

        void *r = alloc_pool_next;
        alloc_pool_next = (void *)((uintptr_t)alloc_pool_next + PAGE4KB);
        memset(r, 0, PAGE4KB);
        return r;
    };

    PDE *page_tables = (PDE *)take_page();


    auto do_mapping = [&](uintptr_t virt_addr, uintptr_t phys_addr_beg, uintptr_t phys_addr_end) {
        // FIXME don't assume availability of 1GB pages

        uintptr_t virt_phys_diff = virt_addr - phys_addr_beg;
        bool use_1gb_pages = (virt_phys_diff & (PAGE1GB - 1)) == 0;
        bool use_2mb_pages = (virt_phys_diff & (PAGE2MB - 1)) == 0;

        // Now we have a range, how big can we make the pages?
        if (use_1gb_pages && (phys_addr_beg & (PAGE1GB - 1)) == 0 && (phys_addr_end - phys_addr_beg) >= PAGE1GB) {
            // 1GB pages!

            allocate_1gb_pages:

            // allocate 2nd level page table if needed
            auto &pde_ent = page_tables[(virt_addr >> 39) & 0x1FF];
            if ((pde_ent.entry & 0x1) == 0) {
                // allocate:
                auto pdpt_page = (uintptr_t)take_page();
                pde_ent.entry = pdpt_page | 3 /* present/read+write */;
            }

            // from pde_ent find the address of the next level:
            uintptr_t pdpt_addr = pde_ent.entry & 0x000FFFFFFFFFF000u; // 52 bits physical
            // (we only have 48 bits linear address so an address larger than that wouldn't work properly -
            //  shouldn't really happen though)
            PDE *pdpt = (PDE *)pdpt_addr;

            // set entrie(s) for 1GB page(s)
            int pdpt_ind = (virt_addr >> 30) & 0x1FF;
            do {
                pdpt[pdpt_ind] = {phys_addr_beg | 0x80 | 3 /* page size, present/read+write */ };
                phys_addr_beg += PAGE1GB;
                virt_addr += PAGE1GB;
                if ((phys_addr_end - phys_addr_beg) < PAGE1GB) {
                    break;
                }
            } while (++pdpt_ind < 512);

            if (use_1gb_pages && (phys_addr_end - phys_addr_beg) >= PAGE1GB) {
                goto allocate_1gb_pages;
            }
        }

        if (use_2mb_pages && (phys_addr_beg & (PAGE2MB - 1)) == 0 && (phys_addr_end - phys_addr_beg) >= PAGE2MB) {
            // 2MB pages

            allocate_2mb_pages:

            // allocate 2nd level page table if needed
            auto &pde_ent = page_tables[(virt_addr >> 39) & 0x1FF];
            if ((pde_ent.entry & 0x1) == 0) {
                // allocate:
                auto pdpt_page = (uintptr_t)take_page();
                pde_ent.entry = pdpt_page | 3 /* present/read+write */;
            }

            // from pde_ent find the address of the next level:
            uintptr_t pdpt_addr = pde_ent.entry & 0x000FFFFFFFFFF000u; // 52 bits physical
            // (we only have 48 bits linear address so an address larger than that wouldn't work properly -
            //  shouldn't really happen though)
            PDE *pdpt = (PDE *)pdpt_addr;

            // allocate 3rd level page table if needed

            auto &pdpt_ent = pdpt[(virt_addr >> 30) & 0x1FF];
            if ((pdpt_ent.entry & 0x1) == 0) {
                if ((pdpt_ent.entry & 0x80) != 0) {
                    // split large page
                    uintptr_t orig_phys = pdpt_ent.entry & 0x000FFFFFFFFFF000u;
                    auto page_for_split = (uintptr_t)take_page();
                    pdpt_ent.entry = page_for_split | 3 /* present/read+write */;
                    PDE *split_page = (PDE *)page_for_split;
                    // re-create original mapping, will be partially overwritten shortly
                    for (int i = 0; i < 512; i++) {
                        split_page[i] = { orig_phys | 0x80 | 3 };
                        orig_phys += PAGE2MB;
                    }
                }
                else {
                    // allocate:
                    auto pdpt_page = (uintptr_t)take_page();
                    pdpt_ent.entry = pdpt_page | 3 /* present/read+write */;
                }
            }

            // from pde_ent find the address of the next level:
            uintptr_t pd_addr = pdpt_ent.entry & 0x000FFFFFFFFFF000u; // 52 bits physical
            // (we only have 48 bits linear address so an address larger than that wouldn't work properly -
            //  shouldn't really happen though)
            PDE *pd = (PDE *)pd_addr;


            // set entrie(s) for 2MB page(s)
            int pd_ind = (virt_addr >> 21) & 0x1FF;
            do {
                pd[pd_ind] = {phys_addr_beg | 0x80 | 3 /* page size, present/read+write */ };
                phys_addr_beg += PAGE2MB;
                virt_addr += PAGE2MB;
                if ((phys_addr_end - phys_addr_beg) < PAGE2MB) {
                    break;
                }
            } while (++pd_ind < 512);

            if (use_1gb_pages && (phys_addr_end - phys_addr_beg) >= PAGE1GB) {
                goto allocate_1gb_pages;
            }
            if ((phys_addr_end - phys_addr_beg) >= PAGE2MB) {
                goto allocate_2mb_pages;
            }
        }

        if (phys_addr_beg != phys_addr_end) {
            // 4kb pages

            allocate_4kb_pages:

            // allocate 2nd level page table if needed
            auto &pde_ent = page_tables[(virt_addr >> 39) & 0x1FF];
            if ((pde_ent.entry & 0x1) == 0) {
                // allocate:
                auto pdpt_page = (uintptr_t)take_page();
                pde_ent.entry = pdpt_page | 3 /* present/read+write */;
            }

            // from pde_ent find the address of the next level:
            uintptr_t pdpt_addr = pde_ent.entry & 0x000FFFFFFFFFF000u; // 52 bits physical
            // (we only have 48 bits linear address so an address larger than that wouldn't work properly -
            //  shouldn't really happen though)
            PDE *pdpt = (PDE *)pdpt_addr;

            // allocate 3rd level page table (PD) if needed

            auto &pdpt_ent = pdpt[(virt_addr >> 30) & 0x1FF];
            if ((pdpt_ent.entry & 0x1) == 0) {
                if ((pdpt_ent.entry & 0x80) != 0) {
                    // split large page
                    uintptr_t orig_phys = pdpt_ent.entry & 0x000FFFFFFFFFF000u;
                    auto page_for_split = (uintptr_t)take_page();
                    pdpt_ent.entry = page_for_split | 3 /* present/read+write */;
                    PDE *split_page = (PDE *)page_for_split;
                    // re-create original mapping, will be partially overwritten shortly
                    for (int i = 0; i < 512; i++) {
                        split_page[i] = { orig_phys | 0x80 | 3 };
                        orig_phys += PAGE2MB;
                    }
                }
                else {
                    // allocate:
                    auto pdpt_page = (uintptr_t)take_page();
                    pdpt_ent.entry = pdpt_page | 3 /* present/read+write */;
                }
            }

            // from pdpt_ent find the address of the next level:
            uintptr_t pd_addr = pdpt_ent.entry & 0x000FFFFFFFFFF000u; // 52 bits physical
            // (we only have 48 bits linear address so an address larger than that wouldn't work properly -
            //  shouldn't really happen though)
            PDE *pd = (PDE *)pd_addr;

            // allocate 4th level page table (PT) if needed

            auto &pd_ent = pd[(virt_addr >> 21) & 0x1FF];
            if ((pd_ent.entry & 0x1) == 0) {
                if ((pd_ent.entry & 0x80) != 0) {
                    // split large page
                    uintptr_t orig_phys = pd_ent.entry & 0x000FFFFFFFFFF000u;
                    auto page_for_split = (uintptr_t)take_page();
                    pd_ent.entry = page_for_split | 3 /* present/read+write */;
                    PDE *split_page = (PDE *)page_for_split;
                    // re-create original mapping, will be partially overwritten shortly
                    for (int i = 0; i < 512; i++) {
                        split_page[i] = { orig_phys | 0x80 | 3 };
                        orig_phys += PAGE2MB;
                    }
                }
                else {
                    // allocate:
                    auto pt_page = (uintptr_t)take_page();
                    pd_ent.entry = pt_page | 3 /* present/read+write */;
                }
            }

            // from pd_ent find the address of the page table:
            uintptr_t pt_addr = pd_ent.entry & 0x000FFFFFFFFFF000u; // 52 bits physical
            // (we only have 48 bits linear address so an address larger than that wouldn't work properly -
            //  shouldn't really happen though)
            PDE *pt = (PDE *)pt_addr;

            // set entrie(s) for 4kb page(s)
            int pt_ind = (virt_addr >> 12) & 0x1FF;
            do {
                pt[pt_ind] = {phys_addr_beg | 3 /* present/read+write */ };
                phys_addr_beg += PAGE4KB;
                virt_addr += PAGE4KB;
                if (phys_addr_end == phys_addr_beg) {
                    break;
                }
            } while (++pt_ind < 512);

            if (use_1gb_pages && (phys_addr_beg & (PAGE1GB - 1)) == 0 && (phys_addr_end - phys_addr_beg) >= PAGE1GB) {
                goto allocate_1gb_pages;
            }
            if (use_2mb_pages && (phys_addr_end - phys_addr_beg) >= PAGE2MB) {
                goto allocate_2mb_pages;
            }
            if (phys_addr_beg != phys_addr_end) {
                goto allocate_4kb_pages;
            }
        }
    };

    // TODO make sure we always split first 1MB(?) into little pages


    // Map all regions from the EFI memory map.
    // Note that this will exclude framebuffer, Local APIC / IO APIC, probably any device mapping
    // that isn't specific to the system.

    EFI_MEMORY_DESCRIPTOR *mmdesc = efi_memmap_ptr.get();
    EFI_MEMORY_DESCRIPTOR *mmdesc_end = (EFI_MEMORY_DESCRIPTOR *)((uintptr_t)mmdesc + memMapSize);

    auto next_mmdesc_from = [&](EFI_MEMORY_DESCRIPTOR *mmdesc) {
        return (EFI_MEMORY_DESCRIPTOR *)((uintptr_t)mmdesc + memMapDescrSize);
    };

    do {
        auto mmdesc_phys_beg = mmdesc->PhysicalStart;
        auto mmdesc_phys_end = mmdesc->PhysicalStart + mmdesc->NumberOfPages * 4096u;

        EFI_MEMORY_DESCRIPTOR *next_mmdesc = next_mmdesc_from(mmdesc);
        while (next_mmdesc != mmdesc_end) {
            if (next_mmdesc->PhysicalStart != mmdesc_phys_end) {
                break;
            }

            // TODO maybe can be looser with this check
            if (next_mmdesc->Attribute != mmdesc->Attribute) {
                break;
            }

            // extend end to this next descriptor's end:
            mmdesc_phys_end = next_mmdesc->PhysicalStart + next_mmdesc->NumberOfPages * 4096u;

            next_mmdesc = next_mmdesc_from(next_mmdesc);
        }

        // XXX need to set caching attributes correctly on pages
        do_mapping(mmdesc_phys_beg, mmdesc_phys_beg, mmdesc_phys_end);

        // Within the 1st 4GB, map everything (even if not in the memory map). This will encompass
        // the LAPIC and IOAPIC for example.
        if (mmdesc_phys_end < 4*PAGE1GB) {
            if (next_mmdesc != mmdesc_end && next_mmdesc->PhysicalStart != mmdesc_phys_end) {
                uintptr_t end_map_range = std::min(next_mmdesc->PhysicalStart, 4*PAGE1GB);
                do_mapping(mmdesc_phys_end, mmdesc_phys_end, end_map_range);
            }
            else {
                do_mapping(mmdesc_phys_end, mmdesc_phys_end, 4*PAGE1GB);
            }
        }

        mmdesc = next_mmdesc;
    } while (mmdesc != mmdesc_end);


    // Set up loader_data

    tosaithe_loader_data loader_data;
    static_assert(sizeof(loader_data.signature == 4));
    std::memcpy(&loader_data.signature, "TSLD", 4);

    loader_data.version = 0;
    loader_data.flags = 0;
    loader_data.cmdline = nullptr; // TODO
    // .memmap/.memmap_entries set below after construction of the map

    // Framebuffer setup

    uint64_t fb_size = 0;
    check_framebuffer(&loader_data, &fb_size);

    if (fb_size != 0) {
        // Need to map the framebuffer in
        uintptr_t fb_addr = loader_data.framebuffer_addr;
        do_mapping(fb_addr, fb_addr, fb_addr + fb_size);
    }

    // Now map low half into high half:
    for (int i = 0; i < 256; i++) {
        page_tables[i+256] = page_tables[i];
    }

    // And finally map the kernel:
    do_mapping(lowest_vaddr, kernel_alloc.get_ptr(), kernel_alloc.get_ptr() + kernel_alloc.page_count() * PAGE4KB);


    // Build tosaithe protocol memory map from EFI memory map

    // This is a little tricky. Since we keep the loader memory map in allocated memory, the
    // map may change between when we retrieve it and when we convert it to loader format
    // (because building the loader-format map may allocate memory).
    // We'll allocate space first to try to avoid this - enough for 64 entries. If necessary we
    // can loop back and re-build the map from scratch.

    // Note: debugging output is risky from this point. Writing to EFI console may affect memory
    // map key.

    tosaithe_memmap tsbp_memmap;
    tsbp_memmap.allocate(64); // hopefully big enough

    retrieve_efi_memmap:

    efi_memmap_ptr.reset(); // free existing map before querying new one!
    efi_memmap_ptr.reset(get_efi_memmap(memMapSize, memMapKey, memMapDescrSize, memMapDescrVersion));

    if (efi_memmap_ptr == nullptr) {
        return EFI_LOAD_ERROR;
    }

    retrieve_efi_memmap_2:

    // Copy entries from EFI memory map to our boot protocol map
    auto *efi_mem_iter = efi_memmap_ptr.get();
    auto *efi_mem_end = (EFI_MEMORY_DESCRIPTOR *)((char *)efi_memmap_ptr.get() + memMapSize);
    while (efi_mem_iter < efi_mem_end) {

        tsbp_mmap_type st_type;

        switch (efi_mem_iter->Type) {
        case EfiReservedMemoryType:
            st_type = tsbp_mmap_type::RESERVED;
            break;
        case EfiLoaderCode:
        case EfiLoaderData:
        case EfiBootServicesCode:
        case EfiBootServicesData:
            st_type = tsbp_mmap_type::BOOTLOADER_RECLAIMABLE;
            break;
        case EfiRuntimeServicesCode:
        case EfiRuntimeServicesData:
            st_type = tsbp_mmap_type::RESERVED;
            break;
        case EfiConventionalMemory:
            st_type = tsbp_mmap_type::USABLE;
            break;
        case EfiUnusableMemory:
            st_type = tsbp_mmap_type::BAD_MEMORY;
            break;
        case EfiACPIReclaimMemory:
            st_type = tsbp_mmap_type::ACPI_RECLAIMABLE;
            break;
        case EfiACPIMemoryNVS:
            st_type = tsbp_mmap_type::ACPI_NVS;
            break;
        case EfiMemoryMappedIO:
        case EfiMemoryMappedIOPortSpace:
        case EfiPalCode:
            st_type = tsbp_mmap_type::RESERVED;
            break;
        case EfiPersistentMemory:
            // Not really clear how this should be handled.
            st_type = tsbp_mmap_type::RESERVED;
            break;
        default:
            st_type = tsbp_mmap_type::RESERVED;
        }

        tsbp_memmap.add_entry(st_type, efi_mem_iter->PhysicalStart,
                efi_mem_iter->NumberOfPages * 0x1000u, 0 /* FIXME */);
        efi_mem_iter = (EFI_MEMORY_DESCRIPTOR *)((char *)efi_mem_iter + memMapDescrSize);
    }

    // We won't release the map here, even though we no longer need it, since that could affect
    // the map and potentially our ability to successfully call ExitBootServices().
    // -> Don't: efiMemMapPtr.reset();

    // Insert memory-map entries for kernel
    tsbp_memmap.insert_entry(tsbp_mmap_type::KERNEL_AND_MODULES, kernel_alloc.get_ptr(),
            kernel_alloc.page_count() * PAGE4KB, 0 /* FIXME */);

    if (fb_size != 0) {
        tsbp_memmap.insert_entry(tsbp_mmap_type::FRAMEBUFFER, loader_data.framebuffer_addr, fb_size, 0 /* FIXME */);
    }

    tsbp_memmap.sort();

    loader_data.memmap = tsbp_memmap.get();
    loader_data.memmap_entries = tsbp_memmap.get_size();

    // TODO command line
    // TODO modules

    // Enable paging (4-level)

    // IA32_EFER = 0xC0000080
    // bit 0 enables SYSCALL/SYSRET [0x1]
    // bit 8 = IA-32e mode enable  [0x100]
    // bit 11 = enable NX bit (no-execute)  [0x800]

    // We can't change the paging mode once while paging is enabled, and we can't disable paging
    // while in long mode. We'd need to transition to 32-bit mode to disable paging, sigh.
    // We'll put that on the TODO list. For now, since we currently only handle 4-level paging,
    // we need to make sure 5-level paging isn't enabled:

    uint64_t cr4flags;

    asm volatile (
            "movq %%cr4, %%rax"
            : "=a"(cr4flags)
    );

    if (cr4flags & 0x1000) {
        con_write(L"Error: LA57 was enabled by firmware\r\n");  // TODO
        return EFI_LOAD_ERROR;
    }

    // Exit boot services: there is no going back from here...
    // Well, actually, it can fail if the memory map has become invalid. In that case we need to
    // go back and build the map again.
    if (EBS->ExitBootServices(ImageHandle, memMapKey) == EFI_INVALID_PARAMETER) {
        tsbp_memmap.clear();

        status = EBS->GetMemoryMap(&memMapSize, efi_memmap_ptr.get(), &memMapKey, &memMapDescrSize, &memMapDescrVersion);
        if (EFI_ERROR(status)) {
            if (status == EFI_BUFFER_TOO_SMALL) {
                // If the buffer is too small, we can resize it
                goto retrieve_efi_memmap;
            }
            con_write(L"*** Could not retrieve EFI memory map ***\r\n");
            return EFI_LOAD_ERROR;
        }

        // we've already got the EFI memory map now, so skip that step and just rebuild the memory map:
        goto retrieve_efi_memmap_2;
    }

    // Now, put our page tables in place:

    asm volatile (
            "cli\n"

            // make sure paging is disabled, otherwise we can't set PAE/LA57
            //"movq %%cr0, %%rax\n"
            //"andl $0x7FFFFFFF, %%eax\n"
            //"movq %%rax, %%cr0\n"

            // put our own page tables in place
            "movq %0, %%rax\n"
            "movq %%rax, %%cr3\n"

            //"movl $0xC0000080, %%ecx\n"
            //"rdmsr\n"
            //"orl $0x811, %%ecx\n"
            //"wrmsr\n"

            //"movq %%cr4, %%rax\n"
            //"orl $0x20, %%eax\n"   // set bit 5, PAE
            //"andl $0xFFFFEFFF, %%eax\n"  // clear bit 12, LA57
            //"movq %%rax, %%cr4\n"

            // Now (re-)enable paging
            //"movq %%cr0, %%rax\n"
            //"orl $0x80000000, %%eax\n"
            //"movq %%rax, %%cr0\n"

            :
            : "rm"(page_tables)
            : "eax", "ecx", "edx"
    );

    // Load GDT, jump into kernel and switch stack:

    // Argument to LGDT instruction will be this format:
    struct LoadGDT64_struct {
        uint16_t size;
        DT_entry *base; /* linear(!) base address */
    } __attribute__((packed));

    LoadGDT64_struct gdt_desc { uint16_t(sizeof(GDT_table) - 1), GDT_table };

        asm volatile (
                    "lgdt %0\n"

                // Note that "iretq" in long mode pops all of flags, CS:RIP and SS:RSP.
                // What we're trying to accomplish here is basically a far jump - something that turns
                // out to be pretty tricky in long mode. But handily, this will load SS:RSP at the
                // same time.

                    "pushq %[dsseg]\n" // SS
                    "pushq %1\n"        // RSP
                    "pushfq\n"
                    "pushq %[csseg]\n" // CS

                    // rather than push the target directly, load it relative to RIP. This prevents issues
                    // in the case that we are loaded above 2GB when the push'd value will be sign extended.
                    // so, not this: "pushq $long_jmp_after_gdt_load\n"
                    "leaq long_jmp_after_gdt_load(%%rip), %%rax\n"
                    "pushq %%rax\n" // RIP
                    "iretq\n"       // returns to following instruction:

                // After this point we are on a new stack. The input operands we access must not be memory,
                // since they could be stack-relative addresses which are no longer valid. Fortunately
                // the only thing we really need now is the target address (in a register).

                "long_jmp_after_gdt_load:\n"
                    "movl %[dsseg], %%eax\n"
                    "movl %%eax, %%ds\n"
                    "pushq $0x0\n"  // invalid return address
                    "jmpq %A2"

                :
                : "m"(gdt_desc), "rm"(kern_stack_top), "r"(kern_entry), "D"(&loader_data),
                  [csseg] "i"(TOSAITHE_CS_SEG), [dsseg] "i"(TOSAITHE_DS_SEG)
                : "rax"
        );

    __builtin_unreachable();
}
