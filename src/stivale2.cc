#include <algorithm>
#include <string>
#include <memory>
#include <new>

#include <elf.h>

#include "uefi.h"
#include "uefi-media-file.h"
#include "uefi-loadedimage.h"
#include "stivale2.h"

#include "tosaithe-util.h"

extern EFI_BOOT_SERVICES *EBS;
extern EFI_SYSTEM_TABLE *EST;

// Class to manage building a Stivale2 memory map structure
class tosaithe_stivale2_memmap {
    stivale2_memmap_info *st2_memmap = nullptr;
    uint32_t capacity = 0;

    bool increase_capacity() noexcept
    {
        uint32_t newcapacity = capacity + 6; // bump capacity by arbitrary amount
        uint32_t req_size = sizeof(stivale2_memmap_info)
                + sizeof(stivale2_mmap_entry) * newcapacity;
        stivale2_memmap_info *newmap = (stivale2_memmap_info *) alloc_pool(req_size);
        if (newmap == nullptr) {
            return false;
        }

        // Copy map from old to new storage
        auto entries = st2_memmap->entries;
        new(newmap) stivale2_memmap_info(*st2_memmap);
        for (uint32_t i = 0; i < entries; i++) {
            new(&newmap->memmap[i]) stivale2_mmap_entry(st2_memmap->memmap[i]);
        }

        free_pool(st2_memmap);
        st2_memmap = newmap;
        capacity = newcapacity;

        return true;
    }

public:
    bool allocate(uint32_t capacity_p) noexcept
    {
        uint32_t req_size = sizeof(stivale2_memmap_info)
                + sizeof(stivale2_mmap_entry) * capacity_p;
        st2_memmap = (stivale2_memmap_info *) alloc_pool(req_size);
        if (st2_memmap == nullptr) {
            return false;
        }
        new(st2_memmap) stivale2_memmap_info();
        st2_memmap->tag.identifier = STIVALE2_LT_MMAP_TAGID;
        st2_memmap->tag.next = nullptr;
        st2_memmap->entries = 0;
        capacity = capacity_p;
        return true;
    }

    bool add_entry(stivale2_mmap_type type_p, uint64_t physaddr, uint64_t length) noexcept
    {
        auto entries = st2_memmap->entries;

        if (st2_memmap->entries == capacity) {
            if (!increase_capacity()) {
                return false;
            }
        }

        new(&st2_memmap->memmap[entries]) stivale2_mmap_entry();
        st2_memmap->memmap[entries].type = type_p;
        st2_memmap->memmap[entries].base = physaddr;
        st2_memmap->memmap[entries].length = length;
        st2_memmap->memmap[entries].unused = 0;
        st2_memmap->entries++;

        return true;
    }

    // Insert an entry, which should be making use of available space only.
    // On failure, returns false; in that case integrity of the map is no longer guaranteed.
    // On success returns true: beware, map may require sorting
    bool insert_entry(stivale2_mmap_type type_p, uint64_t physaddr, uint64_t length) noexcept
    {
        auto &entries = st2_memmap->entries;

        uint64_t physend = physaddr + length;

        for (uint32_t i = 0; i < entries; i++) {
            uint64_t ent_base = st2_memmap->memmap[i].base;
            uint64_t ent_len = st2_memmap->memmap[i].length;
            uint64_t ent_end = ent_base + ent_len;

            if (ent_base >= physaddr && ent_end <= physend) {
                // complete overlap; remove this entry by moving the last entry into its place
                st2_memmap->memmap[i] = st2_memmap->memmap[--entries];
            }
            else if (ent_end > physaddr && physend > ent_base) {
                // partial overlap, trim or possibly split
                if (physaddr <= ent_base) {
                    // trim start
                    ent_len -= (physend - ent_base);
                    ent_base = physend;
                    st2_memmap->memmap[i].base = ent_base;
                    st2_memmap->memmap[i].length = ent_len;
                }
                else if (physend >= ent_end) {
                    // trim end
                    ent_len = physaddr - ent_base;
                    st2_memmap->memmap[i].length = ent_len;
                }
                else {
                    // split
                    uint64_t newlen = ent_end - physend;
                    if (!add_entry(st2_memmap->memmap[i].type, physend, newlen)) {
                        return false;
                    }
                    ent_len = physaddr - ent_base;
                    st2_memmap->memmap[i].length = ent_len;
                }
            }
        }

        // Finally add the new entry:
        if (!add_entry(type_p, physaddr, length)) {
            return false;
        }

        return true;
    }

    void sort() noexcept
    {
        // Ok, so this is bubble sort. But the map shouldn't be too big and will likely be nearly
        // sorted already, so this is a good fit.

        uint32_t end_i = st2_memmap->entries - 1; // highest unsorted entry

        while (end_i > 0) {
            uint32_t last_i = 0;
            for (uint32_t i = 0; i < end_i; i++) {
                if (st2_memmap->memmap[i].base > st2_memmap->memmap[i+1].base) {
                    swap(st2_memmap->memmap[i], st2_memmap->memmap[i+1]);
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
        st2_memmap->entries = 0;
    }

    stivale2_memmap_info *get()
    {
        return st2_memmap;
    }

    ~tosaithe_stivale2_memmap()
    {
        if (st2_memmap != nullptr) {
            free_pool(st2_memmap);
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

    // Constructor with a standard set of parameters. Will create a maximally-sized segment (0
    // base, 0xFF...FF limit) and DPL=0 (i.e. highest privilege level).
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

    // Constructor with a standard set of parameters, and a specified privilege level. Segment
    // will be maximally sized (0 base, 0xFF....FF limit).
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

// Global descriptor table, for kernel entry, as per Stivale 2 spec
DT_entry GDT_table[] = {
        {0}, // NULL

        // ---- 1 ----

        cons_DT_code16_descriptor(),
        cons_DT_data16_descriptor(),
        cons_DT_code32_descriptor(),
        cons_DT_data32_descriptor(),

        // ---- 5 ----

        cons_DT_code64_descriptor(),

        // Stivale says this should be a "64-bit data descriptor". There is no such thing...
        // A regular 32-bit data descriptor should be fine, the base/limit will be ignored.
        cons_DT_data32_descriptor(),
};

static bool open_kernel_file(EFI_HANDLE image_handle, const CHAR16 *exec_path,
        EFI_FILE_PROTOCOL **kernel_file_p, UINTN *kernel_file_size_p)
{
    EFI_LOADED_IMAGE_PROTOCOL *image_proto;
    EFI_STATUS status = EBS->HandleProtocol(image_handle,
            &EFI_loaded_image_protocol_guid, (void **)&image_proto);
    // status must be EFI_SUCCESS?
    (void)status;

    EFI_DEVICE_PATH_PROTOCOL *image_device_path = nullptr;
    if (EBS->HandleProtocol(image_handle, &EFI_loaded_image_device_path_protocol_guid,
            (void **)&image_device_path) != EFI_SUCCESS) {
        con_write(L"Image does not support loaded-image device path protocol.\r\n");
        return false;
    }

    if (image_device_path == nullptr) {
        con_write(L"Firmware misbehaved; don't have loaded image device path.\r\n");
        return false;
    }

    unsigned exec_path_size = (strlen(exec_path) + 1) * sizeof(CHAR16);
    efi_unique_ptr<EFI_DEVICE_PATH_PROTOCOL> kernel_path
            { switch_path(image_device_path, exec_path, exec_path_size) };
    if (kernel_path == nullptr) {
        return false;
    }

    // Try to load the kernel now
    EFI_HANDLE loadDevice;

    auto *remaining_path = kernel_path.get();
    status = EBS->LocateDevicePath(&EFI_simple_file_system_protocol_guid, &remaining_path, &loadDevice);
    kernel_path = nullptr;
    if (EFI_ERROR(status)) {
        con_write(L"Couldn't get file system protocol for kernel path\r\n");
        return false;
    }

    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *sfs_protocol = nullptr;

    status = EBS->HandleProtocol(loadDevice, &EFI_simple_file_system_protocol_guid,
            (void **)&sfs_protocol);
    if (EFI_ERROR(status) || (sfs_protocol == nullptr /* firmware misbehaving */)) {
        con_write(L"Couldn't get file system protocol for kernel path\r\n");
        return false;
    }

    EFI_FILE_PROTOCOL *fs_root = nullptr;
    status = sfs_protocol->OpenVolume(sfs_protocol, &fs_root);
    if (EFI_ERROR(status) || (fs_root == nullptr /* firmware misbehaving */)) {
        con_write(L"Couldn't open volume (fs protocol)\r\n");
        return false;
    }

    EFI_FILE_PROTOCOL *kernel_file = nullptr;
    status = fs_root->Open(fs_root, &kernel_file, exec_path, EFI_FILE_MODE_READ, 0);
    fs_root->Close(fs_root);
    if (EFI_ERROR(status) || kernel_file == nullptr) {
        con_write(L"Couldn't open kernel file\r\n");
        return false;
    }

    EFI_FILE_INFO *kernel_file_info = get_file_info(kernel_file);
    if (kernel_file_info == nullptr) {
        kernel_file->Close(kernel_file);
        con_write(L"Couldn't get kernel file size\r\n");
        return false;
    }

    UINTN kernel_file_size = kernel_file_info->FileSize;
    free_pool(kernel_file_info);

    *kernel_file_p = kernel_file;
    *kernel_file_size_p = kernel_file_size;
    return true;
}

static void check_framebuffer(stivale2_framebuffer_info *fbinfo, uint64_t *fb_size)
{
    EFI_GRAPHICS_OUTPUT_PROTOCOL *graphics =
            (EFI_GRAPHICS_OUTPUT_PROTOCOL *) locate_protocol(EFI_graphics_output_protocol_guid);;

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

    fbinfo->memory_model = 1;
    fbinfo->framebuffer_addr = graphics->Mode->FrameBufferBase;
    fbinfo->framebuffer_width = graphics->Mode->Info->HorizontalResolution;
    fbinfo->framebuffer_height = graphics->Mode->Info->VerticalResolution;
    fbinfo->framebuffer_pitch = graphics->Mode->Info->PixelsPerScanLine
            * ((fbinfo->framebuffer_bpp + 7) / 8u);

    *fb_size = (((uint64_t)graphics->Mode->FrameBufferSize) + 0xFFFu) / 0x1000u * 0x1000u;
}

EFI_STATUS load_stivale2(EFI_HANDLE ImageHandle, const CHAR16 *exec_path, const CHAR16 *cmdLine)
{
    EFI_FILE_PROTOCOL *kernel_file;
    UINTN kernel_file_size;
    if (!open_kernel_file(ImageHandle, exec_path, &kernel_file, &kernel_file_size)) {
        return EFI_LOAD_ERROR;
    }

    // Allocate space for kernel file
    // For now we'll load a portion at an arbitrary address. We'll allocate 128kb and read at most
    // that much, for now. We'll read more if needed for program headers. Once we've read program
    // headers, we know where the file should end up, at which point we'll allocate space, relocate
    // what we've already read, and read the rest.

    // Try to read in chunks of at least 128kb:
    UINTN min_read_chunk = 128*1024u;

    efi_page_alloc kernel_alloc;
    UINTN first_chunk = std::min(min_read_chunk, kernel_file_size);

    {
        UINTN kernel_pages = (first_chunk + 0xFFFu)/0x1000u;

        if (!kernel_alloc.allocate_nx(kernel_pages)) {
            con_write(L"Couldn't allocate kernel memory\r\n");
            return EFI_LOAD_ERROR;
        }
    }

    UINTN read_amount = first_chunk;
    EFI_STATUS status = kernel_file->Read(kernel_file, &read_amount, (void *)kernel_alloc.get());

    if (EFI_ERROR(status)) {
        kernel_file->Close(kernel_file);
        con_write(L"Couldn't read kernel file; ");
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
            con_write(L"status not recognized, misbehaving firmware?\r\n");
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

    Elf64_Ehdr *elf_hdr = (Elf64_Ehdr *) kernel_alloc.get();

    // check e_ident
    if (std::char_traits<char>::compare((const char *)elf_hdr->e_ident, ELFMAGIC, 4) != 0) {
        con_write(L"Incorrect ELF header, not a valid ELF file\r\n");
        kernel_file->Close(kernel_file);
        return EFI_LOAD_ERROR;
    }

    unsigned elf_class = elf_hdr->e_ident[EI_CLASS];
    static_assert(sizeof(void*) == 4 || sizeof(void*) == 8, "pointer size must be 4/8 bytes");
    if ((sizeof(void*) == 4 && elf_class != ELFCLASS32) || (sizeof(void*) == 8 && elf_class != ELFCLASS64)) {
        con_write(L"Wrong ELF class (64/32 bit)\r\n");
        kernel_file->Close(kernel_file);
        return EFI_LOAD_ERROR;
    }

    unsigned elf_version = elf_hdr->e_ident[EI_VERSION];
    if (elf_version != EV_CURRENT) {
        con_write(L"Unsupported ELF version\r\n");
        kernel_file->Close(kernel_file);
        return EFI_LOAD_ERROR;
    }

    unsigned elf_data_enc = elf_hdr->e_ident[EI_DATA];
    if (elf_data_enc != ELFDATA2LSB /* && elf_data_enc != ELFDATA2MSB */) {
        con_write(L"Unsupported ELF data encoding\r\n");
        kernel_file->Close(kernel_file);
        return EFI_LOAD_ERROR;
    }

    // TODO actually support non-native encoding?

    if (elf_hdr->e_machine != EM_X86_64) {
        con_write(L"Wrong or unsupported ELF machine type\r\n");
        kernel_file->Close(kernel_file);
        return EFI_LOAD_ERROR;
    }

    if (elf_hdr->e_phnum == PH_XNUM) {
        con_write(L"Too many ELF program headers\r\n");
        kernel_file->Close(kernel_file);
        return EFI_LOAD_ERROR;
    }

    // check program headers, make sure we have allocated  correctly
    uintptr_t elf_ph_off = elf_hdr->e_phoff;
    uint16_t elf_ph_ent_size = elf_hdr->e_phentsize;
    uint16_t elf_ph_ent_num = elf_hdr->e_phnum;

    // sanity check program headers
    if (elf_ph_off >= kernel_file_size
            || ((kernel_file_size - elf_ph_off) / elf_ph_ent_size) < elf_ph_ent_num) {
        con_write(L"Bad ELF structure\r\n");
        kernel_file->Close(kernel_file);
        return EFI_LOAD_ERROR;
    }

    // Do we need to expand the chunk read? (Typically we won't, the program headers tend to follow
    // immediately after the ELF header. But, we'll allow for the other case).

    uintptr_t kernel_current_limit = kernel_alloc.get() + first_chunk;

    uintptr_t elf_ph_end = elf_ph_off + elf_ph_ent_size * elf_ph_ent_num;
    if (elf_ph_end > first_chunk) {
        read_amount = std::max(elf_ph_end - first_chunk, min_read_chunk);
        read_amount = std::min(read_amount, kernel_file_size - first_chunk);

        // Extend allocation. We can assume current kernel limit is on a page boundary.
        UINTN alloc_pages = (read_amount + 0xFFFu) / 0x1000u;
        status = EBS->AllocatePages(AllocateAddress, EfiLoaderCode, alloc_pages, &kernel_current_limit);
        if (EFI_ERROR(status)) {
            con_write(L"Couldn't allocate kernel memory\r\n");
            return EFI_LOAD_ERROR;
        }

        kernel_alloc.rezone(kernel_alloc.get(), kernel_alloc.page_count() + alloc_pages);

        status = kernel_file->Read(kernel_file, &read_amount, (void *)(kernel_alloc.get() + first_chunk));
        if (EFI_ERROR(status)) {
            con_write(L"Couldn't read kernel file\r\n");
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
    uintptr_t file_voffs;
    uintptr_t lowest_vaddr;
    uintptr_t highest_vaddr;

    struct bss_area {
        uintptr_t begin_offset;
        size_t size;
    };

    // bss areas need to be cleared before entry to kernel
    std::vector<bss_area> bss_areas;

    for (uint16_t i = 0; i < elf_ph_ent_num; i++) {
        uintptr_t ph_addr = i * elf_ph_ent_size + elf_ph_off + kernel_alloc.get();
        Elf64_Phdr *phdr = (Elf64_Phdr *)ph_addr;
        if (phdr->p_type == PT_LOAD) {
            uintptr_t voffs = phdr->p_vaddr - phdr->p_offset;

            if (phdr->p_vaddr < phdr->p_offset) {
                // technically possible, but unsupported
                // TODO support this
                con_write(L"Unsupported ELF structure\r\n");
                kernel_file->Close(kernel_file);
                return EFI_LOAD_ERROR;
            }

            if (!found_loadable) {
                file_voffs = voffs;
                lowest_vaddr = phdr->p_vaddr;
                highest_vaddr = phdr->p_vaddr + phdr->p_memsz;
                found_loadable = true;
            }
            else {
                if (file_voffs != voffs) {
                    // This segment has a different file/address offset than the previous one(s).
                    // Technically possible, but unsupported.
                    // TODO support this
                    con_write(L"Unsupported ELF structure\r\n");
                    kernel_file->Close(kernel_file);
                    return EFI_LOAD_ERROR;
                }
                lowest_vaddr = std::min(lowest_vaddr, phdr->p_vaddr);
                highest_vaddr = std::max(highest_vaddr, phdr->p_vaddr + phdr->p_memsz);
            }

            if (phdr->p_memsz > phdr->p_filesz) {
                bss_areas.push_back(bss_area { phdr->p_offset + phdr->p_filesz,
                    phdr->p_memsz - phdr->p_filesz });
            }
        }
    }

    if (!found_loadable) {
        con_write(L"No loadable segments in ELF\r\n");
        kernel_file->Close(kernel_file);
        return EFI_LOAD_ERROR;
    }

    // Need to account for values in upper half
    const uintptr_t high_half_addr = 0xFFFFFFFF80000000;

    uintptr_t adj_voffs = file_voffs;
    if (adj_voffs >= high_half_addr) adj_voffs -= high_half_addr;

    // From this point, kernel_addr is the address of the kernel. Currently page-aligned, though that
    // may soon change.
    EFI_PHYSICAL_ADDRESS kernel_addr = kernel_alloc.get();

    {
        UINTN kernel_pages = kernel_alloc.page_count();

        // The limit of the current allocation for kernel (+1)
        uintptr_t kernel_alloc_limit = (kernel_current_limit + 0xFFFu) / 0x1000u;
        // The page address of the kernel allocation
        uintptr_t kernel_page_addr = kernel_addr;

        // Re-locate if necessary:
        if (adj_voffs != kernel_addr) {
            uintptr_t new_kernel_limit = adj_voffs + kernel_current_limit - kernel_addr;
            uintptr_t new_alloc_limit = (new_kernel_limit + 0xFFFu) & ~uintptr_t(0xFFFu);
            uintptr_t new_kernel_page_addr = adj_voffs & ~uintptr_t(0xFFFu);

            uintptr_t alloc_from;
            UINTN alloc_pages;
            uintptr_t free_from;
            UINTN free_pages;

            if (adj_voffs < kernel_addr && new_kernel_limit > kernel_addr) {
                // moved backwards, overlapping
                alloc_from = new_kernel_page_addr;
                alloc_pages = (kernel_addr - alloc_from) / 0x1000u;
                free_from = new_alloc_limit;
                free_pages = (kernel_alloc_limit - free_from) / 0x1000u;
            }
            else if (adj_voffs > kernel_addr && adj_voffs < kernel_current_limit) {
                // moved forwards, overlapping
                alloc_from = kernel_alloc_limit;
                alloc_pages = (new_alloc_limit - kernel_alloc_limit) / 0x1000u;
                free_from = kernel_page_addr;
                free_pages = (new_kernel_page_addr - free_from) / 0x1000u;
            }
            else {
                // no overlap
                alloc_from = new_kernel_page_addr;
                alloc_pages = (new_alloc_limit - alloc_from) / 0x1000u;
                free_from = kernel_page_addr;
                free_pages = kernel_pages;
            }

            status = EBS->AllocatePages(AllocateAddress, EfiLoaderCode, alloc_pages, &alloc_from);
            if (EFI_ERROR(status)) {
                // TODO if PIE, can relocate completely
                con_write(L"Couldn't allocate kernel memory\r\n");
                kernel_file->Close(kernel_file);
                return EFI_LOAD_ERROR;
            }

            memmove((void *)adj_voffs, (void *)kernel_addr, kernel_pages * 0x1000u);
            EBS->FreePages(free_from, free_pages);

            kernel_current_limit = new_kernel_limit;
            kernel_alloc_limit = new_alloc_limit;
            kernel_page_addr = new_kernel_page_addr;
            kernel_pages = (new_alloc_limit - new_kernel_page_addr) / 0x1000u;

            kernel_addr = adj_voffs;
            elf_hdr = (Elf64_Ehdr *)kernel_addr;

            kernel_alloc.rezone(kernel_page_addr, kernel_pages);
        }

        // Allocate memory for the rest of the kernel, including any bss
        uintptr_t kernel_limit = std::max(kernel_file_size, highest_vaddr - file_voffs);
        UINTN total_pages_required = (kernel_limit + kernel_addr + 0xFFFu) / 0x1000u;
        if (total_pages_required > kernel_pages) {
            UINTN additional_reqd = total_pages_required - kernel_pages;

            status = EBS->AllocatePages(AllocateAddress, EfiLoaderCode, additional_reqd, &kernel_alloc_limit);
            if (EFI_ERROR(status)) {
                // TODO if PIE, can relocate completely
                con_write(L"Couldn't allocate kernel memory\r\n");
                kernel_file->Close(kernel_file);
                return EFI_LOAD_ERROR;
            }

            kernel_pages = total_pages_required;
            kernel_alloc.rezone(kernel_addr, kernel_pages);
        }
    }

    // Read the entire kernel image
    read_amount = kernel_file_size - first_chunk;

    if (read_amount > 0) {
        status = kernel_file->Read(kernel_file, &read_amount, (void *)kernel_current_limit);
        if (EFI_ERROR(status)) {
            con_write(L"Couldn't read kernel file\r\n");
            kernel_file->Close(kernel_file);
            return EFI_LOAD_ERROR;
        }
    }

    kernel_file->Close(kernel_file);

    // Find the stivale2 header (in the .stivale2hdr section).

    // We need to iterate through the sections and find one with the correct name (the name is
    // stored as an index into the section header names section, whose index is identified via
    // an entry in the elf header).

    auto num_section_hdrs = elf_hdr->e_shnum;
    if (num_section_hdrs == 0) { // real number is in first section entry, don't support that yet
        con_write(L"Unsupported ELF structure\r\n");
        return EFI_LOAD_ERROR;
    }

    uintptr_t section_headers_start = elf_hdr->e_shoff;

    if ((kernel_file_size - section_headers_start) / elf_hdr->e_shentsize < num_section_hdrs
            || elf_hdr->e_shstrndx >= num_section_hdrs
            || elf_hdr->e_shstrndx == 0) {
        con_write(L"Bad ELF structure\r\n");
        return EFI_LOAD_ERROR;
    }

    Elf64_Shdr *sh_string_section = (Elf64_Shdr *)(kernel_addr + section_headers_start
            + (elf_hdr->e_shentsize * elf_hdr->e_shstrndx));
    char *sh_string_start = (char *)(kernel_addr + sh_string_section->sh_offset);

    stivale2_header *sv2_header = nullptr;

    for (unsigned i = 0; i < num_section_hdrs; i++) {
        Elf64_Shdr *section_hdr = (Elf64_Shdr *)(kernel_addr + section_headers_start
                + (elf_hdr->e_shentsize * i));
        uint16_t name_offs = section_hdr->sh_name;
        if (name_offs >= sh_string_section->sh_size) {
            con_write(L"Bad ELF structure\r\n");
            return EFI_LOAD_ERROR;
        }
        std::string_view section_name { sh_string_start + name_offs, sh_string_section->sh_size - name_offs };
        auto nul_pos = section_name.find('\0');
        if (nul_pos == std::string_view::npos) {
            con_write(L"Bad ELF structure\r\n");
            return EFI_LOAD_ERROR;
        }
        section_name = section_name.substring(0, nul_pos);

        if (section_name == ".stivale2hdr") {
            con_write(L"found stivale2hdr section, index = "); con_write(i); con_write(L"\r\n"); // XXX
            sv2_header = (stivale2_header *)(kernel_addr + section_hdr->sh_offset);
        }
    }

    if (sv2_header == nullptr) {
        con_write(L"Stivale2 header not found\r\n");
        return EFI_LOAD_ERROR;
    }

    // We need to extract any needed info from the stivale header before we clear .bss!

    // TODO entry point and stack top need to be adjusted if kernel relocated
    uint64_t sv2_entry_point = sv2_header->entry_point;
    uint64_t sv2_stack_top = sv2_header->stack_top;
    uint64_t sv2_flags = sv2_header->flags;

    bool sv2_high_half_ptrs = (sv2_flags & 0x2) != 0;

    typedef void (*stivale_entry_t)(stivale2_struct *);
    stivale_entry_t stivale_entry = sv2_entry_point == 0
            ? (stivale_entry_t) elf_hdr->e_entry : (stivale_entry_t) sv2_entry_point;

    // TODO check tags - at least "any video" or "framebuffer" tags must be present

    // Zero out bss (parts of segments which have no corresponding file backing)
    for (bss_area bss : bss_areas) {
        memset((char *)kernel_addr + bss.begin_offset, 0, bss.size);
    }

    // Allocate space for page tables
    // We will use 4-level paging, so we need:
    // A PML4 top-level page directory (4kb)
    // A PDPT (page directory pointer table) (4kb)
    //   with 1 entry per 1GB page  -- max 512GB

    struct PDE {
        uint64_t entry;
    };

    // Allocate memory for page tables

    efi_page_alloc page_tables_alloc;
    if (!page_tables_alloc.allocate_nx(2)) {
        con_write(L"*** Memory allocation failed ***\r\n");
        return EFI_LOAD_ERROR;
    }

    PDE *page_tables = (PDE *)page_tables_alloc.get();

    // initialise all entries as "not present"
    for (unsigned i = 0; i < 512; i++) {
        page_tables[i] = PDE{0}; // not present
    }

    // Paging
    //
    // With standard 4-level paging, there are 48 bits of linear address (bits 0-47). Addresses in
    // proper canonical form will duplicate bit 47 up through to bit 63, effectively dividing the
    // address space into a positive (47-63 are 0) and negative (47-63 are 1).
    //
    //    0xFFFF 8000 0000 0000 <-- lowest "high half" address
    //    0xFFFF FFFF 8000 0000 <-- corresponds to (top - 2GB)
    //
    // Stivale2 spec says the first of the above is mapped to address 0, with a 4GB mapping "plus
    // any additional memory map entry", whatever that means. We may as well just map as much as
    // possible (and cover, hopefully, all available memory).
    //
    // Pagewise:
    //   0xFFFF 8000 0000 0000 = PML4[256][0]
    //   0xFFFF FFFF 8000 0000 = PML4[511][510]
    //
    // If we use just a single second-level page table (with 1GB pages) we could almost cover
    // 512GB. However, we need to map the top 2GB back to physical address 0, so we can cover
    // 510GB. TODO - that's a lot, but there could theoretically be more memory than that.

    // 1st level page tables (PML4):
    // Set up three entries to map the first 510GB at each of 0, (high half), and (top - 2GB)
    uint64_t PDPTaddress = page_tables_alloc.get() + 0x1000;
    page_tables[0] = PDE{PDPTaddress | 0x7}; // present, writable, user-accessible
    page_tables[256] = PDE{PDPTaddress | 0x7};
    page_tables[511] = PDE{PDPTaddress | 0x7};

    // 2nd level page tables:
    for (unsigned int i = 0; i < 512; i++) {
        // address || Page size (1GB page) || present, writable, user-accessible
        page_tables[512 + i] = PDE{uint64_t(i) * 1024UL*1024UL*1024UL | (1UL << 7) | 0x7UL};
    }
    // Map 2G at tail back to start (i.e. map 0xFFFFFFFF80000000 -> 0).
    page_tables[512 + 510] = page_tables[512];
    page_tables[512 + 511] = page_tables[513];

    // Set up Stivale2 tags
    stivale2_struct stivale2_info = { "tosaithe", "0.1", nullptr };

    // Framebuffer setup

    stivale2_framebuffer_info fbinfo;
    uint64_t fb_size = 0;
    fbinfo.tag.identifier = STIVALE2_LT_FRAMEBUFFER_TAGID;
    fbinfo.tag.next = nullptr;

    check_framebuffer(&fbinfo, &fb_size);

    // Build Stivale2 memory map from EFI memory map

    // This is a little tricky. Since we keep the stivale2 memory map in allocated memory, the
    // map may change between when we retrieve it and when we convert it to stivale2 format.
    // We'll allocate space first to try to avoid this - enough for 64 entries. If necessary we
    // can loop back and re-build the map from scratch.

    // Note: debugging output is risky from this point. Writing to EFI console may affect memory
    // map key.

    // Allocate Stivale2 memmap
    tosaithe_stivale2_memmap st2_memmap;
    if (!st2_memmap.allocate(64)) { // hopefully big enough
        con_write(L"*** Memory allocation failed ***\r\n");
        return EFI_LOAD_ERROR;
    }

    retrieve_efi_memmap:

    UINTN memMapSize = 0;
    UINTN memMapKey = 0;
    UINTN memMapDescrSize = 0;
    uint32_t memMapDescrVersion = 0;
    status = EBS->GetMemoryMap(&memMapSize, nullptr, &memMapKey, &memMapDescrSize, &memMapDescrVersion);
    if (status != EFI_BUFFER_TOO_SMALL) {
        con_write(L"*** Could not retrieve EFI memory map ***\r\n");
        return EFI_LOAD_ERROR;
    }

    // con_write(L"building mem map 2...\r\n"); // XXX

    efi_unique_ptr<EFI_MEMORY_DESCRIPTOR> efiMemMapPtr;

    {
        EFI_MEMORY_DESCRIPTOR *efiMemMap = (EFI_MEMORY_DESCRIPTOR *) alloc_pool(memMapSize);

        if (efiMemMap == nullptr) {
            con_write(L"*** Memory allocation failed ***\r\n");
            return EFI_LOAD_ERROR;
        }

        status = EBS->GetMemoryMap(&memMapSize, efiMemMap, &memMapKey, &memMapDescrSize, &memMapDescrVersion);
        while (status == EFI_BUFFER_TOO_SMALL) {
            // Above allocation may have increased size of memory map, so we keep trying
            free_pool(efiMemMap);
            efiMemMap = (EFI_MEMORY_DESCRIPTOR *) alloc_pool(memMapSize);
            if (efiMemMap == nullptr) {
                con_write(L"*** Memory allocation failed ***\r\n");
                return EFI_LOAD_ERROR;
            }
            status = EBS->GetMemoryMap(&memMapSize, efiMemMap, &memMapKey, &memMapDescrSize, &memMapDescrVersion);
        }

        efiMemMapPtr.reset(efiMemMap);
    }

    retrieve_efi_memmap_2:

    if (EFI_ERROR(status)) {
        con_write(L"*** Could not retrieve EFI memory map ***\r\n");
        return EFI_LOAD_ERROR;
    }

    // Copy entries from EFI memory map to Stivale2 map
    auto *efi_mem_iter = efiMemMapPtr.get();
    auto *efi_mem_end = (EFI_MEMORY_DESCRIPTOR *)((char *)efiMemMapPtr.get() + memMapSize);
    while (efi_mem_iter < efi_mem_end) {

        stivale2_mmap_type st_type;

        switch (efi_mem_iter->Type) {
        case EfiReservedMemoryType:
            st_type = stivale2_mmap_type::RESERVED;
            break;
        case EfiLoaderCode:
        case EfiLoaderData:
        case EfiBootServicesCode:
        case EfiBootServicesData:
            st_type = stivale2_mmap_type::BOOTLOADER_RECLAIMABLE;
            break;
        case EfiRuntimeServicesCode:
        case EfiRuntimeServicesData:
            // Stivale2 has no suitable memory type to indicate EFI runtime services use.
            // If we specify it as USABLE or RECLAIMABLE, runtime services won't be usable.
            st_type = stivale2_mmap_type::RESERVED;
            break;
        case EfiConventionalMemory:
            st_type = stivale2_mmap_type::USABLE;
            break;
        case EfiUnusableMemory:
            st_type = stivale2_mmap_type::BAD_MEMORY;
            break;
        case EfiACPIReclaimMemory:
            st_type = stivale2_mmap_type::ACPI_RECLAIMABLE;
            break;
        case EfiACPIMemoryNVS:
            st_type = stivale2_mmap_type::ACPI_NVS;
            break;
        case EfiMemoryMappedIO:
        case EfiMemoryMappedIOPortSpace:
        case EfiPalCode:
            st_type = stivale2_mmap_type::RESERVED;
            break;
        case EfiPersistentMemory:
            // Not really clear how this should be handled.
            st_type = stivale2_mmap_type::RESERVED;
            break;
        default:
            st_type = stivale2_mmap_type::RESERVED;
        }

        st2_memmap.add_entry(st_type, efi_mem_iter->PhysicalStart,
                efi_mem_iter->NumberOfPages * 0x1000u);
        efi_mem_iter = (EFI_MEMORY_DESCRIPTOR *)((char *)efi_mem_iter + memMapDescrSize);
    }

    // We won't release the map here, even though we no longer need it, since that would affect
    // the map and potentially our ability to successfully cal ExitBootServices().
    // -> Don't: efiMemMapPtr.reset();

    uint64_t kernel_size = kernel_alloc.page_count() * 0x1000u;
    st2_memmap.insert_entry(stivale2_mmap_type::KERNEL_AND_MODULES, kernel_alloc.get(), kernel_size);

    if (fb_size != 0) {
        st2_memmap.insert_entry(stivale2_mmap_type::FRAMEBUFFER, fbinfo.framebuffer_addr, fb_size);
    }

    st2_memmap.sort();

    // Set up tag chain: memmap, efi system table, framebuffer

    stivale2_memmap_info *st2_memmap_tag = st2_memmap.get();
    stivale2_info.tags = &st2_memmap_tag->tag;

    stivale2_efi_system_table_info st2_efi_sys_tbl_tag;
    st2_efi_sys_tbl_tag.tag.identifier = STIVALE2_LT_EFI_SYSTEM_TBL_TAGID;
    st2_efi_sys_tbl_tag.tag.next = nullptr;
    st2_efi_sys_tbl_tag.system_table = EST;
    st2_memmap_tag->tag.next = &st2_efi_sys_tbl_tag.tag;

    if (fb_size != 0) {
        st2_efi_sys_tbl_tag.tag.next = &fbinfo.tag;
    }

    // TODO command line tag
    // TODO modules tag

    // TODO high-half pointers support

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
        con_write(L"Uh-oh, LA57 was enabled by firmware :(\r\n");  // TODO
        return EFI_LOAD_ERROR;
    }

    // Exit boot services: there is no going back from here...
    if (EBS->ExitBootServices(ImageHandle, memMapKey) == EFI_INVALID_PARAMETER) {
        st2_memmap.clear();

        status = EBS->GetMemoryMap(&memMapSize, efiMemMapPtr.get(), &memMapKey, &memMapDescrSize, &memMapDescrVersion);
        if (EFI_ERROR(status)) {
            if (status != EFI_BUFFER_TOO_SMALL) {
                con_write(L"*** Could not retrieve EFI memory map ***\r\n");
                return EFI_LOAD_ERROR;
            }
            goto retrieve_efi_memmap;
        }

        // we've already got the EFI memory map now, so skip that step and just rebuild the stivale map:
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

    // TODO: Stivale2 spec says we should disable all IRQs on the PIC and APIC.

    // Load GDT, jump into kernel and switch stack:

    // Argument to LGDT instruction will be this format:
    struct LoadGDT64_struct {
        uint16_t size;
        DT_entry *base; /* linear(!) base address */
    } __attribute__((packed));

    LoadGDT64_struct gdt_desc { uint16_t(sizeof(GDT_table) - 1), GDT_table };

    if (sv2_stack_top != 0) {
        asm volatile (
                    "lgdt %0\n"

                // Note that "iretq" in long mode pops all of flags, CS:RIP and SS:RSP.
                // What we're trying to accomplish here is basically a far jump - something that turns
                // out to be pretty tricky in long mode. But handily, this will load SS:RSP at the
                // same time.

                    "pushq $0x30\n" // SS
                    "pushq %1\n"    // RSP
                    "pushfq\n"
                    "pushq $0x28\n" // CS

                    // rather than push the target directly, load it relative to RIP. This prevents issues
                    // in the case that we are loaded above 2GB when the push'd value will be sign extended.
                    // (Although, due to our mappings, that mightn't be a problem anyway...)
                    // so, not this: "pushq $long_jmp_after_gdt_load\n"
                    "leaq long_jmp_after_gdt_load(%%rip), %%rax\n"
                    "pushq %%rax\n" // RIP
                    "iretq\n"       // returns to following instruction:

                // After this point we are on a new stack. The input operands we access must not be memory,
                // since they could be stack-relative addresses which are no longer valid. Fortunately
                // there's only one: the target address

                "long_jmp_after_gdt_load:\n"
                    "movl $0x30, %%eax\n"
                    "movl %%eax, %%ds\n"
                    "pushq $0x0\n"  // invalid return address
                    "jmpq %A2"

                :
                : "m"(gdt_desc), "rm"(sv2_stack_top), "r"(stivale_entry), "D"(&stivale2_info)
                : "rax"
        );
    }
    else {
        // In this version, we set RSP to 0:
        asm volatile (
                    "lgdt %0\n"

                    "pushq $0x30\n" // SS
                    "pushq $0x0\n"  // RSP (0x0)
                    "pushfq\n"
                    "pushq $0x28\n" // CS
                    "leaq long_jmp_after_gdt_load2(%%rip), %%rax\n"
                    "pushq %%rax\n" // RIP
                    "iretq\n"  // returns to following instruction:

                "long_jmp_after_gdt_load2:\n"
                    "movl $0x30, %%eax\n"
                    "movl %%eax, %%ds\n"
                    "jmpq %A1"

                :
                : "m"(gdt_desc), "r"(stivale_entry), "D"(&stivale2_info)
                : "rax"
        );
    }

    return EFI_SUCCESS;
}
