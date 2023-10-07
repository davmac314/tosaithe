#include "tosaithe-proto.h"

#include <algorithm>
#include <string>
#include <memory>
#include <new>

#include <cstring>
#include <cstdint>

#include <elf.h>

#include <uefi.h>
#include <uefi-media-file.h>
#include <uefi-loadedimage.h>

#include "cpu-x86_64.h"
#include "tosaithe-util.h"

extern EFI_BOOT_SERVICES *EBS;
extern EFI_SYSTEM_TABLE *EST;

// Supported page sizes:
static const uintptr_t PAGE4KB = 0x1000u;
static const uintptr_t PAGE2MB = 0x200000u;
static const uintptr_t PAGE1GB = 0x40000000u;

// Top of memory minus 2GB. The kernel virtual address must be within this region.
static const uintptr_t TOP_MINUS_2GB = 0xFFFFFFFF80000000u;

namespace {

// round up to a power of 2
template <typename T>
T round_up_to_p2(T val, T alignment)
{
    return (val + alignment - 1) & ~(alignment - 1);
}

}

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
static bool open_kernel_file(EFI_HANDLE image_handle, const EFI_DEVICE_PATH_PROTOCOL *exec_path,
        EFI_FILE_PROTOCOL **kernel_file_p, UINTN *kernel_file_size_p)
{
    efi_file_handle kernel_file_hndl;
    const CHAR16 * errmsg;

    try {
        kernel_file_hndl.reset(open_file(exec_path));
    }
    catch (open_file_exception &ofe) {
        if (ofe.status == open_file_exception::CANNOT_OPEN_FILE) {
            errmsg = OPEN_KERNEL_ERR_FILEOPEN;
        }
        else if (ofe.status == open_file_exception::CANNOT_OPEN_VOLUME) {
            errmsg = OPEN_KERNEL_ERR_VOLUME;
        }
        else if (ofe.status == open_file_exception::NO_DPTT_PROTOCOL) {
            errmsg = OPEN_KERNEL_ERR_FIRMWARE;
        }
        else /* if (ofe.status == open_file_exception::NO_FSPROTOCOL_FOR_DEV_PATH) */ {
            errmsg = OPEN_KERNEL_ERR_FILEOPEN;
        }
        goto error_out;
    }

    {
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

// Find a configuration table by GUID
static void *find_config_table(const EFI_GUID &table_id)
{
    EFI_CONFIGURATION_TABLE *tables = EST->ConfigurationTable;
    for (UINTN i = 0; i < EST->NumberOfTableEntries; i++) {
        if (memcmp(&tables[i].VendorGuid, &table_id, sizeof(EFI_GUID)) == 0) {
            return tables[i].VendorTable;
        }
    }
    return nullptr;
}

// Check whether a usable framebuffer exists, copy relevant info into 'fbinfo' if so
// and store the framebuffer size (rounded up to page boundary) into '*fb_size'.
static void check_framebuffer(tosaithe_loader_data *fbinfo)
{
    EFI_GRAPHICS_OUTPUT_PROTOCOL *graphics =
            (EFI_GRAPHICS_OUTPUT_PROTOCOL *) locate_protocol(EFI_graphics_output_protocol_guid);

    fbinfo->framebuffer_addr = 0;
    fbinfo->framebuffer_size = 0;

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
        return; // framebuffer not available
    }

    fbinfo->framebuffer_addr = graphics->Mode->FrameBufferBase;
    fbinfo->framebuffer_width = graphics->Mode->Info->HorizontalResolution;
    fbinfo->framebuffer_height = graphics->Mode->Info->VerticalResolution;
    fbinfo->framebuffer_pitch = graphics->Mode->Info->PixelsPerScanLine
            * ((fbinfo->framebuffer_bpp + 7) / 8u);
    fbinfo->framebuffer_size = (((uint64_t)graphics->Mode->FrameBufferSize) + 0xFFFu) / 0x1000u * 0x1000u;
}

// Get a copy of the EFI memory map in an allocated buffer. Returns null on general failure or
// throws std::bad_alloc for out-of-memory.
//   memMapSize - will contain size in bytes
//   memMapKey - will contain key suitable for passing to ExitBootServices
//   memMapDescrSize - will be set to the size of each descriptor entry
//   memMapDescrVersion - will be set to the descriptor version
EFI_MEMORY_DESCRIPTOR *get_efi_memmap(UINTN &memMapSize, UINTN &memMapKey, UINTN &memMapDescrSize, uint32_t &memMapDescrVersion)
{
    // Ideally we would start with size 0 and null pointer, which should return the needed size.
    // But the EFI firmware for the ASRock B550 PG Riptide board (bios version L2.71) seems to
    // handle this case incorrectly and returns EFI_INVALID_PARAMETER instead of EFI_BUFFER_TOO_SMALL.
    // So instead start with a small fixed-size buffer:

    memMapSize = 16 * sizeof(EFI_MEMORY_DESCRIPTOR);
    EFI_MEMORY_DESCRIPTOR *efiMemMap = (EFI_MEMORY_DESCRIPTOR *) alloc_pool(memMapSize);
    if (efiMemMap == nullptr) {
        throw std::bad_alloc();
    }

    EFI_STATUS status = EBS->GetMemoryMap(&memMapSize, efiMemMap, &memMapKey, &memMapDescrSize, &memMapDescrVersion);

    while (status == EFI_BUFFER_TOO_SMALL) {
        // Above allocation may have increased size of memory map, so we keep trying
        free_pool(efiMemMap);
        memMapSize += 4 * memMapDescrSize; // Add a margin for error
        efiMemMap = (EFI_MEMORY_DESCRIPTOR *) alloc_pool(memMapSize);
        if (efiMemMap == nullptr) {
            throw std::bad_alloc();
        }
        status = EBS->GetMemoryMap(&memMapSize, efiMemMap, &memMapKey, &memMapDescrSize, &memMapDescrVersion);
    }

    if (EFI_ERROR(status)) {
        con_write(L"Error: could not retrieve EFI memory map\r\n");
        free_pool(efiMemMap);
        return nullptr;
    }

    return efiMemMap;
}

// Sort entries in the EFI memory map (by address).
void sort_efi_memmap(EFI_MEMORY_DESCRIPTOR *memmap, UINTN memMapSize, UINTN memMapDescrSize)
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

// Compact EFI memory map by merging adjacent entries with same type/attributes and adjacent range.
// Ranges with EFI_MEMORY_RUNTIME attribute will not be merged.
void compact_efi_memmap(EFI_MEMORY_DESCRIPTOR *memmap, UINTN &memMapSize, UINTN memMapDescrSize)
{
    EFI_MEMORY_DESCRIPTOR *end_ent = (EFI_MEMORY_DESCRIPTOR *)
            ((uintptr_t)memmap + memMapSize);

    // set cur_ent -> first entry, scan_ent -> second entry:
    EFI_MEMORY_DESCRIPTOR *cur_ent = memmap;
    EFI_MEMORY_DESCRIPTOR *scan_ent = (EFI_MEMORY_DESCRIPTOR *)((uintptr_t)memmap + memMapDescrSize);

    while (scan_ent != end_ent) {
        // Can we merge?
        // (Note, we don't merge if EFI_MEMORY_RUNTIME is set, since if the kernel wants to use
        // SetVirtualAddressMap to continue using runtime services it needs to pass the runtime areas
        // as separate entries in the map).
        if (cur_ent->Type == scan_ent->Type && !(cur_ent->Attribute & EFI_MEMORY_RUNTIME)
                && cur_ent->Attribute == scan_ent->Attribute
                && scan_ent->PhysicalStart == (cur_ent->PhysicalStart + cur_ent->NumberOfPages * PAGE4KB)) {
            cur_ent->NumberOfPages += scan_ent->NumberOfPages;
        }
        else {
            cur_ent = (EFI_MEMORY_DESCRIPTOR *)((uintptr_t)cur_ent + memMapDescrSize);
            *cur_ent = *scan_ent;
        }
        scan_ent = (EFI_MEMORY_DESCRIPTOR *)((uintptr_t)scan_ent + memMapDescrSize);
    }

    memMapSize = ((uintptr_t)cur_ent - (uintptr_t)memmap) + memMapDescrSize;
}

// Find an entry by address in a pre-sorted EFI memory map
EFI_MEMORY_DESCRIPTOR *efi_memmap_find(UINTN addr, EFI_MEMORY_DESCRIPTOR *memmap,
        UINTN memMapSize, UINTN memMapDescrSize)
{
    EFI_MEMORY_DESCRIPTOR *end_ent = (EFI_MEMORY_DESCRIPTOR *)
            ((uintptr_t)memmap + memMapSize);

    EFI_MEMORY_DESCRIPTOR *cur_ent = memmap;

    while (cur_ent != end_ent) {
        if (cur_ent->PhysicalStart <= addr) {
            UINTN phys_end = cur_ent->PhysicalStart + cur_ent->NumberOfPages * PAGE4KB;
            if (phys_end > addr) {
                return cur_ent;
            }
        }
        else {
            break;
        }
        cur_ent = (EFI_MEMORY_DESCRIPTOR *)((uintptr_t)cur_ent + memMapDescrSize);
    }
    return nullptr;
}

// Load a kernel via the TSBP (ToSaithe Boot Protocol)
EFI_STATUS load_tsbp(EFI_HANDLE ImageHandle, const EFI_DEVICE_PATH_PROTOCOL *exec_path, const char *cmdLine,
        void *ramdisk, uint64_t ramdisk_size)
{
    efi_file_handle kernel_handle;
    UINTN kernel_file_size = 0;
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
        elf_header_alloc.extend_or_move(alloc_pages);
        elf_hdr = (Elf64_Ehdr *) elf_header_alloc.get_ptr();

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
    uintptr_t lowest_vaddr = 0;
    uintptr_t highest_vaddr = 0;
    uintptr_t seg_alignment = 0;

    struct bss_area {
        uintptr_t begin_offset;
        size_t size;
    };

    // bss areas need to be cleared before entry to kernel
    std::vector<bss_area> bss_areas;

    // Find the total virtual address span of all segments (lowest_vaddr, highest_vaddr)
    for (uint16_t i = 0; i < elf_ph_ent_num; i++) {
        uintptr_t ph_addr = i * elf_ph_ent_size + elf_ph_off + elf_header_alloc.get_ptr();
        Elf64_Phdr phdr;
        std::memcpy(&phdr, (void *)ph_addr, sizeof(phdr));
        if (phdr.p_type == PT_LOAD) {
            // Do some consistency checks while we are at it:
            auto max_addr = std::numeric_limits<decltype(phdr.p_vaddr)>::max();
            if (phdr.p_vaddr > max_addr - phdr.p_memsz) {
                // size is too large, given the starting address
                con_write(L"Error: bad ELF structure\r\n");
                return EFI_LOAD_ERROR;
            }

            if (phdr.p_vaddr & (phdr.p_align - 1)) {
                con_write(L"Error: unsupported ELF structure\r\n");
                return EFI_LOAD_ERROR;
            }

            auto vaddr = phdr.p_vaddr;
            auto vaddr_high = vaddr + phdr.p_memsz;

            if (!found_loadable) {
                // Valid page sizes: 4kb, 2mb, 1gb
                if (phdr.p_align != 0x1000u && phdr.p_align != 0x200000 && phdr.p_align != 0x40000000u) {
                    con_write(L"Error: unsupported ELF structure\r\n");
                    return EFI_LOAD_ERROR;
                }
                seg_alignment = phdr.p_align;
                lowest_vaddr = vaddr;
                highest_vaddr = vaddr_high;
                found_loadable = true;
            }
            else {
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

    if (!found_loadable || lowest_vaddr < TOP_MINUS_2GB) {
        con_write(L"Error: unsupported ELF structure\r\n");
        return EFI_LOAD_ERROR;
    }


    // Allocate space for kernel; we need to ensure sufficient alignment

    efi_page_alloc kernel_alloc;

    {
        UINTN req_size = round_up_to_p2(highest_vaddr - lowest_vaddr, PAGE4KB);
        UINTN pages_to_alloc = (req_size + seg_alignment - 1) / PAGE4KB;

        kernel_alloc.allocate(pages_to_alloc);

        uintptr_t aligned_begin = kernel_alloc.get_ptr(); // may not be aligned yet...
        uintptr_t alloc_offset = aligned_begin & (seg_alignment - 1);
        if (alloc_offset != 0) {
            // correct alignment:
            aligned_begin = (aligned_begin & ~(seg_alignment - 1));
            if (aligned_begin < kernel_alloc.get_ptr()) {
                aligned_begin += seg_alignment;
            }
            // trim allocation (start):
            EBS->FreePages(kernel_alloc.get_ptr(), (aligned_begin - kernel_alloc.get_ptr()) / PAGE4KB);
        }

        // trim end
        uintptr_t end_trim = kernel_alloc.get_ptr() + pages_to_alloc * PAGE4KB
                - (aligned_begin + req_size);
        if (end_trim != 0) {
            EBS->FreePages(aligned_begin + req_size, end_trim / PAGE4KB);
        }

        kernel_alloc.rezone(aligned_begin, req_size / PAGE4KB);
    }


    // Actually load kernel (read from disk into memory).

    // Go through each segment (identified by program header) and relevant portion of the file
    // into the kernel image area.

    tosaithe_entry_header *ts_entry_header = nullptr;

    for (uint16_t i = 0; i < elf_ph_ent_num; /* increment in body */) {
        uintptr_t ph_addr = i * elf_ph_ent_size + elf_ph_off + elf_header_alloc.get_ptr();
        Elf64_Phdr phdr;
        std::memcpy(&phdr, (void *)ph_addr, sizeof(phdr));
        if (phdr.p_type == PT_LOAD) {
            uintptr_t addr_offs = phdr.p_vaddr - lowest_vaddr;
            bool do_file_read = true;
            UINTN seek_pos;
            UINTN amount_to_read;
            void *read_to_addr;
            UINTN seg_size = phdr.p_filesz;

            // Look for additional adjacent segments to combine as a single read
            while (++i < elf_ph_ent_num) {
                ph_addr += elf_ph_ent_size;
                Elf64_Phdr next_phdr;
                std::memcpy(&next_phdr, (void *)ph_addr, sizeof(next_phdr));
                if (next_phdr.p_type != PT_LOAD)
                    break;
                // If same physical-virtual offset, combine segments
                if ((next_phdr.p_paddr - next_phdr.p_vaddr) != (phdr.p_paddr - phdr.p_vaddr))
                    break;

                seg_size = (next_phdr.p_paddr - phdr.p_paddr) + next_phdr.p_filesz;
            }

            // We already have read a decent chunk when we read the ELF header (an amount given by
            // first_chunk). If that covers the segments portion of the file, or part of it, copy
            // from the header rather than re-reading the file:
            if (phdr.p_offset < first_chunk) {
                // copy from our initial read rather than re-reading
                auto copy_size = std::min(first_chunk - phdr.p_offset, seg_size);
                memcpy((void *)(kernel_alloc.get_ptr() + addr_offs), ((char *)elf_hdr) + phdr.p_offset, copy_size);
                if (copy_size == seg_size) {
                    do_file_read = false;
                }
                else {
                    seek_pos = phdr.p_offset + copy_size;
                    amount_to_read = seg_size - copy_size;
                    read_to_addr = (void *)(kernel_alloc.get_ptr() + addr_offs + copy_size);
                }
            }
            else {
                seek_pos = phdr.p_offset;
                amount_to_read = seg_size;
                read_to_addr = (void *)(kernel_alloc.get_ptr() + addr_offs);
            }

            // Read any portion of the segment that we didn't copy from the header chunk:
            if (do_file_read && seg_size != 0) {
                status = kernel_handle.seek(seek_pos);
                if (!EFI_ERROR(status)) {
                    read_amount = amount_to_read;
                    status = kernel_handle.read(&read_amount, read_to_addr);
                }
                if (EFI_ERROR(status) || (read_amount != amount_to_read)) {
                    con_write(L"Error: couldn't read kernel file\r\n");
                    return EFI_LOAD_ERROR;
                }
            }

            // We find the tosaithe entry header at the beginning of the first segment:
            if (ts_entry_header == nullptr) {
                ts_entry_header = (tosaithe_entry_header *)(kernel_alloc.get_ptr() + addr_offs);
            }
        }
        else {
            ++i;
        }
    }

    kernel_handle.release();

    // build vector of kernel mappings
    std::vector<tsbp_kernel_mapping> tsbp_kernel_map;
    for (uint16_t i = 0; i < elf_ph_ent_num; ++i) {
        uintptr_t ph_addr = i * elf_ph_ent_size + elf_ph_off + elf_header_alloc.get_ptr();
        Elf64_Phdr phdr;
        std::memcpy(&phdr, (void *)ph_addr, sizeof(phdr));
        if (phdr.p_type == PT_LOAD) {
            tsbp_kernel_map.emplace_back(tsbp_kernel_mapping {
                phdr.p_vaddr - lowest_vaddr + kernel_alloc.get_ptr(),  // base physical address
                phdr.p_vaddr,
                round_up_to_p2(phdr.p_memsz, seg_alignment),  // length
                phdr.p_flags & 0x7 // X/W/R flags
            });
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

    sort_efi_memmap(efi_memmap_ptr.get(), memMapSize, memMapDescrSize);
    compact_efi_memmap(efi_memmap_ptr.get(), memMapSize, memMapDescrSize);

    // Allocate memory for page tables

    struct PDE {
        uint64_t entry;
    };

    enum class memory_types {
        CACHE_WB = 0x0, // write-back (full caching)
        CACHE_WT = 0x1, // write-thru (allows reads from cache)
        CACHE_UC = 0x2, // uncacheable
        // for the following types, generally should map to uncacheable if PAT is not available
        // (which then may be overwridden via MTRRs)
        CACHE_WP = 0x4, // write-protect (allow reads from cache, writes don't go to cache)
        CACHE_WC = 0x5 // write-combining (writes go through store buffer, not cached)
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

    const int PAGE_POOL_ALLOC_SIZE = 8;

    std::vector<efi_page_alloc> page_table_allocs;

    efi_page_alloc page_tables_alloc_pool;
    page_tables_alloc_pool.allocate(PAGE_POOL_ALLOC_SIZE);
    void * alloc_pool_next = (void *)page_tables_alloc_pool.get_ptr();

    auto take_page = [&]() -> void * {
        uintptr_t ap_end = (uintptr_t)page_tables_alloc_pool.get_ptr() + page_tables_alloc_pool.page_count() * PAGE4KB;
        if (alloc_pool_next == (void *)ap_end) {
            if (!page_tables_alloc_pool.extend_nx(PAGE_POOL_ALLOC_SIZE)) {
                page_table_allocs.emplace_back(std::move(page_tables_alloc_pool));
                page_tables_alloc_pool.allocate(PAGE_POOL_ALLOC_SIZE);
                alloc_pool_next = (void *)page_tables_alloc_pool.get_ptr();
            }
        }

        void *r = alloc_pool_next;
        alloc_pool_next = (void *)((uintptr_t)alloc_pool_next + PAGE4KB);
        memset(r, 0, PAGE4KB);
        return r;
    };

    PDE *page_tables = (PDE *)take_page();

    // Check availability of 1GB pages:
    // CPUID.80000001H:EDX.Page1GB [bit 26]
    bool have_1gb_pages = false;

    // First check if we can use 80000001h (we'll assume we have CPUID since it's been supported
    // even since the later 80486's):
    uint32_t cpuid_eax;
    uint32_t cpuid_edx;
    asm volatile (
            "movl $0x80000000, %%eax\n"
            "cpuid\n"
            : "=a"(cpuid_eax), "=d"(cpuid_edx) :  : "rbx", "rcx"
    );
    if (cpuid_eax >= 0x80000001) {
        // Ok, we can use CPUID.80000001H: do so
        asm volatile (
                "movl $0x80000001, %%eax\n"
                "cpuid\n"
                : "=a"(cpuid_eax), "=d"(cpuid_edx) :  : "rbx", "rcx"
        );

        if ((cpuid_edx & (1u << 26)) != 0) {
            // 1GB pages are supported.
            have_1gb_pages = true;
        }
    }

    // Create page mapping for a region, i.e. insert a mapping from some virtual address to a physical
    // address. Mapping will use the largest possible page size (according to the alignment/size of the
    // mapped range, and processor support for page size).
    //
    // In general this expects the virtual range to be unoccupied, i.e. does not support mapping over an
    // existing mapping; however, it does support over-mapping if the new mapper is equally or more
    // fine-grained than the existing mapping(s) (i.e. if the new page size will be equal or smaller, across
    // all of the mapped range).
    //
    // page_attrs - can include Writable (0x2), NX/XD (not executable/execute disable) (1<<63).
    //              NX/XD requires processor support.
    auto do_mapping = [&](uintptr_t virt_addr, uintptr_t phys_addr_beg, uintptr_t phys_addr_end, memory_types mem_type,
            uint64_t page_attrs) {
        uintptr_t virt_phys_diff = virt_addr - phys_addr_beg;
        bool use_1gb_pages = have_1gb_pages ? ((virt_phys_diff & (PAGE1GB - 1)) == 0) : false;
        bool use_2mb_pages = (virt_phys_diff & (PAGE2MB - 1)) == 0;

        // PWT = bit 3
        // PCD = bit 4
        // PAT = bit 12 (1GB/2MB page) or bit 7 (4kb page)

        // allocate an intermediate page table for a given entry. If the entry is already marked
        // present, no allocation is performed and the entry is returned unchanged (unless the
        // entry points to a large page and split_large is true).
        //
        // pde_ent: entry which will be updated to point to the allocated page table
        // split_large: if true, and the entry points to a large page
        auto allocate_int_pt = [&](PDE &pde_ent, bool split_large, uintptr_t pg_size) {
            if ((pde_ent.entry & 0x1) != 0) {
                // intermediate already exists... or is it a large page?
                if (split_large && (pde_ent.entry & 0x80) != 0) {
                    // split large page

                    // Preserve caching attributes (memory type), W bits
                    uint64_t PAT_PCD_PWT_PS_dst;
                    if (pg_size == PAGE4KB) {
                        // PAT is in different place between 4kb page entries and larger entries:
                        bool PAT_src = (pde_ent.entry & 0x1000) != 0;
                        PAT_PCD_PWT_PS_dst = (pde_ent.entry & 0x18) | (PAT_src ? 0x80 : 0x0);
                    }
                    else {
                        PAT_PCD_PWT_PS_dst = (pde_ent.entry & 0x1018) | 0x80 /* page size */;
                    }
                    uint64_t dst_entry_flags = PAT_PCD_PWT_PS_dst | (pde_ent.entry & /* W */ 0x2);

                    uintptr_t orig_phys = pde_ent.entry & 0x000FFFFFFFFFF000u;
                    auto page_for_split = (uintptr_t)take_page();
                    pde_ent.entry = page_for_split | 3 /* present/read+write */;
                    PDE *split_page = (PDE *)page_for_split;
                    // re-create original mapping, will be partially overwritten by caller
                    for (int i = 0; i < 512; i++) {
                        split_page[i] = { orig_phys | dst_entry_flags | 0x1u /* present */ };
                        orig_phys += pg_size;
                    }
                }
            }
            else {
                // nothing in the entry yet. Allocate:
                auto pdpt_page = (uintptr_t)take_page();
                pde_ent.entry = pdpt_page | 3 /* present/read+write */;
                // (leave the cache attributes as default; they can be modified by caller)
            }
        };

        // The following three blocks of code (if statements) are pretty similar, but each handles
        // a different page size. For smaller page sizes we have more intermediate levels to deal
        // with.

        if (use_1gb_pages && (phys_addr_beg & (PAGE1GB - 1)) == 0 && (phys_addr_end - phys_addr_beg) >= PAGE1GB) {
            // 1GB pages!

            allocate_1gb_pages:

            // allocate 2nd level page table if needed
            auto &pde_ent = page_tables[(virt_addr >> 39) & 0x1FF];
            allocate_int_pt(pde_ent, false, 0);

            // from pde_ent find the address of the next level:
            uintptr_t pdpt_addr = pde_ent.entry & 0x000FFFFFFFFFF000u; // 52 bits physical
            PDE *pdpt = (PDE *)pdpt_addr;

            uint64_t PAT_PCD_PWT_PS_dst = ((uint64_t)mem_type & 3) << 3; // PCD, PWT
            PAT_PCD_PWT_PS_dst |= ((uint64_t)mem_type & 4) << 10; // PAT
            PAT_PCD_PWT_PS_dst |= 0x80; // PS

            // set entrie(s) for 1GB page(s)
            int pdpt_ind = (virt_addr >> 30) & 0x1FF;
            do {
                pdpt[pdpt_ind] = {phys_addr_beg | PAT_PCD_PWT_PS_dst | page_attrs | 1 /* present */ };
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
            allocate_int_pt(pde_ent, false, 0);

            // from pde_ent find the address of the next level:
            uintptr_t pdpt_addr = pde_ent.entry & 0x000FFFFFFFFFF000u; // 52 bits physical
            PDE *pdpt = (PDE *)pdpt_addr;

            // allocate 3rd level page table if needed
            auto &pdpt_ent = pdpt[(virt_addr >> 30) & 0x1FF];
            allocate_int_pt(pdpt_ent, true, PAGE2MB);

            // from pde_ent find the address of the next level:
            uintptr_t pd_addr = pdpt_ent.entry & 0x000FFFFFFFFFF000u; // 52 bits physical
            PDE *pd = (PDE *)pd_addr;

            uint64_t PAT_PCD_PWT_PS_dst = ((uint64_t)mem_type & 3) << 3; // PCD, PWT
            PAT_PCD_PWT_PS_dst |= ((uint64_t)mem_type & 4) << 10; // PAT
            PAT_PCD_PWT_PS_dst |= 0x80; // PS

            // set entrie(s) for 2MB page(s)
            int pd_ind = (virt_addr >> 21) & 0x1FF;
            do {
                pd[pd_ind] = {phys_addr_beg | PAT_PCD_PWT_PS_dst | page_attrs | 1 /* present */ };
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
            allocate_int_pt(pde_ent, false, 0);

            // from pde_ent find the address of the next level:
            uintptr_t pdpt_addr = pde_ent.entry & 0x000FFFFFFFFFF000u; // 52 bits physical
            PDE *pdpt = (PDE *)pdpt_addr;

            // allocate 3rd level page table (PD) if needed:
            auto &pdpt_ent = pdpt[(virt_addr >> 30) & 0x1FF];
            allocate_int_pt(pdpt_ent, true, PAGE2MB);

            // from pdpt_ent find the address of the next level:
            uintptr_t pd_addr = pdpt_ent.entry & 0x000FFFFFFFFFF000u; // 52 bits physical
            PDE *pd = (PDE *)pd_addr;

            // allocate 4th level page table (PT) if needed:
            auto &pd_ent = pd[(virt_addr >> 21) & 0x1FF];
            allocate_int_pt(pd_ent, true, PAGE4KB);

            // from pd_ent find the address of the page table:
            uintptr_t pt_addr = pd_ent.entry & 0x000FFFFFFFFFF000u; // 52 bits physical
            PDE *pt = (PDE *)pt_addr;

            uint64_t PAT_PCD_PWT_PS_dst = ((uint64_t)mem_type & 3) << 3; // PCD, PWT
            PAT_PCD_PWT_PS_dst |= ((uint64_t)mem_type & 4) << 5; // PAT (bit 7)

            // set entrie(s) for 4kb page(s)
            int pt_ind = (virt_addr >> 12) & 0x1FF;
            do {
                pt[pt_ind] = {phys_addr_beg | PAT_PCD_PWT_PS_dst | page_attrs | 1 /* present */ };
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

    // Map all regions from the EFI memory map.
    // Note that this will exclude framebuffer, Local APIC / IO APIC, probably any device mapping
    // that isn't specific to the system.

    static_assert(tsbp_mmap_flags::CACHE_UC == (int)memory_types::CACHE_UC);
    static_assert(tsbp_mmap_flags::CACHE_WB == (int)memory_types::CACHE_WB);
    static_assert(tsbp_mmap_flags::CACHE_WC == (int)memory_types::CACHE_WC);
    static_assert(tsbp_mmap_flags::CACHE_WP == (int)memory_types::CACHE_WP);
    static_assert(tsbp_mmap_flags::CACHE_WT == (int)memory_types::CACHE_WT);

    EFI_MEMORY_DESCRIPTOR *mmdesc = efi_memmap_ptr.get();
    EFI_MEMORY_DESCRIPTOR *mmdesc_end = (EFI_MEMORY_DESCRIPTOR *)((uintptr_t)mmdesc + memMapSize);

    uint64_t page_attr_writable = 0x2; // writable

    auto mem_type_for_efi_attr = [&](uint64_t attr) {
        if (attr & EFI_MEMORY_WB) return memory_types::CACHE_WB;
        if (attr & EFI_MEMORY_WT) return memory_types::CACHE_WT;
        if (attr & EFI_MEMORY_WP) return memory_types::CACHE_WP;
        if (attr & EFI_MEMORY_WC) return memory_types::CACHE_WC;
        return memory_types::CACHE_UC;
    };
    auto page_attrs_for_efi_mem = [&](uint32_t efi_type) {
        uint64_t attrs = 0;
        if (efi_type != EfiRuntimeServicesCode && efi_type != EfiUnusableMemory) {
            attrs |= page_attr_writable;
        }
        return attrs;
    };

    auto next_mmdesc_from = [&](EFI_MEMORY_DESCRIPTOR *mmdesc) {
        return (EFI_MEMORY_DESCRIPTOR *)((uintptr_t)mmdesc + memMapDescrSize);
    };

    do {
        auto mmdesc_phys_beg = mmdesc->PhysicalStart;
        auto mmdesc_phys_end = mmdesc->PhysicalStart + mmdesc->NumberOfPages * 4096u;

        if (mmdesc_phys_beg != 0 && mmdesc == efi_memmap_ptr.get()) {
            // Unusual to have nothing mapped at address 0, but let's handle it (we want
            // to ensure the entire first 4GB is mapped regardless of whether there is physical
            // memory present):
            auto low0_end = std::min(mmdesc_phys_beg, 4*PAGE1GB);
            do_mapping(0, low0_end, low0_end, memory_types::CACHE_UC, 0);
        }

        auto mem_type_this = mem_type_for_efi_attr(mmdesc->Attribute);
        auto page_attrs_this = page_attrs_for_efi_mem(mmdesc->Type);

        // Create a single mapping for as large a contiguous range as possible; break the range
        // if the memory type or permissions (Writable bit) changes
        EFI_MEMORY_DESCRIPTOR *next_mmdesc = next_mmdesc_from(mmdesc);
        while (next_mmdesc != mmdesc_end) {
            if (next_mmdesc->PhysicalStart != mmdesc_phys_end) {
                break;
            }

            auto mem_type_next = mem_type_for_efi_attr(next_mmdesc->Attribute);
            if (mem_type_this != mem_type_next) break;
            auto attrs_next = page_attrs_for_efi_mem(next_mmdesc->Type);
            if (attrs_next != page_attrs_this) break;

            // extend end to this next descriptor's end:
            mmdesc_phys_end = next_mmdesc->PhysicalStart + next_mmdesc->NumberOfPages * 4096u;

            next_mmdesc = next_mmdesc_from(next_mmdesc);
        }

        do_mapping(mmdesc_phys_beg, mmdesc_phys_beg, mmdesc_phys_end, mem_type_this, page_attrs_this);

        // Within the 1st 4GB, map everything (even if not in the memory map). This will encompass
        // the LAPIC and IOAPIC for example.
        if (mmdesc_phys_end < 4*PAGE1GB) {
            if (next_mmdesc != mmdesc_end && next_mmdesc->PhysicalStart != mmdesc_phys_end) {
                uintptr_t end_map_range = std::min(next_mmdesc->PhysicalStart, 4*PAGE1GB);
                do_mapping(mmdesc_phys_end, mmdesc_phys_end, end_map_range, memory_types::CACHE_UC, 0);
            }
            else {
                do_mapping(mmdesc_phys_end, mmdesc_phys_end, 4*PAGE1GB, memory_types::CACHE_UC, 0);
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
    loader_data.cmdline = cmdLine;
    loader_data.ramdisk = ramdisk;
    loader_data.ramdisk_size = ramdisk_size;
    // .memmap/.memmap_entries set below after construction of the map

    loader_data.acpi_rdsp = find_config_table(EFI_acpi20_table_guid);
    if (loader_data.acpi_rdsp == nullptr) {
        loader_data.acpi_rdsp = find_config_table(EFI_acpi_table_guid);
    }
    loader_data.smbios3_entry = find_config_table(EFI_smbios3_table_guid);

    // Framebuffer setup

    uint64_t fb_size = 0;
    uint64_t fb_region = 0;
    check_framebuffer(&loader_data);
    fb_size = loader_data.framebuffer_size;

    if (fb_size != 0) {
        // Need to map the framebuffer in
        uintptr_t fb_addr = loader_data.framebuffer_addr;
        fb_region = fb_addr;

        // See if there is an existing mapping for the framebuffer. There shouldn't be, but if there does
        // happen to be an overlapping mapping we'll assume that the the memory map entry gives the
        // total size.
        EFI_MEMORY_DESCRIPTOR *fb_desc = efi_memmap_find(fb_addr, efi_memmap_ptr.get(),
                memMapSize, memMapDescrSize);
        if (fb_desc != nullptr) {
            fb_region = fb_desc->PhysicalStart;
            fb_size = fb_desc->NumberOfPages * PAGE4KB;
        }

        do_mapping(fb_region, fb_region, fb_region + fb_size, memory_types::CACHE_WC, page_attr_writable);
    }

    if (fb_size == 0 && (ts_entry_header->flags & tosaithe_hdr_flags::REQ_FRAMEBUFFER)) {
        con_write(L"Framebuffer not available but required by kernel\r\n");
        return EFI_LOAD_ERROR;
    }

    // Now map low half into high half:
    for (int i = 0; i < 256; i++) {
        page_tables[i+256] = page_tables[i];
    }

    // And finally map the kernel:
    for (const auto &mapping : tsbp_kernel_map) {
        uint64_t attrs = mapping.flags & tsbp_kernel_mapping_flags::WRITE ? page_attr_writable : 0;
        do_mapping(mapping.base_virt, mapping.base_phys, mapping.base_phys + mapping.length,
                memory_types::CACHE_WB, attrs);
    }


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

    auto efi_attrib_to_tosaithe = [](uint64_t attr) {
        uint32_t rs = (attr & EFI_MEMORY_RUNTIME) ? tsbp_mmap_flags::UEFI_RUNTIME : 0;
        if (attr & EFI_MEMORY_WB) return tsbp_mmap_flags::CACHE_WB | rs;
        if (attr & EFI_MEMORY_WT) return tsbp_mmap_flags::CACHE_WT | rs;
        if (attr & EFI_MEMORY_WC) return tsbp_mmap_flags::CACHE_WC | rs;
        if (attr & EFI_MEMORY_WP) return tsbp_mmap_flags::CACHE_WP | rs;
        return tsbp_mmap_flags::CACHE_UC | rs;
    };

    // Copy entries from EFI memory map to our boot protocol map
    auto *efi_mem_iter = efi_memmap_ptr.get();
    auto *efi_mem_end = (EFI_MEMORY_DESCRIPTOR *)((char *)efi_memmap_ptr.get() + memMapSize);
    while (efi_mem_iter < efi_mem_end) {

        tsbp_mmap_type st_type;

        switch (efi_mem_iter->Type) {
        case EfiReservedMemoryType:
            st_type = tsbp_mmap_type::RESERVED;
            break;
        case EfiLoaderData:
            // TODO: we don't really need all EfiLoaderData to be marked reclaimable; the majority
            // is probably USABLE. Only memory that is specifically made available to the kernel
            // needs to be marked RECLAIMABLE.
            st_type = tsbp_mmap_type::BOOTLOADER_RECLAIMABLE;
            break;
        case EfiRuntimeServicesCode:
            st_type = tsbp_mmap_type::UEFI_RUNTIME_CODE;
            break;
        case EfiRuntimeServicesData:
            st_type = tsbp_mmap_type::UEFI_RUNTIME_DATA;
            break;
        case EfiLoaderCode:
        case EfiConventionalMemory:
        case EfiBootServicesCode:
        case EfiBootServicesData:
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
            st_type = tsbp_mmap_type::PERSISTENT_MEMORY;
            break;
        default:
            st_type = tsbp_mmap_type::RESERVED;
        }

        uint64_t number_of_pages = efi_mem_iter->NumberOfPages;
        EFI_PHYSICAL_ADDRESS physical_start = efi_mem_iter->PhysicalStart;

        // Merge BOOTLOADER_RECLAIMABLE sections
        if (st_type == tsbp_mmap_type::BOOTLOADER_RECLAIMABLE) {
            auto efi_mem_next = (EFI_MEMORY_DESCRIPTOR *)((char *)efi_mem_iter + memMapDescrSize);
            while (efi_mem_next < efi_mem_end) {
                if (efi_mem_next->Type != EfiLoaderData)
                    break;
                if (efi_mem_next->Attribute != efi_mem_iter->Attribute)
                    break;
                efi_mem_iter = efi_mem_next;
                number_of_pages += efi_mem_iter->NumberOfPages;
                efi_mem_next = (EFI_MEMORY_DESCRIPTOR *)((char *)efi_mem_iter + memMapDescrSize);
            }
        }
        // Similarly, merge various RESERVED sections
        else if (st_type == tsbp_mmap_type::RESERVED) {
            auto efi_mem_next = (EFI_MEMORY_DESCRIPTOR *)((char *)efi_mem_iter + memMapDescrSize);
            while (efi_mem_next < efi_mem_end) {
                if (efi_mem_next->Type != EfiMemoryMappedIO && efi_mem_next->Type != EfiMemoryMappedIOPortSpace
                        && efi_mem_next->Type != EfiPalCode)
                    break;
                if (efi_mem_next->Attribute != efi_mem_iter->Attribute)
                    break;
                efi_mem_iter = efi_mem_next;
                number_of_pages += efi_mem_iter->NumberOfPages;
                efi_mem_next = (EFI_MEMORY_DESCRIPTOR *)((char *)efi_mem_iter + memMapDescrSize);
            }
        }
        // And any USABLE sections
        else if (st_type == tsbp_mmap_type::USABLE) {
            auto efi_mem_next = (EFI_MEMORY_DESCRIPTOR *)((char *)efi_mem_iter + memMapDescrSize);
            while (efi_mem_next < efi_mem_end) {
                if (efi_mem_next->Type != EfiLoaderCode && efi_mem_next->Type != EfiConventionalMemory
                        && efi_mem_next->Type != EfiBootServicesCode && efi_mem_next->Type != EfiBootServicesData)
                    break;
                if (efi_mem_next->Attribute != efi_mem_iter->Attribute)
                    break;
                efi_mem_iter = efi_mem_next;
                number_of_pages += efi_mem_iter->NumberOfPages;
                efi_mem_next = (EFI_MEMORY_DESCRIPTOR *)((char *)efi_mem_iter + memMapDescrSize);
            }
        }

        tsbp_memmap.add_entry(st_type, physical_start, number_of_pages * 0x1000u,
                efi_attrib_to_tosaithe(efi_mem_iter->Attribute));
        efi_mem_iter = (EFI_MEMORY_DESCRIPTOR *)((char *)efi_mem_iter + memMapDescrSize);
    }

    // Insert memory-map entries for kernel
    tsbp_memmap.insert_entry(tsbp_mmap_type::KERNEL_AND_MODULES, kernel_alloc.get_ptr(),
            kernel_alloc.page_count() * PAGE4KB, tsbp_mmap_flags::CACHE_WB);

    if (fb_size != 0) {
        tsbp_memmap.insert_entry(tsbp_mmap_type::FRAMEBUFFER, fb_region, fb_size, tsbp_mmap_flags::CACHE_WC);
    }

    tsbp_memmap.sort();

    loader_data.memmap = tsbp_memmap.get();
    loader_data.memmap_entries = tsbp_memmap.get_size();
    loader_data.kern_map = tsbp_kernel_map.data();
    loader_data.kern_map_entries = tsbp_kernel_map.size();

    loader_data.efi_memmap = efi_memmap_ptr.get();
    loader_data.efi_memmap_descr_size = memMapDescrSize;
    loader_data.efi_memmap_size = memMapSize;
    loader_data.efi_system_table = EST;

    // TODO modules

    // Enable paging (4-level)

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
            con_write(L"Error: could not retrieve EFI memory map\r\n");
            return EFI_LOAD_ERROR;
        }

        // we've already got the EFI memory map now, so skip that step and just rebuild the tosaithe memory
        // map:
        goto retrieve_efi_memmap_2;
    }

    // Now, put our page tables in place:

    asm volatile (
            "cli\n"

            // make sure paging is disabled, otherwise we can't set PAE/LA57
            //"movq %%cr0, %%rax\n"
            //"andl $0x7FFFFFFF, %%eax\n"
            //"movq %%rax, %%cr0\n"

            // Set up PAT (as per memory_types:: enum)
            //  0 - 06 - Write-back (WB)
            //  1 - 04 - Write-throught (WT)
            //  2 - 07 - Uncached, overridable by MTRRs (UC-)
            //  3 - 00 - Uncached (UC)
            //  4 - 05 - Write protected (WP)
            //  5 - 01 - Write combining (WC)
            "movl $0x00070406, %%eax\n"
            "movl $0x00000105, %%edx\n"
            "movl $0x277, %%ecx\n"  // IA32_PAT
            "wrmsr\n"

            // put our own page tables in place:
            "movq %0, %%rax\n"
            "movq %%rax, %%cr3\n"

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
                    "pushq %1\n"       // RSP
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
