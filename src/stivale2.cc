#include <elf.h>

#include "uefi.h"
#include "uefi-media-file.h"
#include "uefi-loadedimage.h"
#include "stivale2.h"

#include "tosaithe-util.h"

extern EFI_BOOT_SERVICES *EBS;

// Class to manage building a Stivale2 memory map structure
class tosaithe_stivale2_memmap {
    stivale2_struct_tag_memmap *st2_memmap = nullptr;
    uint32_t capacity = 0;

    bool increase_capacity()
    {
        auto &entries = st2_memmap->entries;

        uint32_t newcapacity = capacity + 6; // bump capacity by arbitrary amount
        uint32_t req_size = sizeof(stivale2_struct_tag_memmap)
                + sizeof(stivale2_mmap_entry) * newcapacity;
        stivale2_struct_tag_memmap *newmap = (stivale2_struct_tag_memmap *) alloc(req_size);
        if (newmap == nullptr) {
            return false;
        }

        // Copy map from old to new storage
        new(newmap) stivale2_struct_tag_memmap(*st2_memmap);
        for (uint32_t i = 0; i < entries; i++) {
            new(&newmap->memmap[entries]) stivale2_mmap_entry(st2_memmap->memmap[entries]);
        }

        freePool(st2_memmap);
        st2_memmap = newmap;
        capacity = newcapacity;

        return true;
    }

public:
    bool allocate(uint32_t capacity_p)
    {
        uint32_t req_size = sizeof(stivale2_struct_tag_memmap)
                + sizeof(stivale2_mmap_entry) * capacity_p;
        st2_memmap = (stivale2_struct_tag_memmap *) alloc(req_size);
        if (st2_memmap == nullptr) {
            return false;
        }
        new(st2_memmap) stivale2_struct_tag_memmap();
        st2_memmap->tag.identifier = STIVALE2_LT_MMAP_IDENT;
        st2_memmap->tag.next = nullptr;
        st2_memmap->entries = 0;
        capacity = capacity_p;
        return true;
    }

    bool add_entry(stivale2_mmap_type type_p, uint64_t physaddr, uint64_t length)
    {
        auto &entries = st2_memmap->entries;

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
        entries++;

        return true;
    }

    // Insert an entry, which should be making use of available space only.
    // On failure, returns false; in that case integrity of the map is no longer guaranteed.
    // On success returns true: beware, map may require sorting
    bool insert_entry(stivale2_mmap_type type_p, uint64_t physaddr, uint64_t length)
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

    void sort()
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

    stivale2_struct_tag_memmap *get()
    {
        return st2_memmap;
    }

    ~tosaithe_stivale2_memmap()
    {
        if (st2_memmap != nullptr) {
            freePool(st2_memmap);
        }
    }
};

EFI_STATUS load_stivale2(EFI_HANDLE ImageHandle, const CHAR16 *exec_path, const CHAR16 *cmdLine)
{
    EFI_LOADED_IMAGE_PROTOCOL *imageProto;
    EFI_STATUS status = EBS->HandleProtocol(ImageHandle,
            &EFI_loaded_image_protocol_guid, (void **)&imageProto);
    // status must be EFI_SUCCESS?

    EFI_DEVICE_PATH_PROTOCOL *imageDevicePath = nullptr;
    if (EBS->HandleProtocol(ImageHandle, &EFI_loaded_image_device_path_protocol_guid,
            (void **)&imageDevicePath) != EFI_SUCCESS) {
        con_write(L"Image does not support loaded-image device path protocol.\r\n");
        return EFI_LOAD_ERROR;
    }

    if (imageDevicePath == nullptr) {
        ConOut->OutputString(ConOut, L"Firmware misbehaved; don't have loaded image device path.\r\n");
        return EFI_LOAD_ERROR;
    }

    unsigned exec_path_size = (strlen(exec_path) + 1) * sizeof(CHAR16);
    EFI_DEVICE_PATH_PROTOCOL *kernel_path = switch_path(imageDevicePath, exec_path, exec_path_size);
    if (kernel_path == nullptr) {
        return EFI_LOAD_ERROR;
    }

    // Allocate space for kernel file
    // For now we'll load the fixed 0x200000 - 0x1000, the -0x1000 is for the file header.
    EFI_PHYSICAL_ADDRESS kernelAddr = 0x200000u - 0x1000u;
    UINTN kernelPages = (0x200000u + 0x1000u)/0x1000u;
    status = EBS->AllocatePages(AllocateAddress, EfiLoaderCode, kernelPages, &kernelAddr);
    if (EFI_ERROR(EFI_SUCCESS)) {
        ConOut->OutputString(ConOut, L"Couldn't allocate kernel memory at 0x200000u\r\n");
        freePool(kernel_path);
        return EFI_LOAD_ERROR;
    }

    con_write(L"Allocated kernel memory at 0x200000u\r\n"); // XXX

    // Try to load the kernel now
    EFI_HANDLE loadDevice;

    status = EBS->LocateDevicePath(&EFI_simple_file_system_protocol_guid, &kernel_path, &loadDevice);
    freePool(kernel_path);
    if (EFI_ERROR(EFI_SUCCESS)) {
        ConOut->OutputString(ConOut, L"Couldn't get file system protocol for kernel path\r\n");
        EBS->FreePages(kernelAddr, kernelPages);
        return EFI_LOAD_ERROR;
    }

    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *sfsProtocol = nullptr;

    status = EBS->HandleProtocol(loadDevice, &EFI_simple_file_system_protocol_guid,
            (void **)&sfsProtocol);
    if (EFI_ERROR(EFI_SUCCESS) || (sfsProtocol == nullptr /* firmware misbehaving */)) {
        ConOut->OutputString(ConOut, L"Couldn't get file system protocol for kernel path\r\n");
        EBS->FreePages(kernelAddr, kernelPages);
        return EFI_LOAD_ERROR;
    }

    EFI_FILE_PROTOCOL *fsRoot = nullptr;
    status = sfsProtocol->OpenVolume(sfsProtocol, &fsRoot);
    if (EFI_ERROR(EFI_SUCCESS) || (fsRoot == nullptr /* firmware misbehaving */)) {
        ConOut->OutputString(ConOut, L"Couldn't open volume (fs protocol)\r\n");
        EBS->FreePages(kernelAddr, kernelPages);
        return EFI_LOAD_ERROR;
    }

    EFI_FILE_PROTOCOL *kernelFile = nullptr;
    status = fsRoot->Open(fsRoot, &kernelFile, exec_path, EFI_FILE_MODE_READ, 0);
    fsRoot->Close(fsRoot);
    if (EFI_ERROR(EFI_SUCCESS) || kernelFile == nullptr) {
        ConOut->OutputString(ConOut, L"Couldn't open kernel file\r\n");
        EBS->FreePages(kernelAddr, kernelPages);
        return EFI_LOAD_ERROR;
    }


    EFI_FILE_INFO *kernelFileInfo = getFileInfo(kernelFile);
    if (kernelFileInfo == nullptr) {
        EBS->FreePages(kernelAddr, kernelPages);
        kernelFile->Close(kernelFile);
        ConOut->OutputString(ConOut, L"Couldn't get kernel file size\r\n");
        return EFI_LOAD_ERROR;
    }

    con_write(L"Kernel file size: "); con_write(kernelFileInfo->FileSize); con_write(L"\r\n"); // XXX

    UINTN readAmount = kernelFileInfo->FileSize;

    status = kernelFile->Read(kernelFile, &readAmount, (void *)kernelAddr);
    kernelFile->Close(kernelFile);
    if (EFI_ERROR(status)) {
        ConOut->OutputString(ConOut, L"Couldn't read kernel file; ");
        if (status == EFI_NO_MEDIA) {
            ConOut->OutputString(ConOut, L"status: NO_MEDIA\r\n");
        }
        else if (status == EFI_DEVICE_ERROR) {
            ConOut->OutputString(ConOut, L"status: DEVICE_ERROR\r\n");
        }
        else if (status == EFI_VOLUME_CORRUPTED) {
            ConOut->OutputString(ConOut, L"status: VOLUME_CORRUPTED\r\n");
        }
        else if (status == EFI_BUFFER_TOO_SMALL) {
            ConOut->OutputString(ConOut, L"status: BUFFER_TOO_SMALL\r\n");
        }
        else {
            ConOut->OutputString(ConOut, L"status not recognized, misbehaving firmware?\r\n");
            CHAR16 errcode[3];
            errcode[2] = 0;
            errcode[1] = hexdigit(status & 0xFu);
            errcode[0] = hexdigit((status >> 4) & 0xFu);
            ConOut->OutputString(ConOut, L"    EFI status: 0x");
            ConOut->OutputString(ConOut, errcode);
            ConOut->OutputString(ConOut, L"\r\n");
        }
        EBS->FreePages(kernelAddr, kernelPages);
        return EFI_LOAD_ERROR;
    }
    else {
        ConOut->OutputString(ConOut, L"Loaded kernel (!!)\r\n"); // XXX
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

    EFI_PHYSICAL_ADDRESS pageTablesPhysaddr;
    PDE *pageTables;
    const UINTN pageTablesPages = 2;
    if (EFI_ERROR(EBS->AllocatePages(AllocateAnyPages, EfiLoaderCode, pageTablesPages,
            &pageTablesPhysaddr))) {
        con_write(L"*** Memory allocation failed ***\r\n");
        EBS->FreePages(kernelAddr, kernelPages);
        return EFI_LOAD_ERROR;
    }

    // initialise all entries as "not present"
    pageTables = (PDE *)pageTablesPhysaddr;
    for (unsigned i = 0; i < 512; i++) {
        pageTables[i] = PDE{0}; // not present
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
    uint64_t PDPTaddress = pageTablesPhysaddr + 0x1000;
    pageTables[0] = PDE{PDPTaddress | 0x7}; // present, writable, user-accessible
    pageTables[256] = PDE{PDPTaddress | 0x7};
    pageTables[511] = PDE{PDPTaddress | 0x7};

    // 2nd level page tables:
    for (unsigned int i = 0; i < 512; i++) {
        // address || Page size (1GB page) || present, writable, user-accessible
        pageTables[512 + i] = PDE{uint64_t(i) * 1024UL*1024UL*1024UL | (1UL << 7) | 0x7UL};
    }
    // Map 2G at tail back to start (i.e. map 0xFFFFFFFF80000000 -> 0).
    pageTables[512 + 510] = pageTables[512];
    pageTables[512 + 511] = pageTables[513];

    // Set up Stivale2 tags
    stivale2_struct stivale2_info = { "tosaithe", "0.1", nullptr };

    // Build Stivale2 memory map from EFI memory map

    UINTN memMapSize = 0;
    UINTN memMapKey = 0;
    UINTN memMapDescrSize = 0;
    uint32_t memMapDescrVersion = 0;
    status = EBS->GetMemoryMap(&memMapSize, nullptr, &memMapKey, &memMapDescrSize, &memMapDescrVersion);
    if (status != EFI_BUFFER_TOO_SMALL) {
        con_write(L"*** Could not retrieve EFI memory map ***\r\n");
        EBS->FreePages((EFI_PHYSICAL_ADDRESS)pageTables, pageTablesPages);
        EBS->FreePages(kernelAddr, kernelPages);
        return EFI_LOAD_ERROR;
    }

    EFI_MEMORY_DESCRIPTOR *efiMemMap = (EFI_MEMORY_DESCRIPTOR *) alloc(memMapSize);
    if (efiMemMap == nullptr) {
        con_write(L"*** Memory allocation failed ***\r\n");
        EBS->FreePages((EFI_PHYSICAL_ADDRESS)pageTables, pageTablesPages);
        EBS->FreePages(kernelAddr, kernelPages);
        return EFI_LOAD_ERROR;
    }

    status = EBS->GetMemoryMap(&memMapSize, efiMemMap, &memMapKey, &memMapDescrSize, &memMapDescrVersion);
    while (status == EFI_BUFFER_TOO_SMALL) {
        // Above allocation may have increased size of memory map, so we keep trying
        freePool(efiMemMap);
        efiMemMap = (EFI_MEMORY_DESCRIPTOR *) alloc(memMapSize);
        if (efiMemMap == nullptr) {
            con_write(L"*** Memory allocation failed ***\r\n");
            EBS->FreePages((EFI_PHYSICAL_ADDRESS)pageTables, pageTablesPages);
            EBS->FreePages(kernelAddr, kernelPages);
            return EFI_LOAD_ERROR;
        }
        status = EBS->GetMemoryMap(&memMapSize, efiMemMap, &memMapKey, &memMapDescrSize, &memMapDescrVersion);
    }

    if (EFI_ERROR(status)) {
        con_write(L"*** Could not retrieve EFI memory map ***\r\n");
        freePool(efiMemMap);
        EBS->FreePages((EFI_PHYSICAL_ADDRESS)pageTables, pageTablesPages);
        EBS->FreePages(kernelAddr, kernelPages);
        return EFI_LOAD_ERROR;
    }

    // Allocate Stivale2 memmap
    tosaithe_stivale2_memmap st2_memmap;
    if (!st2_memmap.allocate(memMapSize / memMapDescrSize + 6)) { // +6 for wiggle room
        con_write(L"*** Memory allocation failed ***\r\n");
        freePool(efiMemMap);
        EBS->FreePages((EFI_PHYSICAL_ADDRESS)pageTables, pageTablesPages);
        EBS->FreePages(kernelAddr, kernelPages);
        return EFI_LOAD_ERROR;
    }

    // Copy entries from EFI memory map to Stivale2 map
    auto *efi_mem_iter = efiMemMap;
    auto *efi_mem_end = (EFI_MEMORY_DESCRIPTOR *)((char *)efiMemMap + memMapSize);
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

    freePool(efiMemMap);

    // TODO calculate kernelSize including bss / stack
    uint64_t kernelSize = ((readAmount - 0x1000u + 0xFFFu) / 0x1000u) * 0x1000u;

    st2_memmap.insert_entry(stivale2_mmap_type::KERNEL_AND_MODULES, kernelAddr, kernelSize);

    // Framebuffer setup

    stivale2_struct_tag_framebuffer fbinfo;
    fbinfo.tag.identifier = STIVALE2_LT_FRAMEBUFFER_IDENT;
    fbinfo.tag.next = nullptr;

    EFI_GRAPHICS_OUTPUT_PROTOCOL *graphics =
            (EFI_GRAPHICS_OUTPUT_PROTOCOL *) locateProtocol(EFI_graphics_output_protocol_guid);;
    if (graphics == nullptr) {
        con_write(L"No graphics protocol available.\r\n");
        // TODO so what, just don't pass one to kernel
        EBS->FreePages((EFI_PHYSICAL_ADDRESS)pageTables, pageTablesPages);
        EBS->FreePages(kernelAddr, kernelPages);
        return EFI_LOAD_ERROR;
    }

    switch(graphics->Mode->Info->PixelFormat) {
    case PixelRedGreenBlueReserved8BitPerColor:
        fbinfo.blue_mask_shift = 16;
        fbinfo.blue_mask_size = 8;
        fbinfo.green_mask_shift = 8;
        fbinfo.green_mask_size = 8;
        fbinfo.red_mask_shift = 0;
        fbinfo.red_mask_size = 8;
        fbinfo.framebuffer_bpp = 32;
        break;
    case PixelBlueGreenRedReserved8BitPerColor:
        fbinfo.blue_mask_shift = 0;
        fbinfo.blue_mask_size = 8;
        fbinfo.green_mask_shift = 8;
        fbinfo.green_mask_size = 8;
        fbinfo.red_mask_shift = 16;
        fbinfo.red_mask_size = 8;
        fbinfo.framebuffer_bpp = 32;
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

        fbinfo.red_mask_shift = count_shift(graphics->Mode->Info->PixelInformation.RedMask);
        fbinfo.red_mask_size = count_size(graphics->Mode->Info->PixelInformation.RedMask, fbinfo.red_mask_shift);
        fbinfo.green_mask_shift = count_shift(graphics->Mode->Info->PixelInformation.GreenMask);
        fbinfo.green_mask_size = count_size(graphics->Mode->Info->PixelInformation.GreenMask, fbinfo.green_mask_shift);
        fbinfo.blue_mask_shift = count_shift(graphics->Mode->Info->PixelInformation.BlueMask);
        fbinfo.blue_mask_size = count_size(graphics->Mode->Info->PixelInformation.BlueMask, fbinfo.blue_mask_shift);

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

        fbinfo.framebuffer_bpp = max(highest_bit(graphics->Mode->Info->PixelInformation.RedMask),
                highest_bit(graphics->Mode->Info->PixelInformation.GreenMask),
                highest_bit(graphics->Mode->Info->PixelInformation.BlueMask),
                highest_bit(graphics->Mode->Info->PixelInformation.ReservedMask));

        break;
    }
    default:
        con_write(L"Graphics mode is not supported.\r\n");
        // TODO don't fail, just don't pass framebuffer to kernel...
        EBS->FreePages((EFI_PHYSICAL_ADDRESS)pageTables, pageTablesPages);
        EBS->FreePages(kernelAddr, kernelPages);
        return EFI_LOAD_ERROR;
    }

    fbinfo.memory_model = 1;
    fbinfo.framebuffer_addr = graphics->Mode->FrameBufferBase;
    fbinfo.framebuffer_width = graphics->Mode->Info->HorizontalResolution;
    fbinfo.framebuffer_height = graphics->Mode->Info->VerticalResolution;
    fbinfo.framebuffer_pitch = graphics->Mode->Info->PixelsPerScanLine * (fbinfo.framebuffer_bpp / 8u);

    uint64_t fb_size = (((uint64_t)graphics->Mode->FrameBufferSize) + 0xFFFu) / 0x1000u * 0x1000u;

    st2_memmap.insert_entry(stivale2_mmap_type::FRAMEBUFFER, fbinfo.framebuffer_addr, fb_size);
    st2_memmap.sort();

    // Set up tag chain: memmap, framebuffer

    stivale2_struct_tag_memmap *st2_memmap_tag = st2_memmap.get();
    stivale2_info.tags = &st2_memmap_tag->tag;
    st2_memmap_tag->tag.next = &fbinfo.tag;

    // Exit boot services

    // (for later: SetVirtualMemoryMap to allow EFI runtime services to be used in kernel mode)

    // Jump into kernel (incl. switch stack)


    // Enable paging (4-level)

    // IA32_EFER = 0xC0000080
    // bit 0 enables SYSCALL/SYSRET [0x1]
    // bit 8 = IA-32e mode enable  [0x100]
    // bit 11 = enable NX bit (no-execute)  [0x800]

    // Cannot do the following in long mode, need to transition to 32-bit mode to disable paging,
    // sigh. Since we currently only handle 4-level paging, we need to make sure 5-level paging
    // isn't enabled:

    uint64_t cr4flags;

    asm volatile (
            "movq %%cr4, %%rax"
            : "=a"(cr4flags)
    );

    con_write(L"cr4 flags = "); con_write(cr4flags); con_write(L"\r\n");
    if (cr4flags & 0x1000) {
        con_write(L"Uh-oh, LA57 is enabled :(\r\n");  // TODO
        EBS->FreePages((EFI_PHYSICAL_ADDRESS)pageTables, pageTablesPages);
        EBS->FreePages(kernelAddr, kernelPages);
        return EFI_LOAD_ERROR;
    }

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
            : "rm"(pageTablesPhysaddr)
            : "eax", "ecx", "edx"
    );


    typedef void (*stivale_entry_t)(stivale2_struct *);
    Elf64_Ehdr *elf_hdr = (Elf64_Ehdr *) kernelAddr;

    stivale_entry_t stivale_entry = (stivale_entry_t) elf_hdr->e_entry;

    asm volatile (
            "callq *%0\n"
            :
            : "r"(stivale_entry), "D"(&stivale2_info)
    );

    return EFI_SUCCESS;
}
