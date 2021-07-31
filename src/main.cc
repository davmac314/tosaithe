#include <stddef.h>

#include "uefi.h"
#include "uefi-loadedimage.h"
#include "uefi-devicepath.h"
#include "uefi-media-file.h"

#include "stivale2.h"

#include "elf.h"

EFI_BOOT_SERVICES *EBS;
EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *ConOut;

// Placement new:
inline void * operator new(size_t count, void *addr)
{
    return addr;
}

// Locate a protocol by finding a singular handle supporting it
static void *locateProtocol(const EFI_GUID &guid)
{
    void *interfacePtr = nullptr;

    if (EBS->Hdr.Revision >= 0x110) {
        // Note, we fallback if this is not available to searching for a handle which provides
        // the protocol. But that doesn't seem to work with current OVMF, in that LocateHandle
        // returns success with 1 handle, but that 1 handle is null :(
        // Anyway, this should work...
        EBS->LocateProtocol(&guid, nullptr, &interfacePtr);
        return interfacePtr;
    }

    EFI_HANDLE locatedHandle;
    UINTN handleBufsize = sizeof(locatedHandle);

    EFI_STATUS status = EBS->LocateHandle(ByProtocol,
            &guid, nullptr, &handleBufsize, &locatedHandle);
    if (status != EFI_SUCCESS) {
        return nullptr;
    }

    // This should succeed.
    EBS->HandleProtocol(locatedHandle, &guid, &interfacePtr);

    return interfacePtr;
}

static void *alloc(unsigned size)
{
    void *allocdBuf;
    EFI_STATUS status = EBS->AllocatePool(EfiLoaderCode, size, &allocdBuf);
    if (EFI_ERROR(status)) {
        return nullptr;
    }
    return allocdBuf;
}

static void freePool(void *buf)
{
    EBS->FreePool(buf);
}

static void con_write(const CHAR16 *str)
{
    ConOut->OutputString(ConOut, str);
}

static void con_write(uint64_t val)
{
    CHAR16 buf[21];

    unsigned pos = 20;
    buf[20] = 0;

    do {
        unsigned digit = val % 10;
        val = val / 10;
        pos--;
        buf[pos] = digit + '0';
    } while (val > 0);

    con_write(buf + pos);
}

static unsigned strlen(const CHAR16 *str)
{
    unsigned i = 0;
    while (str[i] != 0) {
        i++;
    }
    return i;
}

static CHAR16 *strdup(CHAR16 *str)
{
    unsigned len = strlen(str);
    CHAR16 *rbuf = (CHAR16 *) alloc(len);
    if (rbuf == nullptr) {
        return nullptr;
    }

    for (unsigned i = 0; i < len; i++) {
        rbuf[i] = str[i];
    }

    return rbuf;
}

static CHAR16 hexdigit(int val)
{
    if (val < 10) {
        return L'0' + val;
    }
    return L'A' + val;
}

template <typename T> void swap(T &a, T &b)
{
    T temp = a;
    a = b;
    b = temp;
}

// Find the file path (if any) device node in the device path (it should be the last node
// before the end-of-instance marker, if present) and return the offset. Return (unsigned)-1
// if not found.
static unsigned find_file_path(const EFI_DEVICE_PATH_PROTOCOL *dp)
{
    typedef unsigned char byte;
    byte *dp_u8_start = (byte *)dp;
    byte *dp_u8 = dp_u8_start;

    uint8_t dpn_type = dp_u8[0];
    while(dpn_type != 0x7F) {
        if (dpn_type == 0x04) {
            uint8_t dpn_subtype = dp_u8[1];
            if (dpn_subtype == 0x04) {
                return dp_u8 - dp_u8_start;
            }
        }

        uint16_t len = dp_u8[2] + (dp_u8[3] << 8);
        dp_u8 += len;
        dpn_type = dp_u8[0];
    }

    return -1;
}

// Switch out the file path part in a device path for another file path. Writes error message
// and returns null on failure.
// Params:
//   dp - original device path
//   new_path - the new file path, with null terminator
//   new_path_len - length in *bytes*, includes null terminator
static EFI_DEVICE_PATH_PROTOCOL *switch_path(const EFI_DEVICE_PATH_PROTOCOL *dp,
        const CHAR16 *new_path, unsigned new_path_len)
{
    unsigned path_offs = find_file_path(dp);
    unsigned new_node_size = new_path_len + 4;
    unsigned req_size = path_offs + new_node_size + 4; // terminator node

    unsigned char *allocdBuf = (unsigned char *) alloc(req_size);
    if (allocdBuf == nullptr) {
        ConOut->OutputString(ConOut, L"*** Pool allocation failed ***\r\n");
        return nullptr;
    }

    // Copy source up to path_offs
    unsigned char *srcBuf = (unsigned char *)dp;
    for (unsigned i = 0; i < path_offs; i++) {
        allocdBuf[i] = srcBuf[i];
    }

    // Create new path node
    allocdBuf[path_offs] = 0x4;
    allocdBuf[path_offs+1] = 0x4;
    allocdBuf[path_offs+2] = new_node_size & 0xFFu;
    allocdBuf[path_offs+3] = (new_node_size >> 8) & 0xFFu;

    srcBuf = (unsigned char *)new_path;
    for (unsigned i = 0; i < new_path_len; i++) {
        allocdBuf[path_offs+4 + i] = srcBuf[i];
    }

    // Add terminator node
    unsigned terminatorOffs = path_offs + new_node_size;
    allocdBuf[terminatorOffs] = 0x7Fu;
    allocdBuf[terminatorOffs+1] = 0xFFu;
    allocdBuf[terminatorOffs+2] = 4; // length, low byte
    allocdBuf[terminatorOffs+3] = 0; // length, high byte

    return (EFI_DEVICE_PATH_PROTOCOL *)allocdBuf;
}

static EFI_FILE_INFO *getFileInfo(EFI_FILE_PROTOCOL *file)
{
    UINTN bufferSize = 128;
    EFI_FILE_INFO *buffer = (EFI_FILE_INFO *) alloc(bufferSize);
    if (buffer == nullptr) {
        return nullptr;
    }

    EFI_STATUS status = file->GetInfo(file, &EFI_file_info_id, &bufferSize, buffer);
    if (status == EFI_BUFFER_TOO_SMALL) {
        freePool(buffer);
        // bufferSize has now been updated:
        buffer = (EFI_FILE_INFO *) alloc(bufferSize);
        if (buffer == nullptr) {
            return nullptr;
        }

        status = file->GetInfo(file, &EFI_file_info_id, &bufferSize, buffer);
    }

    if (EFI_ERROR(status)) {
        freePool(buffer);
        return nullptr;
    }

    return buffer;
}

// Load an entire file, in a block of allocated pages
void *loadEntireFile(EFI_DEVICE_PATH_PROTOCOL *devPath, UINTN *bufSize)
{
    EFI_HANDLE loadDevice;
    EFI_STATUS status = EBS->LocateDevicePath(&EFI_simple_file_system_protocol_guid, &devPath, &loadDevice);
    if (EFI_ERROR(status)) {
        ConOut->OutputString(ConOut, L"Couldn't get file system protocol for file's device path\r\n");
        return nullptr;
    }

    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *sfsProtocol = nullptr;

    status = EBS->HandleProtocol(loadDevice, &EFI_simple_file_system_protocol_guid, (void **)&sfsProtocol);
    if (EFI_ERROR(status)) {
        ConOut->OutputString(ConOut, L"Couldn't get file system protocol for file path\r\n");
        return nullptr;
    }
    if (sfsProtocol == nullptr) {
        ConOut->OutputString(ConOut, L"Couldn't get file system protocol for file path (firmware misbehaving)\r\n");
        return nullptr;
    }

    EFI_FILE_PROTOCOL *fsRoot = nullptr;
    status = sfsProtocol->OpenVolume(sfsProtocol, &fsRoot);
    if (EFI_ERROR(status)) {
        ConOut->OutputString(ConOut, L"Couldn't open volume (fs protocol)\r\n");
        return nullptr;
    }
    if (fsRoot == nullptr) {
        ConOut->OutputString(ConOut, L"Couldn't open volume (fs protocol); firmware misbehaving\r\n");
        return nullptr;
    }

    // Need to convert remaining path to string path (within filesystem)
    EFI_DEVICE_PATH_TO_TEXT_PROTOCOL *dpToTextProto =
            (EFI_DEVICE_PATH_TO_TEXT_PROTOCOL *)locateProtocol(EFI_device_path_to_text_protocol_guid);

    if (dpToTextProto == nullptr) {
        con_write(L"Firmware doesn't support DEVICE_PATH_TO_TEXT protocol\r\n");
        // TODO combine the path ourselves
        fsRoot->Close(fsRoot);
        return nullptr;
    }

    CHAR16 *filePath = dpToTextProto->ConvertDevicePathToText(devPath,
            false /* displayOnly */, false /* allowShortcuts */);

    EFI_FILE_PROTOCOL *fileToLoad = nullptr;
    status = fsRoot->Open(fsRoot, &fileToLoad, filePath, EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(status) || fileToLoad == nullptr) {
        ConOut->OutputString(ConOut, L"Couldn't open file\r\n");
        freePool(filePath);
        fsRoot->Close(fsRoot);
        return nullptr;
    }

    EFI_FILE_INFO *loadFileInfo = getFileInfo(fileToLoad);
    if (loadFileInfo == nullptr) {
        ConOut->OutputString(ConOut, L"Couldn't get file size\r\n");
    }

    UINTN readAmount = loadFileInfo->FileSize;
    EFI_PHYSICAL_ADDRESS loadAddress = 0;
    freePool(loadFileInfo);

    status = EBS->AllocatePages(AllocateAnyPages, EfiLoaderCode, (readAmount + 0xFFF)/0x1000u, &loadAddress);
    if (EFI_ERROR(status)) {
        con_write(L"Couldn't allocate memory to load file");
        fileToLoad->Close(fileToLoad);
        fsRoot->Close(fsRoot);
        return nullptr;
    }

    status = fileToLoad->Read(fileToLoad, &readAmount, (void *)loadAddress);
    if (EFI_ERROR(status)) {
        ConOut->OutputString(ConOut, L"Couldn't read file; ");
        CHAR16 errcode[3];
        errcode[2] = 0;
        errcode[1] = hexdigit(status & 0xFu);
        errcode[0] = hexdigit((status >> 4) & 0xFu);
        ConOut->OutputString(ConOut, L"EFI status: 0x");
        ConOut->OutputString(ConOut, errcode);
        ConOut->OutputString(ConOut, L"\r\n");
    }

    fileToLoad->Close(fileToLoad);
    fsRoot->Close(fsRoot);

    if (bufSize) *bufSize = readAmount;
    return (void *)loadAddress;
}

static EFI_STATUS chainLoad(EFI_HANDLE ImageHandle, const CHAR16 *ExecPath, const CHAR16 *cmdLine)
{
    EFI_DEVICE_PATH_PROTOCOL *imageDevicePathProto = nullptr;
    if (EFI_ERROR(EBS->HandleProtocol(ImageHandle, &EFI_loaded_image_device_path_protocol_guid,
            (void **)&imageDevicePathProto))) {
        con_write(L"Image does not support loaded-image device path protocol.\r\n");
        return EFI_LOAD_ERROR;
    }

    if (imageDevicePathProto == nullptr) {
        con_write(L"Firmware misbehaved; don't have loaded image device path.\r\n");
        return EFI_LOAD_ERROR;
    }

    // Construct a device path for the chain load image, by finding our own device path and
    // basing the new path on it.

    EFI_DEVICE_PATH_PROTOCOL *chainPath = switch_path(imageDevicePathProto, ExecPath,
            (strlen(ExecPath) + 1) * sizeof(CHAR16));
    if (chainPath == nullptr) {
        return EFI_LOAD_ERROR;
    }

    // Now load the image

    EFI_HANDLE loadedHandle = nullptr;
    EFI_STATUS status = EBS->LoadImage(true, ImageHandle, chainPath, nullptr, 0, &loadedHandle);

    freePool(chainPath);

    if (EFI_ERROR(status)) {
        con_write(L"Couldn't chain-load image: ");
        con_write(ExecPath);
        con_write(L"\r\n");
        return EFI_LOAD_ERROR;
    }

    // Set load options, and run the image

    EFI_LOADED_IMAGE_PROTOCOL *chainedImageLIP;
    status = EBS->HandleProtocol(loadedHandle, &EFI_loaded_image_protocol_guid,
            (void **)&chainedImageLIP);

    chainedImageLIP->LoadOptions = const_cast<void *>((const void *)cmdLine);
    chainedImageLIP->LoadOptionsSize = (strlen(cmdLine) + 1) * sizeof(CHAR16);

    status = EBS->StartImage(loadedHandle, nullptr, nullptr);

    return status;
}

EFI_STATUS load_stivale2(EFI_HANDLE ImageHandle, const CHAR16 *exec_path, const CHAR16 *cmdLine);

extern "C"
EFI_STATUS
EFIAPI
EfiMain (
    IN EFI_HANDLE        ImageHandle,
    IN EFI_SYSTEM_TABLE  *SystemTable
    )
{
    /*
    volatile int doWait = 1;
    while (doWait) {
        asm volatile ("pause\n");
    }
    */

    EBS = SystemTable->BootServices;
    ConOut = SystemTable->ConOut;

    ConOut->ClearScreen(ConOut);

    con_write(L"Stigorge boot menu\r\n");
    con_write(L"Firmware vendor: ");
    con_write(SystemTable->FirmwareVendor);
    con_write(L"\r\n\r\n");

    ConOut->SetAttribute(ConOut, EFI_YELLOW);
    con_write(L"Please make a selection:\r\n\r\n");
    ConOut->SetAttribute(ConOut, EFI_LIGHTCYAN);

    con_write(L"1. Linux - vmlinuz-5.10.47-pstore root=/dev/nvme0n1p2\r\n");
    con_write(L"2. EFI shell\r\n");
    con_write(L"3. Badux\r\n");

    ConOut->SetAttribute(ConOut, EFI_LIGHTGRAY);
    con_write(L"\r\n=>");

    UINTN eventIndex = 0;
    EBS->WaitForEvent(1, &SystemTable->ConIn->WaitForKey, &eventIndex);

    EFI_INPUT_KEY keyPr;
    if (EFI_ERROR(SystemTable->ConIn->ReadKeyStroke(SystemTable->ConIn, &keyPr))) {
        con_write(L"Error reading keyboard.\r\n");
        return EFI_LOAD_ERROR;
    }

    // Echo key
    ConOut->SetAttribute(ConOut, EFI_WHITE);
    CHAR16 keyStr[4];
    keyStr[0] = keyPr.UnicodeChar;
    keyStr[1] = L'\r'; keyStr[2] = L'\n';
    keyStr[3] = 0;
    con_write(keyStr);
    ConOut->SetAttribute(ConOut, EFI_LIGHTGRAY);

    if (keyPr.UnicodeChar == L'1') {
        return chainLoad(ImageHandle, L"\\vmlinuz-5.10.47-pstore", L"linux root=/dev/nvme0n1p2");
    } else if (keyPr.UnicodeChar == L'2') {
        return chainLoad(ImageHandle, L"\\EFI\\Shell.efi", L"Shell.efi");
    } if (keyPr.UnicodeChar == L'3') {
        return load_stivale2(ImageHandle, L"\\badux.elf", L"");
    }

    return EFI_LOAD_ERROR;
}

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

    EFI_DEVICE_PATH_TO_TEXT_PROTOCOL *dpToTextProto =
            (EFI_DEVICE_PATH_TO_TEXT_PROTOCOL *)locateProtocol(EFI_device_path_to_text_protocol_guid);

    EFI_DEVICE_PATH_PROTOCOL *imageDevicePathProto = nullptr;
    if (EBS->HandleProtocol(ImageHandle, &EFI_loaded_image_device_path_protocol_guid,
            (void **)&imageDevicePathProto) != EFI_SUCCESS) {
        ConOut->OutputString(ConOut, L"Image does not support loaded-image device path protocol.\r\n");
        return EFI_LOAD_ERROR;
    }

    if (imageDevicePathProto == nullptr) {
        ConOut->OutputString(ConOut, L"Firmware misbehaved; don't have loaded image device path.\r\n");
        return EFI_LOAD_ERROR;
    }

    unsigned fp_index = find_file_path(imageDevicePathProto);

    unsigned exec_path_size = (strlen(exec_path) + 1) * sizeof(CHAR16);
    EFI_DEVICE_PATH_PROTOCOL *kernel_path = switch_path(imageDevicePathProto, exec_path, exec_path_size);

    // Allocate space for kernel file
    // For now we'll load the fixed 0x200000 - 0x1000, the -0x1000 is for the file header.
    EFI_PHYSICAL_ADDRESS kernelAddr = 0x200000u - 0x1000u;
    status = EBS->AllocatePages(AllocateAddress, EfiLoaderCode, (0x200000u + 0x1000u)/0x1000u, &kernelAddr);
    if (EFI_ERROR(EFI_SUCCESS)) {
        ConOut->OutputString(ConOut, L"Couldn't allocate kernel memory at 0x200000u\r\n");
        return EFI_LOAD_ERROR;
    }

    ConOut->OutputString(ConOut, L"Allocated kernel memory at 0x200000u\r\n"); // XXX

    // Try to load the kernel now
    EFI_HANDLE loadDevice;

    auto origin_kernel_path = kernel_path;

    status = EBS->LocateDevicePath(&EFI_simple_file_system_protocol_guid, &kernel_path, &loadDevice);
    if (EFI_ERROR(EFI_SUCCESS)) {
        ConOut->OutputString(ConOut, L"Couldn't get file system protocol for kernel path\r\n");
        return EFI_LOAD_ERROR;
    }

    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *sfsProtocol = nullptr;

    status = EBS->HandleProtocol(loadDevice, &EFI_simple_file_system_protocol_guid, (void **)&sfsProtocol);
    if (EFI_ERROR(EFI_SUCCESS)) {
        ConOut->OutputString(ConOut, L"Couldn't get file system protocol for kernel path\r\n");
        return EFI_LOAD_ERROR;
    }
    if (sfsProtocol == nullptr) {
        ConOut->OutputString(ConOut, L"Couldn't get file system protocol for kernel path (firmware misbehaving)\r\n");
        return EFI_LOAD_ERROR;
    }

    EFI_FILE_PROTOCOL *fsRoot = nullptr;
    status = sfsProtocol->OpenVolume(sfsProtocol, &fsRoot);
    if (EFI_ERROR(EFI_SUCCESS)) {
        ConOut->OutputString(ConOut, L"Couldn't open volume (fs protocol)\r\n");
        return EFI_LOAD_ERROR;
    }
    if (fsRoot == nullptr) {
        ConOut->OutputString(ConOut, L"Couldn't open volume (fs protocol); firmware misbehaving\r\n");
        return EFI_LOAD_ERROR;
    }

    EFI_FILE_PROTOCOL *kernelFile = nullptr;
    status = fsRoot->Open(fsRoot, &kernelFile, exec_path, EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(EFI_SUCCESS) || kernelFile == nullptr) {
        // XXX close fsroot
        ConOut->OutputString(ConOut, L"Couldn't open kernel file\r\n");
        return EFI_LOAD_ERROR;
    }

    fsRoot->Close(fsRoot);

    EFI_FILE_INFO *kernelFileInfo = getFileInfo(kernelFile);
    if (kernelFileInfo == nullptr) {
        // XXX close kernelFile
        ConOut->OutputString(ConOut, L"Couldn't get kernel file size\r\n");
        return EFI_LOAD_ERROR;
    }

    con_write(L"Kernel file size: "); con_write(kernelFileInfo->FileSize); con_write(L"\r\n"); // XXX

    UINTN readAmount = kernelFileInfo->FileSize;

    status = kernelFile->Read(kernelFile, &readAmount, (void *)kernelAddr);
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
        // XXX close kernelFile
        return EFI_LOAD_ERROR;
    }
    else {
        ConOut->OutputString(ConOut, L"Loaded kernel (!!)\r\n"); // XXX
    }

    // XXX close kernelFile

    // Allocate space for page tables
    // We will use 4-level paging, so we need:
    // A PML4 top-level page directory (4kb)
    // A PDPT (page directory pointer table) (4kb)
    //   with 1 entry per 1GB page  -- max 512GB

    struct PDE {
        uint64_t entry;
    };

    EFI_PHYSICAL_ADDRESS pageTablesPhysaddr;
    PDE *pageTables;
    if (EFI_ERROR(EBS->AllocatePages(AllocateAnyPages, EfiLoaderCode, 2, &pageTablesPhysaddr))) {
        con_write(L"*** Memory allocation failed ***\r\n");
        return EFI_LOAD_ERROR;
    }

    pageTables = (PDE *)pageTablesPhysaddr;
    for (unsigned i = 0; i < 512; i++) {
        pageTables[i] = PDE{0}; // not present
    }

    // Set up two entries to map the first 512GB at both 0 and at (high half)
    uint64_t PDPTaddress = pageTablesPhysaddr + 0x1000;
    pageTables[0] = PDE{PDPTaddress | 0x7}; // present, writable, user-accessible
    pageTables[511] = PDE{PDPTaddress | 0x7};

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
        return EFI_LOAD_ERROR;
    }

    EFI_MEMORY_DESCRIPTOR *efiMemMap = (EFI_MEMORY_DESCRIPTOR *) alloc(memMapSize);
    if (efiMemMap == nullptr) {
        con_write(L"*** Memory allocation failed ***\r\n");
        return EFI_LOAD_ERROR;
    }

    status = EBS->GetMemoryMap(&memMapSize, efiMemMap, &memMapKey, &memMapDescrSize, &memMapDescrVersion);
    while (status == EFI_BUFFER_TOO_SMALL) {
        // Above allocation may have increased size of memory map, so we keep trying
        freePool(efiMemMap);
        efiMemMap = (EFI_MEMORY_DESCRIPTOR *) alloc(memMapSize);
        if (efiMemMap == nullptr) {
            con_write(L"*** Memory allocation failed ***\r\n");
            return EFI_LOAD_ERROR;
        }
        status = EBS->GetMemoryMap(&memMapSize, efiMemMap, &memMapKey, &memMapDescrSize, &memMapDescrVersion);
    }

    if (EFI_ERROR(status)) {
        con_write(L"*** Could not retrieve EFI memory map ***\r\n");
        return EFI_LOAD_ERROR;
    }

    // Allocate Stivale2 memmap
    tosaithe_stivale2_memmap st2_memmap;
    if (!st2_memmap.allocate(memMapSize / memMapDescrSize + 6)) { // +6 for wiggle room
        con_write(L"*** Memory allocation failed ***\r\n");
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
                efi_mem_iter->NumberOfPages * 1000u);
        efi_mem_iter = (EFI_MEMORY_DESCRIPTOR *)((char *)efi_mem_iter + memMapDescrSize);
    }

    ConOut->OutputString(ConOut, L"Copied all map entries\r\n"); // XXX

    // TODO calculate kernelSize including bss / stack
    uint64_t kernelSize = ((readAmount - 0x1000u + 0xFFFu) / 0x1000u) * 0x1000u;

    st2_memmap.insert_entry(stivale2_mmap_type::KERNEL_AND_MODULES, kernelAddr, kernelSize);

    ConOut->OutputString(ConOut, L"Gonna setup framebuffer now\r\n"); // XXX

    // Framebuffer setup

    stivale2_struct_tag_framebuffer fbinfo;
    fbinfo.tag.identifier = STIVALE2_ST_FRAMEBUFFER_IDENT;
    fbinfo.tag.next = nullptr;

    EFI_GRAPHICS_OUTPUT_PROTOCOL *graphics =
            (EFI_GRAPHICS_OUTPUT_PROTOCOL *) locateProtocol(EFI_graphics_output_protocol_guid);;
    if (graphics == nullptr) {
        con_write(L"No graphics protocol available.\r\n");
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

    uint64_t cr4flags;

    asm volatile (
            "movq %%cr4, %%rax"
            : "=a"(cr4flags)
    );

    con_write(L"cr4 flags = "); con_write(cr4flags); con_write(L"\r\n");
    if (cr4flags & 0x1000) {
        con_write(L"Uh-oh, LA57 is enabled :(\r\n");  // TODO
        return EFI_LOAD_ERROR;
    }

    /*
    volatile int doWait = 1;
    while (doWait) {
        asm volatile ("pause\n");
    }
    */

    // Cannot do the following in long mode, need to transition to 32-bit mode to disable paging,
    // sigh.

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
