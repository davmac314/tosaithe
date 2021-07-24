#include "uefi.h"
#include "uefi-loadedimage.h"
#include "uefi-devicepath.h"
#include "uefi-media-file.h"

EFI_BOOT_SERVICES *EBS;
EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *ConOut;

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
    void *allocdBuf = nullptr;
    EFI_STATUS status = EBS->AllocatePool(EfiLoaderCode, size, &allocdBuf);
    // We'll assume, on failure, allocdBuf will still be null...
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

    unsigned pos = 21;
    buf[21] = 0;

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

EFI_STATUS loadBadux(EFI_HANDLE ImageHandle);

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
        return loadBadux(ImageHandle);
    }

    return EFI_LOAD_ERROR;
}

struct stivale2_tag {
    uint64_t identifier;
    stivale2_tag *next;
};

struct stivale2_struct {
    char bootloader_brand[64];    // null-terminated ASCII bootloader brand string
    char bootloader_version[64];  // null-terminated ASCII bootloader version string
    stivale2_tag *tags;          // Linked list of tags
};

struct stivale2_struct_tag_framebuffer {
    stivale2_tag tag;             // Identifier: 0x506461d2950408fa
    uint64_t framebuffer_addr;    // Address of the framebuffer
    uint16_t framebuffer_width;   // Width and height in pixels
    uint16_t framebuffer_height;
    uint16_t framebuffer_pitch;   // Pitch in bytes
    uint16_t framebuffer_bpp;     // Bits per pixel
    uint8_t  memory_model;        // Memory model: 1=RGB, all other values undefined
    uint8_t  red_mask_size;       // RGB mask sizes and left shifts
    uint8_t  red_mask_shift;
    uint8_t  green_mask_size;
    uint8_t  green_mask_shift;
    uint8_t  blue_mask_size;
    uint8_t  blue_mask_shift;
} __attribute__((packed, aligned));


EFI_STATUS loadBadux(EFI_HANDLE ImageHandle)
{
    EFI_LOADED_IMAGE_PROTOCOL *imageProto;
    EFI_STATUS status = EBS->HandleProtocol(ImageHandle,
            &EFI_loaded_image_protocol_guid, (void **)&imageProto);
    // status must be EFI_SUCCESS?

    EFI_DEVICE_PATH_TO_TEXT_PROTOCOL *dpToTextProto =
            (EFI_DEVICE_PATH_TO_TEXT_PROTOCOL *)locateProtocol(EFI_device_path_to_text_protocol_guid);

    EFI_DEVICE_PATH_UTILITIES_PROTOCOL *dpUtils =
            (EFI_DEVICE_PATH_UTILITIES_PROTOCOL *)locateProtocol(EFI_device_path_utilities_protocol_guid);


    if (dpToTextProto) {
        wchar_t *dpString = dpToTextProto->ConvertDevicePathToText(imageProto->FilePath,
                false /* displayOnly */, false /* allowShortcuts */);

        con_write(L"FilePath: ");
        con_write(dpString);
        con_write(L"\r\n");
    }

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

    if (dpToTextProto) {
        ConOut->OutputString(ConOut, L"DevicePath: ");
        wchar_t *idpString = dpToTextProto->ConvertDevicePathToText(imageDevicePathProto,
                false /* displayOnly */, false /* allowShortcuts */);
        ConOut->OutputString(ConOut, idpString);
        ConOut->OutputString(ConOut, L"\r\n");
    }

    unsigned fp_index = find_file_path(imageDevicePathProto);
    if (dpToTextProto) {
        uintptr_t fp_addr = (uintptr_t)imageDevicePathProto + fp_index;
        EFI_DEVICE_PATH_PROTOCOL *filePath = (EFI_DEVICE_PATH_PROTOCOL *)fp_addr;
        ConOut->OutputString(ConOut, L"DevicePath file path: ");
        wchar_t *idpString = dpToTextProto->ConvertDevicePathToText(filePath,
                false /* displayOnly */, false /* allowShortcuts */);
        ConOut->OutputString(ConOut, idpString);
        ConOut->OutputString(ConOut, L"\r\n");
    }

    CHAR16 BADUX_FILEPATH[] = L"\\badux.elf";
    EFI_DEVICE_PATH_PROTOCOL *baduxPath = switch_path(imageDevicePathProto, BADUX_FILEPATH, sizeof(BADUX_FILEPATH));
    if (dpToTextProto) {
        ConOut->OutputString(ConOut, L"kernel path: ");
        wchar_t *idpString = dpToTextProto->ConvertDevicePathToText(baduxPath,
                false /* displayOnly */, false /* allowShortcuts */);
        ConOut->OutputString(ConOut, idpString);
        ConOut->OutputString(ConOut, L"\r\n");
    }

    // Allocate space for kernel file
    // For now we'll load the fixed 0x200000 - 0x1000, the -0x1000 is for the file header.
    EFI_PHYSICAL_ADDRESS kernelAddr = 0x200000u - 0x1000u;
    status = EBS->AllocatePages(AllocateAddress, EfiLoaderCode, (0x200000u + 0x1000u)/0x1000u, &kernelAddr);
    if (status != EFI_SUCCESS) {
        ConOut->OutputString(ConOut, L"Couldn't allocate kernel memory at 0x200000u\r\n");
        return EFI_LOAD_ERROR;
    }

    ConOut->OutputString(ConOut, L"Allocated kernel memory at 0x200000u\r\n");


    // Try to load the kernel now
    EFI_HANDLE loadDevice;

    auto origBaduxPath = baduxPath;

    // TODO use LoadProtocol[2] if available
    /*
    status = EBS->LocateDevicePath(&EFI_load_file_protocol_guid, &baduxPath, &loadDevice);
    if (status != EFI_SUCCESS) {
        ConOut->OutputString(ConOut, L"Couldn't get load file protocol for kernel path\r\n");
        // return EFI_LOAD_ERROR;
    }
    */

    status = EBS->LocateDevicePath(&EFI_simple_file_system_protocol_guid, &baduxPath, &loadDevice);
    if (status != EFI_SUCCESS) {
        ConOut->OutputString(ConOut, L"Couldn't get file system protocol for kernel path\r\n");
        return EFI_LOAD_ERROR;
    }

    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *sfsProtocol = nullptr;

    status = EBS->HandleProtocol(loadDevice, &EFI_simple_file_system_protocol_guid, (void **)&sfsProtocol);
    if (status != EFI_SUCCESS) {
        ConOut->OutputString(ConOut, L"Couldn't get file system protocol for kernel path\r\n");
        return EFI_LOAD_ERROR;
    }
    if (sfsProtocol == nullptr) {
        ConOut->OutputString(ConOut, L"Couldn't get file system protocol for kernel path (firmware misbehaving)\r\n");
        return EFI_LOAD_ERROR;
    }

    EFI_FILE_PROTOCOL *fsRoot = nullptr;
    status = sfsProtocol->OpenVolume(sfsProtocol, &fsRoot);
    if (status != EFI_SUCCESS) {
        ConOut->OutputString(ConOut, L"Couldn't open volume (fs protocol)\r\n");
        return EFI_LOAD_ERROR;
    }
    if (fsRoot == nullptr) {
        ConOut->OutputString(ConOut, L"Couldn't open volume (fs protocol); firmware misbehaving\r\n");
        return EFI_LOAD_ERROR;
    }

    EFI_FILE_PROTOCOL *kernelFile = nullptr;
    status = fsRoot->Open(fsRoot, &kernelFile, BADUX_FILEPATH, EFI_FILE_MODE_READ, 0);
    if (status != EFI_SUCCESS || kernelFile == nullptr) {
        ConOut->OutputString(ConOut, L"Couldn't open kernel file\r\n");
        return EFI_LOAD_ERROR;
    }

    EFI_FILE_INFO *kernelFileInfo = getFileInfo(kernelFile);
    if (kernelFileInfo == nullptr) {
        ConOut->OutputString(ConOut, L"Couldn't get kernel file size\r\n");
    }

    con_write(L"Kernel file size: "); con_write(kernelFileInfo->FileSize); con_write(L"\r\n");

    UINTN readAmount = kernelFileInfo->FileSize;

    status = kernelFile->Read(kernelFile, &readAmount, (void *)kernelAddr);
    if (status != EFI_SUCCESS) {
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
        return EFI_LOAD_ERROR;
    }
    else {
        ConOut->OutputString(ConOut, L"Loaded kernel (!!)\r\n");
    }

    uint64_t *kernelPtr = (uint64_t *)(kernelAddr + 0x1000);
    if (kernelPtr[0] == 0 && kernelPtr[2] == 2) {
        con_write(L"Stivale signature looks in place (!!)\r\n");
    } else {
        return EFI_LOAD_ERROR;
    }

    unsigned char *kernelcPtr = (unsigned char *)kernelAddr;

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

    stivale2_struct_tag_framebuffer fbinfo;
    fbinfo.tag.identifier = 0x506461d2950408fa;
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

    stivale2_info.tags = &fbinfo.tag;

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


    typedef void (*badux_entry_t)(stivale2_struct *);
    badux_entry_t badux_entry = (badux_entry_t)(0xffffffff80201171ULL);

    asm volatile (
            "callq *%0\n"
            :
            : "r"(badux_entry), "D"(&stivale2_info)
    );

    return EFI_SUCCESS;
}
