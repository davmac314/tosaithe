#include <stddef.h>

#include "uefi.h"
#include "uefi-loadedimage.h"
#include "uefi-devicepath.h"
#include "uefi-media-file.h"

#include "tosaithe-util.h"


EFI_BOOT_SERVICES *EBS;
EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *ConOut;

// Load an entire file, in a block of allocated pages
void *load_entire_file(EFI_DEVICE_PATH_PROTOCOL *devPath, UINTN *bufSize)
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

    fsRoot->Close(fsRoot);

    EFI_FILE_INFO *loadFileInfo = getFileInfo(fileToLoad);
    if (loadFileInfo == nullptr) {
        ConOut->OutputString(ConOut, L"Couldn't get file size\r\n");
    }

    UINTN readAmount = loadFileInfo->FileSize;
    freePool(loadFileInfo);

    void *loadAddress = alloc(readAmount);
    if (loadAddress == nullptr) {
        con_write(L"Couldn't allocate memory to load file");
        fileToLoad->Close(fileToLoad);
        return nullptr;
    }

    status = fileToLoad->Read(fileToLoad, &readAmount, (void *)loadAddress);
    fileToLoad->Close(fileToLoad);
    if (EFI_ERROR(status)) {
        ConOut->OutputString(ConOut, L"Couldn't read file; ");
        CHAR16 errcode[3];
        errcode[2] = 0;
        errcode[1] = hexdigit(status & 0xFu);
        errcode[0] = hexdigit((status >> 4) & 0xFu);
        ConOut->OutputString(ConOut, L"EFI status: 0x");
        ConOut->OutputString(ConOut, errcode);
        ConOut->OutputString(ConOut, L"\r\n");
        freePool(loadAddress);
        return nullptr;
    }

    if (bufSize) *bufSize = readAmount;
    return (void *)loadAddress;
}

static EFI_DEVICE_PATH_PROTOCOL *resolve_relative_path(EFI_HANDLE image_handle, const CHAR16 *path)
{
    EFI_DEVICE_PATH_PROTOCOL *image_path = nullptr;
    if (EFI_ERROR(EBS->HandleProtocol(image_handle, &EFI_loaded_image_device_path_protocol_guid,
            (void **)&image_path))) {
        con_write(L"Image does not support loaded-image device path protocol.\r\n");
        return nullptr;
    }

    if (image_path == nullptr) {
        con_write(L"Firmware misbehaved; don't have loaded image device path.\r\n");
        return nullptr;
    }

    EFI_DEVICE_PATH_PROTOCOL *full_path = switch_path(image_path, path,
            (strlen(path) + 1) * sizeof(CHAR16));

    return full_path;
}

static EFI_STATUS chainLoad(EFI_HANDLE ImageHandle, const CHAR16 *ExecPath, const CHAR16 *cmdLine)
{
    EFI_DEVICE_PATH_PROTOCOL *chainPath = resolve_relative_path(ImageHandle, ExecPath);
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

