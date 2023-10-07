#ifndef UEFI_LOADEDIMAGE_H_INCLUDED
#define UEFI_LOADEDIMAGE_H_INCLUDED 1

#include "uefi.h"

#define EFI_LOADED_IMAGE_PROTOCOL_GUID {0x5B1B31A1,0x9562,0x11d2, {0x8E,0x3F,0x00,0xA0,0xC9,0x69,0x72,0x3B}}
#define EFI_LOADED_IMAGE_DEVICE_PATH_PROTOCOL_GUID {0xbc62157e,0x3e33,0x4fec, {0x99,0x20,0x2d,0x3b,0x36,0xd7,0x50,0xdf}}

static const EFI_GUID EFI_loaded_image_protocol_guid = EFI_LOADED_IMAGE_PROTOCOL_GUID;
static const EFI_GUID EFI_loaded_image_device_path_protocol_guid = EFI_LOADED_IMAGE_DEVICE_PATH_PROTOCOL_GUID;

// Note: EFI_LOADED_IMAGE_DEVICE_PATH_PROTOCOL is just a re-branded EFI_DEVICE_PATH_PROTOCOL

// EFI_LOADED_IMAGE_PROTOCOL
typedef struct {
    uint32_t                  Revision;
    EFI_HANDLE                ParentHandle;
    EFI_SYSTEM_TABLE          *SystemTable;
    // Source location of the image
    EFI_HANDLE                DeviceHandle;
    EFI_DEVICE_PATH_PROTOCOL  *FilePath;
    void                      *Reserved;
    // Image’s load options
    uint32_t                  LoadOptionsSize;
    void                      *LoadOptions;
    // Location where image was loaded
    void                      *ImageBase;
    uint64_t                  ImageSize;
    EFI_MEMORY_TYPE           ImageCodeType;
    EFI_MEMORY_TYPE           ImageDataType;
    EFI_IMAGE_UNLOAD          Unload;
} EFI_LOADED_IMAGE_PROTOCOL;

#endif
