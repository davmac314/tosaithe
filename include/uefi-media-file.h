#ifndef UEFI_MEDIA_FILE_INCLUDED
#define UEFI_MEDIA_FILE_INCLUDED 1

#include "uefi.h"

#define EFI_LOAD_FILE_PROTOCOL_GUID {0x56EC3091,0x954C,0x11d2, {0x8e,0x3f,0x00,0xa0, 0xc9,0x69,0x72,0x3b}}
#define EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID {0x0964e5b22,0x6459,0x11d2, {0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}}

static const EFI_GUID EFI_load_file_protocol_guid = EFI_LOAD_FILE_PROTOCOL_GUID;
static const EFI_GUID EFI_simple_file_system_protocol_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;

// GUIDs that can be passed to EFI_FILE_PROTOCOL.GetInfo():
#define EFI_FILE_INFO_ID {0x09576e92,0x6d3f,0x11d2, {0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}}

static const EFI_GUID EFI_file_info_id = EFI_FILE_INFO_ID;

#define EFI_FILE_MODE_READ     0x0000000000000001
#define EFI_FILE_MODE_WRITE    0x0000000000000002
#define EFI_FILE_MODE_CREATE   0x8000000000000000

#define EFI_FILE_READ_ONLY     0x0000000000000001
#define EFI_FILE_HIDDEN        0x0000000000000002
#define EFI_FILE_SYSTEM        0x0000000000000004
#define EFI_FILE_RESERVED      0x0000000000000008
#define EFI_FILE_DIRECTORY     0x0000000000000010
#define EFI_FILE_ARCHIVE       0x0000000000000020
#define EFI_FILE_VALID_ATTR    0x0000000000000037


typedef struct _EFI_LOAD_FILE_PROTOCOL EFI_LOAD_FILE_PROTOCOL;
typedef struct _EFI_SIMPLE_FILE_SYSTEM_PROTOCOL EFI_SIMPLE_FILE_SYSTEM_PROTOCOL;
typedef struct _EFI_FILE_PROTOCOL EFI_FILE_PROTOCOL;


typedef EFI_STATUS(EFIAPI *EFI_LOAD_FILE)(IN EFI_LOAD_FILE_PROTOCOL *This,
        IN EFI_DEVICE_PATH_PROTOCOL *FilePath, IN BOOLEAN BootPolicy, IN OUT UINTN *BufferSize,
        IN void *Buffer OPTIONAL);

typedef struct _EFI_LOAD_FILE_PROTOCOL {
    EFI_LOAD_FILE        LoadFile;
} EFI_LOAD_FILE_PROTOCOL;


typedef EFI_STATUS(EFIAPI *EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_OPEN_VOLUME)
        (IN EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *This, OUT EFI_FILE_PROTOCOL **Root);

typedef struct _EFI_SIMPLE_FILE_SYSTEM_PROTOCOL {
    uint64_t                                      Revision;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_OPEN_VOLUME   OpenVolume;
} EFI_SIMPLE_FILE_SYSTEM_PROTOCOL;


typedef EFI_STATUS(EFIAPI *EFI_FILE_OPEN)(IN EFI_FILE_PROTOCOL *This,
        OUT EFI_FILE_PROTOCOL **NewHandle, IN const CHAR16 *FileName, IN uint64_t OpenMode,
        IN uint64_t Attributes);
typedef EFI_STATUS(EFIAPI *EFI_FILE_CLOSE)(IN EFI_FILE_PROTOCOL *This);
typedef EFI_STATUS(EFIAPI *EFI_FILE_DELETE)(IN EFI_FILE_PROTOCOL *This);
typedef EFI_STATUS(EFIAPI *EFI_FILE_READ)(IN EFI_FILE_PROTOCOL *This, IN OUT UINTN *BufferSize,
        OUT void *Buffer);
typedef EFI_STATUS(EFIAPI *EFI_FILE_WRITE)( IN EFI_FILE_PROTOCOL *This,
        IN OUT UINTN *BufferSize, IN void *Buffer);
typedef EFI_STATUS(EFIAPI *EFI_FILE_GET_POSITION)(IN EFI_FILE_PROTOCOL *This, OUT uint64_t *Position);
typedef EFI_STATUS(EFIAPI *EFI_FILE_SET_POSITION)(IN EFI_FILE_PROTOCOL *This, IN uint64_t Position);
typedef EFI_STATUS(EFIAPI *EFI_FILE_GET_INFO)(IN EFI_FILE_PROTOCOL *This,
        const IN EFI_GUID *InformationType, IN OUT UINTN *BufferSize, OUT void *Buffer);
typedef EFI_STATUS(EFIAPI *EFI_FILE_SET_INFO)(IN EFI_FILE_PROTOCOL *This,
        IN EFI_GUID *InformationType, IN UINTN BufferSize, IN void *Buffer);
typedef EFI_STATUS(EFIAPI *EFI_FILE_FLUSH)(IN EFI_FILE_PROTOCOL *This);

typedef struct _EFI_FILE_PROTOCOL {
    uint64_t              Revision;
    EFI_FILE_OPEN         Open;
    EFI_FILE_CLOSE        Close;
    EFI_FILE_DELETE       Delete;
    EFI_FILE_READ         Read;
    EFI_FILE_WRITE        Write;
    EFI_FILE_GET_POSITION GetPosition;
    EFI_FILE_SET_POSITION SetPosition;
    EFI_FILE_GET_INFO     GetInfo;
    EFI_FILE_SET_INFO     SetInfo;
    EFI_FILE_FLUSH        Flush;
} EFI_FILE_PROTOCOL;

typedef struct {
    uint64_t  Size; // of the structure! (including variable-length filename)
    uint64_t  FileSize;
    uint64_t  PhysicalSize;
    EFI_TIME  CreateTime;
    EFI_TIME  LastAccessTime;
    EFI_TIME  ModificationTime;
    uint64_t  Attribute;
    CHAR16    FileName[];
} EFI_FILE_INFO;

#endif
