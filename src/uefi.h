#ifndef UEFI_H_INCLUDED
#define UEFI_H_INCLUDED 1

#include <stdint.h>

#define IN
#define OUT
#define OPTIONAL
#define CONST const
#define EFIAPI __attribute__((ms_abi))

// status codes
#define EFI_SUCCESS 0
#define EFI_ERRORBIT ((UINTN)1 << (sizeof(UINTN)*8 - 1))
#define EFI_ERROR_NUM(n) (EFI_ERRORBIT + (UINTN)n)
#define EFI_LOAD_ERROR         EFI_ERROR_NUM(1)
#define EFI_INVALID_PARAMETER  EFI_ERROR_NUM(2)
#define EFI_UNSUPPORTED        EFI_ERROR_NUM(3)
#define EFI_BUFFER_TOO_SMALL   EFI_ERROR_NUM(5)
#define EFI_DEVICE_ERROR       EFI_ERROR_NUM(7)
#define EFI_VOLUME_CORRUPTED   EFI_ERROR_NUM(10)
#define EFI_NO_MEDIA           EFI_ERROR_NUM(12)
#define EFI_NOT_FOUND          EFI_ERROR_NUM(14)

// Check if status is an error. This macro is used in official UEFI examples.
#define EFI_ERROR(n) ((n & EFI_ERRORBIT) != 0)

// timezone special value
#define EFI_UNSPECIFIED_TIMEZONE 0x07FF

// basic types
typedef wchar_t CHAR16;
typedef uint64_t UINTN;
typedef int64_t INTN;
typedef uint8_t BOOLEAN;

typedef UINTN EFI_STATUS;
typedef void *EFI_HANDLE;

// EFI_GUID
typedef struct {
    uint32_t Data1;
    uint16_t Data2;
    uint16_t Data3;
    uint8_t  Data4[8];
} EFI_GUID;

// EFI_TABLE_HEADER
typedef struct {
    uint64_t Signature;
    uint32_t Revision;
    uint32_t HeaderSize;
    uint32_t CRC32;
    uint32_t Reserved;
} EFI_TABLE_HEADER;

typedef UINTN EFI_TPL;
typedef uint64_t EFI_PHYSICAL_ADDRESS;
typedef uint64_t EFI_VIRTUAL_ADDRESS;
typedef void *EFI_EVENT;

typedef enum {
    AllocateAnyPages, AllocateMaxAddress, AllocateAddress, MaxAllocateType
} EFI_ALLOCATE_TYPE;

typedef enum {
    EfiReservedMemoryType, EfiLoaderCode, EfiLoaderData, EfiBootServicesCode, EfiBootServicesData,
    EfiRuntimeServicesCode, EfiRuntimeServicesData, EfiConventionalMemory, EfiUnusableMemory,
    EfiACPIReclaimMemory, EfiACPIMemoryNVS, EfiMemoryMappedIO, EfiMemoryMappedIOPortSpace,
    EfiPalCode, EfiPersistentMemory, EfiMaxMemoryType
} EFI_MEMORY_TYPE;

typedef enum { TimerCancel, TimerPeriodic, TimerRelative} EFI_TIMER_DELAY;

// And the most useless enum award goes to:
typedef enum { EFI_NATIVE_INTERFACE} EFI_INTERFACE_TYPE;

typedef enum { AllHandles, ByRegisterNotify, ByProtocol} EFI_LOCATE_SEARCH_TYPE;

typedef struct {
    uint32_t                         Type;
    EFI_PHYSICAL_ADDRESS             PhysicalStart;
    EFI_VIRTUAL_ADDRESS              VirtualStart;
    uint64_t                         NumberOfPages;
    uint64_t                         Attribute;
} EFI_MEMORY_DESCRIPTOR;


// Forward declarations of some protocols:
struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;
typedef struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;

struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL;
typedef struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL EFI_SIMPLE_TEXT_INPUT_PROTOCOL;

struct _EFI_DEVICE_PATH_PROTOCOL;
typedef struct _EFI_DEVICE_PATH_PROTOCOL EFI_DEVICE_PATH_PROTOCOL;


typedef void(EFIAPI *EFI_EVENT_NOTIFY) (IN EFI_EVENT Event, IN void *Context);

typedef EFI_TPL(EFIAPI *EFI_RAISE_TPL)(IN EFI_TPL NewTpl);
typedef void(EFIAPI *EFI_RESTORE_TPL) (IN EFI_TPL OldTpl);
typedef EFI_STATUS(EFIAPI *EFI_ALLOCATE_PAGES)(IN EFI_ALLOCATE_TYPE Type,
        IN EFI_MEMORY_TYPE MemoryType, IN UINTN Pages, IN OUT EFI_PHYSICAL_ADDRESS *Memory);
typedef EFI_STATUS(EFIAPI *EFI_FREE_PAGES) (IN EFI_PHYSICAL_ADDRESS Memory, IN UINTN Pages);
typedef EFI_STATUS(EFIAPI *EFI_GET_MEMORY_MAP) (IN OUT UINTN *MemoryMapSize,
        OUT EFI_MEMORY_DESCRIPTOR *MemoryMap, OUT UINTN *MapKey, OUT UINTN *DescriptorSize,
        OUT uint32_t *DescriptorVersion);
typedef EFI_STATUS(EFIAPI *EFI_ALLOCATE_POOL)(IN EFI_MEMORY_TYPE PoolType, IN UINTN Size,
        OUT void **Buffer);
typedef EFI_STATUS(EFIAPI *EFI_FREE_POOL)(IN void *Buffer);
typedef EFI_STATUS(EFIAPI *EFI_CREATE_EVENT)(IN uint32_t Type,
        IN EFI_TPL NotifyTpl, IN EFI_EVENT_NOTIFY NotifyFunction, OPTIONAL IN void *NotifyContext,
        OPTIONAL OUT EFI_EVENT *Event);
typedef EFI_STATUS(EFIAPI *EFI_SET_TIMER)(IN EFI_EVENT Event, IN EFI_TIMER_DELAY Type,
        IN uint64_t TriggerTime);
typedef EFI_STATUS(EFIAPI *EFI_WAIT_FOR_EVENT)(IN UINTN NumberOfEvents, IN EFI_EVENT *Event,
        OUT UINTN *Index);
typedef EFI_STATUS(EFIAPI *EFI_SIGNAL_EVENT)(IN EFI_EVENT Event);
typedef EFI_STATUS(EFIAPI *EFI_CLOSE_EVENT)(IN EFI_EVENT Event);
typedef EFI_STATUS(EFIAPI *EFI_CHECK_EVENT)(IN EFI_EVENT Event);
typedef EFI_STATUS(EFIAPI *EFI_INSTALL_PROTOCOL_INTERFACE)(IN OUT EFI_HANDLE *Handle,
        IN EFI_GUID *Protocol, IN EFI_INTERFACE_TYPE InterfaceType, IN void *Interface);
typedef EFI_STATUS(EFIAPI *EFI_REINSTALL_PROTOCOL_INTERFACE)(IN EFI_HANDLE Handle,
        IN EFI_GUID *Protocol, IN void *OldInterface, IN void *NewInterface);
typedef EFI_STATUS(EFIAPI *EFI_UNINSTALL_PROTOCOL_INTERFACE)(IN EFI_HANDLE Handle,
        IN EFI_GUID *Protocol, IN void *Interface);
typedef EFI_STATUS(EFIAPI *EFI_HANDLE_PROTOCOL)(IN EFI_HANDLE Handle, const IN EFI_GUID *Protocol,
        OUT void **Interface);
typedef EFI_STATUS(EFIAPI *EFI_REGISTER_PROTOCOL_NOTIFY)(IN EFI_GUID *Protocol,
        IN EFI_EVENT Event, OUT void **Registration);
typedef EFI_STATUS(EFIAPI *EFI_LOCATE_HANDLE)(IN EFI_LOCATE_SEARCH_TYPE SearchType,
        const IN EFI_GUID *Protocol OPTIONAL, IN void *SearchKey OPTIONAL,
        IN OUT UINTN *BufferSize, OUT EFI_HANDLE *Buffer);
typedef EFI_STATUS(EFIAPI *EFI_LOCATE_DEVICE_PATH)(const IN EFI_GUID *Protocol,
        IN OUT EFI_DEVICE_PATH_PROTOCOL **DevicePath, OUT EFI_HANDLE *Device);
typedef EFI_STATUS(EFIAPI *EFI_INSTALL_CONFIGURATION_TABLE)(IN EFI_GUID *Guid, IN void *Table);
typedef EFI_STATUS(EFIAPI *EFI_IMAGE_LOAD)(IN BOOLEAN BootPolicy, IN EFI_HANDLE ParentImageHandle,
        IN EFI_DEVICE_PATH_PROTOCOL *DevicePath, IN void *SourceBuffer OPTIONAL,
        IN UINTN SourceSize, OUT EFI_HANDLE *ImageHandle);
typedef EFI_STATUS(EFIAPI *EFI_IMAGE_START)(IN EFI_HANDLE ImageHandle, OUT UINTN *ExitDataSize,
        OUT CHAR16 **ExitData OPTIONAL);
typedef EFI_STATUS(EFIAPI *EFI_EXIT)(IN EFI_HANDLE ImageHandle, IN EFI_STATUS ExitStatus,
        IN UINTN ExitDataSize, IN CHAR16 *ExitDataOPTIONAL);
typedef EFI_STATUS(EFIAPI *EFI_IMAGE_UNLOAD)(IN EFI_HANDLE ImageHandle);
typedef EFI_STATUS(EFIAPI *EFI_EXIT_BOOT_SERVICES)(IN EFI_HANDLE ImageHandle, IN UINTN MapKey);

typedef EFI_STATUS(EFIAPI *EFI_LOCATE_PROTOCOL)(const IN EFI_GUID *Protocol,
        IN void *Registration OPTIONAL, OUT void **Interface);


// Boot services table
typedef struct {
    EFI_TABLE_HEADER                 Hdr;
    EFI_RAISE_TPL                    RaiseTPL;
    EFI_RESTORE_TPL                  RestoreTPL;

    EFI_ALLOCATE_PAGES               AllocatePages;
    EFI_FREE_PAGES                   FreePages;
    EFI_GET_MEMORY_MAP               GetMemoryMap;
    EFI_ALLOCATE_POOL                AllocatePool;
    EFI_FREE_POOL                    FreePool;

    EFI_CREATE_EVENT                 CreateEvent;
    EFI_SET_TIMER                    SetTimer;
    EFI_WAIT_FOR_EVENT               WaitForEvent;
    EFI_SIGNAL_EVENT                 SignalEvent;
    EFI_CLOSE_EVENT                  CloseEvent;
    EFI_CHECK_EVENT                  CheckEvent;

    EFI_INSTALL_PROTOCOL_INTERFACE   InstallProtocolInterface;
    EFI_REINSTALL_PROTOCOL_INTERFACE ReinstallProtocolInterface;
    EFI_UNINSTALL_PROTOCOL_INTERFACE UninstallProtocolInterface;
    EFI_HANDLE_PROTOCOL              HandleProtocol;

    void *Reserved;

    EFI_REGISTER_PROTOCOL_NOTIFY     RegisterProtocolNotify;
    EFI_LOCATE_HANDLE                LocateHandle;
    EFI_LOCATE_DEVICE_PATH           LocateDevicePath;
    EFI_INSTALL_CONFIGURATION_TABLE  InstallConfigurationTable;

    EFI_IMAGE_LOAD                   LoadImage;
    EFI_IMAGE_START                  StartImage;
    EFI_EXIT                         Exit;
    EFI_IMAGE_UNLOAD                 UnloadImage;
    EFI_EXIT_BOOT_SERVICES           ExitBootServices;

    void *GetNextMonotonicCount;
    void *Stall;
    void *SetWatchdogTimer;

    void *ConnectController;
    void *DisconnectController;

    void *OpenProtocol;
    void *CloseProtocol;
    void *OpenProtocolInformation;

    void *ProtocolsPerHandle;
    void *LocateHandleBuffer;
    EFI_LOCATE_PROTOCOL              LocateProtocol;


    // XXX not complete
} EFI_BOOT_SERVICES;

typedef struct {
    EFI_TABLE_HEADER                 Hdr;
    // XXX not complete
} EFI_RUNTIME_SERVICES;

typedef struct {
    EFI_GUID VendorGuid;
    void *VendorTable;
} EFI_CONFIGURATION_TABLE;

#define ACPI_TABLE_GUID {0xeb9d2d30,0x2d88,0x11d3, {0x9a,0x16,0x00,0x90,0x27,0x3f,0xc1,0x4d}}
#define EFI_ACPI_TABLE_GUID {0x8868e871,0xe4f1,0x11d3, {0xbc,0x22,0x00,0x80,0xc7,0x3c,0x88,0x81}}

static const EFI_GUID EFI_acpi_table_guid = ACPI_TABLE_GUID;
static const EFI_GUID EFI_acpi20_table_guide = EFI_ACPI_TABLE_GUID;

// System table
typedef struct {
    EFI_TABLE_HEADER                 Hdr;
    CHAR16                           *FirmwareVendor;
    uint32_t                         FirmwareRevision;
    EFI_HANDLE                       ConsoleInHandle;
    EFI_SIMPLE_TEXT_INPUT_PROTOCOL   *ConIn;
    EFI_HANDLE                       ConsoleOutHandle;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL  *ConOut;
    EFI_HANDLE                       StandardErrorHandle;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL  *StdErr;
    EFI_RUNTIME_SERVICES             *RuntimeServices;
    EFI_BOOT_SERVICES                *BootServices;
    UINTN                            NumberOfTableEntries;
    EFI_CONFIGURATION_TABLE          *ConfigurationTable;
} EFI_SYSTEM_TABLE;


typedef struct {
    uint16_t  Year;
    uint8_t   Month;    // 1 – 12
    uint8_t   Day;      // 1 – 31
    uint8_t   Hour;     // 0 – 23
    uint8_t   Minute;   // 0 – 59
    uint8_t   Second;   // 0 – 59
    uint8_t   Pad1;
    uint32_t  Nanosecond;
    int16_t   TimeZone;  // -1440 to 1440 or 2047 (=EFI_UNSPECIFIED_TIMEZONE)
    uint8_t   Daylight;
    uint8_t   Pad2;
} EFI_TIME;


// ------------------------
// Simple input/output protocols

#define EFI_BLACK      0x00
#define EFI_BLUE       0x01
#define EFI_GREEN      0x02
#define EFI_CYAN       0x03
#define EFI_RED        0x04
#define EFI_MAGENTA    0x05
#define EFI_BROWN      0x06
#define EFI_LIGHTGRAY  0x07
#define EFI_BRIGHT     0x08
#define EFI_DARKGRAY   0x08
#define EFI_LIGHTBLUE  0x09
#define EFI_LIGHTGREEN 0x0A
#define EFI_LIGHTCYAN  0x0B
#define EFI_LIGHTRED   0x0C
#define EFI_LIGHTMAGENTA 0x0D
#define EFI_YELLOW     0x0E
#define EFI_WHITE      0x0F

#define EFI_BACKGROUND_BLACK   0x00
#define EFI_BACKGROUND_BLUE    0x10
#define EFI_BACKGROUND_GREEN   0x20
#define EFI_BACKGROUND_CYAN    0x30
#define EFI_BACKGROUND_RED     0x40
#define EFI_BACKGROUND_MAGENTA 0x50
#define EFI_BACKGROUND_BROWN   0x60
#define EFI_BACKGROUND_LIGHTGRAY 0x70

typedef struct {
    int32_t     MaxMode;
    int32_t     Mode;
    int32_t     Attribute;
    int32_t     CursorColumn;
    int32_t     CursorRow;
    BOOLEAN     CursorVisible;
} SIMPLE_TEXT_OUTPUT_MODE;

typedef EFI_STATUS(EFIAPI *EFI_TEXT_STRING)(IN struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
        const IN CHAR16 *String);
typedef EFI_STATUS(EFIAPI *EFI_TEXT_RESET)(IN EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
        IN BOOLEAN ExtendedVerification);
typedef EFI_STATUS(EFIAPI *EFI_TEXT_TEST_STRING)(IN EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
        IN CHAR16 *String);
typedef EFI_STATUS(EFIAPI *EFI_TEXT_QUERY_MODE)(IN EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
        IN UINTN ModeNumber, OUT UINTN *Columns, OUT UINTN *Rows);
typedef EFI_STATUS(EFIAPI *EFI_TEXT_SET_MODE)(IN EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
        IN UINTN ModeNumber);
typedef EFI_STATUS(EFIAPI *EFI_TEXT_SET_ATTRIBUTE)(IN EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
        IN UINTN Attribute);
typedef EFI_STATUS(EFIAPI *EFI_TEXT_CLEAR_SCREEN)(IN EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This);
typedef EFI_STATUS(EFIAPI *EFI_TEXT_SET_CURSOR_POSITION)(IN EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
        IN UINTN Column, IN UINTN Row);
typedef EFI_STATUS(EFIAPI *EFI_TEXT_ENABLE_CURSOR)(IN EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
        IN BOOLEAN Visible);

// SIMPLE_TEXT_OUTPUT_PROTOCOL
typedef struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL {
    EFI_TEXT_RESET                Reset;
    EFI_TEXT_STRING               OutputString;
    EFI_TEXT_TEST_STRING          TestString;
    EFI_TEXT_QUERY_MODE           QueryMode;
    EFI_TEXT_SET_MODE             SetMode;
    EFI_TEXT_SET_ATTRIBUTE        SetAttribute;
    EFI_TEXT_CLEAR_SCREEN         ClearScreen;
    EFI_TEXT_SET_CURSOR_POSITION  SetCursorPosition;
    EFI_TEXT_ENABLE_CURSOR        EnableCursor;
    SIMPLE_TEXT_OUTPUT_MODE      *Mode;
} EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;

typedef struct {
    uint16_t   ScanCode;
    CHAR16     UnicodeChar;
} EFI_INPUT_KEY;

typedef EFI_STATUS(EFIAPI *EFI_INPUT_RESET)(IN EFI_SIMPLE_TEXT_INPUT_PROTOCOL *This,
        IN BOOLEAN ExtendedVerification);
typedef EFI_STATUS(EFIAPI *EFI_INPUT_READ_KEY)(IN EFI_SIMPLE_TEXT_INPUT_PROTOCOL *This,
        OUT EFI_INPUT_KEY *Key );

typedef struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL {
    EFI_INPUT_RESET     Reset;
    EFI_INPUT_READ_KEY  ReadKeyStroke;
    EFI_EVENT           WaitForKey;
} EFI_SIMPLE_TEXT_INPUT_PROTOCOL;;

#define EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID {0x9042a9de,0x23dc,0x4a38, {0x96,0xfb,0x7a,0xde,0xd0,0x80,0x51,0x6a}}

const EFI_GUID EFI_graphics_output_protocol_guid = EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID;

typedef enum {
    PixelRedGreenBlueReserved8BitPerColor,
    PixelBlueGreenRedReserved8BitPerColor,
    PixelBitMask,
    PixelBltOnly,
    PixelFormatMax
} EFI_GRAPHICS_PIXEL_FORMAT;

typedef struct {
    uint32_t    RedMask;
    uint32_t    GreenMask;
    uint32_t    BlueMask;
    uint32_t    ReservedMask;
} EFI_PIXEL_BITMASK;

typedef struct {
    uint32_t        Version;
    uint32_t        HorizontalResolution;
    uint32_t        VerticalResolution;
    EFI_GRAPHICS_PIXEL_FORMAT PixelFormat;
    EFI_PIXEL_BITMASK PixelInformation;
    uint32_t        PixelsPerScanLine;
} EFI_GRAPHICS_OUTPUT_MODE_INFORMATION;

typedef struct {
    uint32_t                            MaxMode;
    uint32_t                            Mode;
    EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *Info;
    UINTN                               SizeOfInfo;
    EFI_PHYSICAL_ADDRESS                FrameBufferBase;
    UINTN                               FrameBufferSize;
} EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE;

typedef struct {
    uint8_t Blue;
    uint8_t Green;
    uint8_t Red;
    uint8_t Reserved;
} EFI_GRAPHICS_OUTPUT_BLT_PIXEL;

typedef enum {
    EfiBltVideoFill,
    EfiBltVideoToBltBuffer,
    EfiBltBufferToVideo,
    EfiBltVideoToVideo,
    EfiGraphicsOutputBltOperationMax
} EFI_GRAPHICS_OUTPUT_BLT_OPERATION;

typedef struct _EFI_GRAPHICS_OUTPUT_PROTCOL EFI_GRAPHICS_OUTPUT_PROTOCOL;

typedef EFI_STATUS(EFIAPI *EFI_GRAPHICS_OUTPUT_PROTOCOL_QUERY_MODE)
        (IN EFI_GRAPHICS_OUTPUT_PROTOCOL *This, IN uint32_t ModeNumber, OUT UINTN *SizeOfInfo,
                OUT EFI_GRAPHICS_OUTPUT_MODE_INFORMATION **Info);
typedef EFI_STATUS(EFIAPI *EFI_GRAPHICS_OUTPUT_PROTOCOL_SET_MODE)
        (IN EFI_GRAPHICS_OUTPUT_PROTOCOL *This, IN uint32_t ModeNumber);
typedef EFI_STATUS(EFIAPI *EFI_GRAPHICS_OUTPUT_PROTOCOL_BLT)
        (IN EFI_GRAPHICS_OUTPUT_PROTOCOL *This, IN OUT EFI_GRAPHICS_OUTPUT_BLT_PIXEL *BltBuffer OPTIONAL,
                IN EFI_GRAPHICS_OUTPUT_BLT_OPERATION BltOperation, IN UINTN SourceX,
                IN UINTN SourceY, IN UINTN DestinationX, IN UINTN DestinationY, IN UINTN Width,
                IN UINTN Height, IN UINTN Delta OPTIONAL
);

typedef struct _EFI_GRAPHICS_OUTPUT_PROTCOL {
    EFI_GRAPHICS_OUTPUT_PROTOCOL_QUERY_MODE QueryMode;
    EFI_GRAPHICS_OUTPUT_PROTOCOL_SET_MODE   SetMode;
    EFI_GRAPHICS_OUTPUT_PROTOCOL_BLT        Blt;
    EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE      *Mode;
} EFI_GRAPHICS_OUTPUT_PROTOCOL;


#endif
