#ifndef INCLUDED_TOSAITHE_UTIL_H
#define INCLUDED_TOSAITHE_UTIL_H

#include "uefi.h"
#include "uefi-media-file.h"

#include <memory>
#include <cstddef>

extern EFI_BOOT_SERVICES *EBS;
extern EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *EFI_con_out;

// Locate a protocol by finding a singular handle supporting it
inline void *locate_protocol(const EFI_GUID &guid)
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

inline void *alloc_pool(unsigned size)
{
    void *allocdBuf;
    EFI_STATUS status = EBS->AllocatePool(EfiLoaderCode, size, &allocdBuf);
    if (EFI_ERROR(status)) {
        return nullptr;
    }
    return allocdBuf;
}

inline void free_pool(void *buf)
{
    EBS->FreePool(buf);
}

// deleter for unique_ptr and pool allocations
class efi_pool_deleter
{
public:
    void operator()(void *v)
    {
        free_pool(v);
    }
};

template <typename T>
using efi_unique_ptr = std::unique_ptr<T, efi_pool_deleter>;

template <typename T>
efi_unique_ptr<T> efi_unique_ptr_wrap(T *t)
{
    return efi_unique_ptr<T>(t);
}

inline void con_write(const CHAR16 *str)
{
    EFI_con_out->OutputString(EFI_con_out, str);
}

inline void con_write(uint64_t val)
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

inline unsigned strlen(const CHAR16 *str)
{
    unsigned i = 0;
    while (str[i] != 0) {
        i++;
    }
    return i;
}

inline CHAR16 *strdup(CHAR16 *str)
{
    unsigned len = strlen(str);
    CHAR16 *rbuf = (CHAR16 *) alloc_pool(len);
    if (rbuf == nullptr) {
        return nullptr;
    }

    for (unsigned i = 0; i < len; i++) {
        rbuf[i] = str[i];
    }

    return rbuf;
}

inline CHAR16 hexdigit(int val)
{
    if (val < 10) {
        return L'0' + val;
    }
    return L'A' + val - 10;
}

inline void con_write_hex(uint64_t val)
{
    CHAR16 buf[21];

    unsigned pos = 20;
    buf[20] = 0;

    do {
        unsigned digit = val % 16;
        val = val / 16;
        pos--;
        buf[pos] = hexdigit(digit);
    } while (val > 0);

    con_write(buf + pos);
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
inline unsigned find_file_path(const EFI_DEVICE_PATH_PROTOCOL *dp)
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
// and returns null on failure. Returned path should be freed via freePool(...).
// Params:
//   dp - original device path
//   new_path - the new file path, with null terminator
//   new_path_len - length in *bytes*, includes null terminator
inline EFI_DEVICE_PATH_PROTOCOL *switch_path(const EFI_DEVICE_PATH_PROTOCOL *dp,
        const CHAR16 *new_path, unsigned new_path_len)
{
    unsigned path_offs = find_file_path(dp);
    unsigned new_node_size = new_path_len + 4;
    unsigned req_size = path_offs + new_node_size + 4; // terminator node

    unsigned char *allocdBuf = (unsigned char *) alloc_pool(req_size);
    if (allocdBuf == nullptr) {
        con_write(L"*** Pool allocation failed ***\r\n");
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

inline EFI_FILE_INFO *get_file_info(EFI_FILE_PROTOCOL *file)
{
    UINTN bufferSize = 128;
    EFI_FILE_INFO *buffer = (EFI_FILE_INFO *) alloc_pool(bufferSize);
    if (buffer == nullptr) {
        return nullptr;
    }

    EFI_STATUS status = file->GetInfo(file, &EFI_file_info_id, &bufferSize, buffer);
    if (status == EFI_BUFFER_TOO_SMALL) {
        free_pool(buffer);
        // bufferSize has now been updated:
        buffer = (EFI_FILE_INFO *) alloc_pool(bufferSize);
        if (buffer == nullptr) {
            return nullptr;
        }

        status = file->GetInfo(file, &EFI_file_info_id, &bufferSize, buffer);
    }

    if (EFI_ERROR(status)) {
        free_pool(buffer);
        return nullptr;
    }

    return buffer;
}

#endif /* INCLUDED_TOSAITHE_UTIL_H */
