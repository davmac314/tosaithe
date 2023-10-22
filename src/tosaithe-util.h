#ifndef INCLUDED_TOSAITHE_UTIL_H
#define INCLUDED_TOSAITHE_UTIL_H

#include <uefi.h>
#include <uefi-media-file.h>

#include <memory>
#include <string>

#include <cstddef>

extern EFI_BOOT_SERVICES *EBS;
extern EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *EFI_con_out;

// Allocate from the "pool". This is, essentially, malloc.
inline void *alloc_pool(unsigned size)
{
    void *allocdBuf;
    EFI_STATUS status = EBS->AllocatePool(EfiLoaderData, size, &allocdBuf);
    if (EFI_ERROR(status)) {
        return nullptr;
    }
    return allocdBuf;
}

// Return memory to the "pool".
inline void free_pool(void *buf)
{
    EBS->FreePool(buf);
}

// Find (or at least guess) the best GOP interface to use
EFI_GRAPHICS_OUTPUT_PROTOCOL *find_GOP();

// Locate a protocol by finding a singular handle supporting it
inline void *locate_protocol(const EFI_GUID &guid)
{
    void *interface_ptr = nullptr;

    // LocateProtocol only available since UEFI 1.10:
    if (EBS->Hdr.Revision >= (0x100 + 10)) {
        EBS->LocateProtocol(&guid, nullptr, &interface_ptr);
        return interface_ptr;
    }

    // Without LocateProtocol, we will try LocateHandle + HandleProtocol.
    EFI_HANDLE located_handle;
    UINTN handle_buf_size = sizeof(located_handle);

    EFI_STATUS status = EBS->LocateHandle(ByProtocol, &guid, nullptr, &handle_buf_size, &located_handle);
    if (EFI_ERROR(status)) {
        if (status != EFI_BUFFER_TOO_SMALL) {
            return nullptr;
        }

        // Our "buffer" was too small, i.e. there is more than one matching handle. Allocate a real buffer
        // on the heap to obtain the full list of handles (even though we only need the first...).
        EFI_HANDLE *heap_buf = (EFI_HANDLE *) alloc_pool(handle_buf_size);
        if (heap_buf == nullptr) {
            return nullptr;
        }
        status = EBS->LocateHandle(ByProtocol, &guid, nullptr, &handle_buf_size, heap_buf);

        // Take the first handle, then free the buffer:
        located_handle = *heap_buf;
        free_pool(heap_buf);
        if (EFI_ERROR(status)) {
            return nullptr;
        }
    }

    // This should succeed.
    EBS->HandleProtocol(located_handle, &guid, &interface_ptr);

    return interface_ptr;
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

// deleter for efi_page_alloc
class efi_page_deleter
{
public:
    using pointer = std::pair<EFI_PHYSICAL_ADDRESS, UINTN>;

    void operator()(pointer v)
    {
        EBS->FreePages(v.first, v.second);
    }
};

// Owned page allocation. This is a unique_ptr implementation (in fact, subclass) for page allocations.
// It tracks both the address and size of the allocation.
class efi_page_alloc : public std::unique_ptr<void, efi_page_deleter>
{
public:
    efi_page_alloc() noexcept {}

    // allocate pages at the specified (page-aligned) address
    void allocate(EFI_PHYSICAL_ADDRESS address, UINTN num_pages)
    {
        if (!allocate_nx(address, num_pages)) {
            throw std::bad_alloc();
        }
    }

    // allocate pages at the specified address, non-throwing (return true if successful)
    bool allocate_nx(EFI_PHYSICAL_ADDRESS address, UINTN num_pages) noexcept
    {
        EFI_STATUS status = EBS->AllocatePages(AllocateAddress, EfiLoaderCode, num_pages, &address);
        if (EFI_ERROR(status)) {
            return false;
        }

        reset(std::make_pair(address, num_pages));
        return true;
    }

    // allocate pages at any address
    void allocate(UINTN num_pages) { if (!allocate_nx(num_pages)) throw std::bad_alloc(); }

    // allocate pages at any address, non-throwing (return true if successful)
    bool allocate_nx(UINTN num_pages) noexcept
    {
        EFI_PHYSICAL_ADDRESS address;
        EFI_STATUS status = EBS->AllocatePages(AllocateAnyPages, EfiLoaderCode, num_pages, &address);
        if (EFI_ERROR(status)) {
            return false;
        }

        reset(std::make_pair(address, num_pages));
        return true;
    }

    // extend allocation (without moving) by the given number of pages, non-throwing
    bool extend_nx(UINTN num_pages) noexcept
    {
        UINTN origPages = get().second;
        EFI_PHYSICAL_ADDRESS address = get().first + origPages * 4096u;
        EFI_STATUS status = EBS->AllocatePages(AllocateAddress, EfiLoaderCode, num_pages, &address);
        if (EFI_ERROR(status)) {
            return false;
        }
        rezone(get().first, origPages + num_pages);
        return true;
    }

    // extend allocation by the given number of pages, relocate if necessary,
    // throws std::bad_alloc on failure
    void extend_or_move(UINTN num_pages)
    {
        if (!extend_nx(num_pages)) {
            UINTN new_total_pages = get().second + num_pages;
            EFI_PHYSICAL_ADDRESS new_address;
            EFI_STATUS status = EBS->AllocatePages(AllocateAnyPages, EfiLoaderCode, new_total_pages, &new_address);
            if (EFI_ERROR(status)) {
                throw std::bad_alloc();
            }
            reset(std::make_pair(new_address, new_total_pages));
        }
    }

    // change the underlying allocated area, without performing any allocation/free
    void rezone(EFI_PHYSICAL_ADDRESS address, UINTN num_pages) noexcept
    {
        release();
        reset(std::make_pair(address, num_pages));
    }

    UINTN page_count() const noexcept { return get().second; }
    EFI_PHYSICAL_ADDRESS get_ptr() const noexcept { return get().first; }
};

// deleter for use by efi_file_handle
class efi_file_closer
{
public:
    using pointer = EFI_FILE_PROTOCOL *;

    void operator()(pointer v) noexcept
    {
        v->Close(v);
    }
};

// An owning file handle for EFI_FILE_PROTOCOL-based files.
class efi_file_handle : public std::unique_ptr<void, efi_file_closer>
{
public:
    using unique_ptr::unique_ptr;

    EFI_STATUS read(UINTN *read_amount, void *addr) noexcept
    {
        auto fd = get();
        return fd->Read(fd, read_amount, addr);
    }

    EFI_STATUS seek(UINTN position) noexcept
    {
        auto fd = get();
        return fd->SetPosition(fd, position);
    }
};

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

// Find the file path (if any) device node in the device path and return the offset.
// Return (unsigned)-1 if not found.
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

// Find the end-of-device-path node in a device path
inline unsigned find_devpath_end(const EFI_DEVICE_PATH_PROTOCOL *dp)
{
    typedef unsigned char byte;
    byte *dp_u8_start = (byte *)dp;
    byte *dp_u8 = dp_u8_start;

    uint8_t dpn_type = dp_u8[0];
    while(dpn_type != 0x7F) {
        uint16_t len = dp_u8[2] + (dp_u8[3] << 8);
        dp_u8 += len;
        dpn_type = dp_u8[0];
    }

    return dp_u8 - dp_u8_start;
}

// Find the total size of a (singular) device path including end node
inline unsigned find_devpath_size(const EFI_DEVICE_PATH_PROTOCOL *dp)
{
    typedef unsigned char byte;
    byte *dp_u8_start = (byte *)dp;
    byte *dp_u8 = dp_u8_start;

    unsigned end = find_devpath_end(dp);

    uint16_t len = dp_u8[end + 2] + (dp_u8[end + 3] << 8);
    return end + len;
}

// Advance to next device path instance (or return nullptr)
inline EFI_DEVICE_PATH_PROTOCOL *find_next_devpath_instance(const EFI_DEVICE_PATH_PROTOCOL *dp)
{
    typedef unsigned char byte;
    unsigned end_offs = find_devpath_end(dp);
    byte *dp_u8 = (byte *)dp + end_offs;

    uint8_t dpn_subtype = dp_u8[1];
    if (dpn_subtype != 0x1) {
        // Not the start of a new instance, therefore end of device path
        return nullptr;
    }

    uint16_t dpn_end_node_len = dp_u8[2] + (dp_u8[3] << 8);
    return (EFI_DEVICE_PATH_PROTOCOL *)(dp_u8 + dpn_end_node_len);
}

class open_file_exception {
public:
    enum of_stage {
        NO_FSPROTOCOL_FOR_DEV_PATH,  // probably does not name a file
        CANNOT_OPEN_VOLUME,
        NO_DPTT_PROTOCOL, // firmware lacks DEVICE_PATH_TO_TEXT
        CANNOT_OPEN_FILE,
    };

    of_stage reason;
    EFI_STATUS status = 0;

    open_file_exception(of_stage reason) : reason(reason) { }
    open_file_exception(of_stage reason, EFI_STATUS status) : reason(reason), status(status) { }
};

// Open a file, specified via devpath; throws open_file_exception on error, std::bad_alloc if out
// of memory
EFI_FILE_PROTOCOL *open_file(const EFI_DEVICE_PATH_PROTOCOL *dev_path);

// Switch out the file path part in a device path for another file path.
// Returned path should be freed via freePool(...).
// Params:
//   dp - original device path
//   new_path - the new file path, with null terminator
//   new_path_len - length in *bytes*, includes null terminator
// Throws: std::bad_alloc
inline EFI_DEVICE_PATH_PROTOCOL *switch_path(const EFI_DEVICE_PATH_PROTOCOL *dp,
        const CHAR16 *new_path, unsigned new_path_len)
{
    unsigned path_offs = find_file_path(dp);
    unsigned new_node_size = new_path_len + 4;
    unsigned req_size = path_offs + new_node_size + 4; // terminator node

    unsigned char *allocdBuf = (unsigned char *) alloc_pool(req_size);
    if (allocdBuf == nullptr) {
        throw std::bad_alloc();
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

// Get file info. May throw std::bad_alloc.
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
            throw std::bad_alloc();
        }

        status = file->GetInfo(file, &EFI_file_info_id, &bufferSize, buffer);
    }

    if (EFI_ERROR(status)) {
        free_pool(buffer);
        return nullptr;
    }

    return buffer;
}

// Convert UTF-8 input to UCS-2 (16-bit unicode codepoint)
class utf8toUCS2
{
    std::wstring output;
    unsigned codepoint;
    unsigned remaining_bytes = 0;

public:
    void process(char c)
    {
        unsigned i = c & 0xFFu;
        if (remaining_bytes != 0) {
            if ((i & 0xE0u) != 0xC0) {
                // encoding error
                output += L'?';
                remaining_bytes = 0;
                return;
            }
            codepoint <<= 6;
            codepoint |= (i & 0x3F);
            remaining_bytes--;
            if (remaining_bytes == 0) {
                // convert codepoint to UCS16
                if (codepoint >= 0x10000) {
                    // non-representable codepoint
                    output += L'?';
                }
                else {
                    output += (wchar_t)codepoint;
                }
            }
            return;
        }

        if ((i & 0x80u) == 0) {
            // plain ascii
            output += (wchar_t)i;
        } else if ((i * 0xE0u) == 0xC0) {
            // 2 byte encoding
            codepoint = i & 0x1F;
            remaining_bytes = 1;
        }
    }

    void process(const char *s)
    {
        while (*s != 0) {
            process(*s);
            s++;
        }
    }

    std::wstring &get_output()
    {
        return output;
    }

    static std::wstring convert(const char *input)
    {
        utf8toUCS2 converter;
        converter.process(input);
        return converter.get_output();
    }
};

#endif /* INCLUDED_TOSAITHE_UTIL_H */
