#include <vector>
#include <type_traits>
#include <memory>
#include <new>
#include <string>
#include <string_view>

#include <cstddef>

#include "uefi.h"
#include "uefi-loadedimage.h"
#include "uefi-devicepath.h"
#include "uefi-media-file.h"

#include "tosaithe-util.h"


EFI_BOOT_SERVICES *EBS;
EFI_SYSTEM_TABLE *EST;
EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *EFI_con_out;

class load_file_exception
{
public:
    enum lf_stage {
        NO_FSPROTOCOL_FOR_DEV_PATH,
        CANNOT_OPEN_VOLUME,
        NO_DPTT_PROTOCOL, // firmware lacks DEVICE_PATH_TO_TEXT
        CANNOT_OPEN_FILE,
        CANNOT_GET_FILE_SIZE,
        CANNOT_READ_FILE
    };

    lf_stage reason;
    EFI_STATUS status = 0;

    load_file_exception(lf_stage reason_p) : reason(reason_p) {}
    load_file_exception(lf_stage reason_p, EFI_STATUS status_p)
        : reason(reason_p), status(status_p) {}
};

// Load an entire file, in pool-allocated memory
//   throws: load_file_exception, std::bad_alloc
void *load_entire_file(EFI_DEVICE_PATH_PROTOCOL *dev_path, UINTN *buf_size_ptr)
{
    EFI_HANDLE load_dev_hndl;
    EFI_STATUS status = EBS->LocateDevicePath(&EFI_simple_file_system_protocol_guid, &dev_path,
            &load_dev_hndl);
    if (EFI_ERROR(status)) {
        throw load_file_exception(load_file_exception::NO_FSPROTOCOL_FOR_DEV_PATH, status);
    }

    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *sfs_protocol = nullptr;

    status = EBS->HandleProtocol(load_dev_hndl, &EFI_simple_file_system_protocol_guid,
            (void **)&sfs_protocol);
    if (EFI_ERROR(status) || sfs_protocol == nullptr) {
        // This shouldn't happen; firmware is misbehaving?
        throw load_file_exception(load_file_exception::NO_FSPROTOCOL_FOR_DEV_PATH, status);
    }

    EFI_FILE_PROTOCOL *fs_root = nullptr;
    status = sfs_protocol->OpenVolume(sfs_protocol, &fs_root);
    if (EFI_ERROR(status) || fs_root == nullptr) {
        throw load_file_exception(load_file_exception::CANNOT_OPEN_VOLUME, status);
    }

    // Need to convert remaining path to string path (within filesystem)
    EFI_DEVICE_PATH_TO_TEXT_PROTOCOL *dp2text_proto =
            (EFI_DEVICE_PATH_TO_TEXT_PROTOCOL *)locate_protocol(EFI_device_path_to_text_protocol_guid);

    if (dp2text_proto == nullptr) {
        // TODO combine the path ourselves
        fs_root->Close(fs_root);
        throw load_file_exception(load_file_exception::NO_DPTT_PROTOCOL);
    }

    EFI_FILE_PROTOCOL *file_to_load = nullptr;

    {
        CHAR16 *file_path = dp2text_proto->ConvertDevicePathToText(dev_path,
                false /* displayOnly */, false /* allowShortcuts */);

        status = fs_root->Open(fs_root, &file_to_load, file_path, EFI_FILE_MODE_READ, 0);

        free_pool(file_path);
        fs_root->Close(fs_root);

        if (EFI_ERROR(status) || file_to_load == nullptr) {
            throw load_file_exception(load_file_exception::CANNOT_OPEN_FILE, status);
        }
    }

    efi_file_handle file_to_load_hndl { file_to_load };

    EFI_FILE_INFO *load_file_info = get_file_info(file_to_load);
    if (load_file_info == nullptr) {
        throw load_file_exception(load_file_exception::CANNOT_GET_FILE_SIZE, status);
    }

    UINTN read_amount = load_file_info->FileSize;
    free_pool(load_file_info);

    void *load_address = alloc_pool(read_amount);
    if (load_address == nullptr) {
        throw std::bad_alloc();
    }

    status = file_to_load_hndl.read(&read_amount, load_address);
    if (EFI_ERROR(status)) {
        free_pool(load_address);
        throw load_file_exception(load_file_exception::CANNOT_READ_FILE, status);
    }

    if (buf_size_ptr) *buf_size_ptr = read_amount;
    return load_address;
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

static EFI_STATUS chain_load(EFI_HANDLE image_handle, const CHAR16 *exec_path, const CHAR16 *cmdline)
{
    EFI_DEVICE_PATH_PROTOCOL *chain_path = resolve_relative_path(image_handle, exec_path);
    if (chain_path == nullptr) {
        return EFI_LOAD_ERROR;
    }

    // Now load the image

    EFI_HANDLE loaded_handle = nullptr;
    EFI_STATUS status = EBS->LoadImage(true, image_handle, chain_path, nullptr, 0, &loaded_handle);

    free_pool(chain_path);

    if (EFI_ERROR(status)) {
        con_write(L"Couldn't chain-load image: ");
        con_write(exec_path);
        con_write(L"\r\n");
        return EFI_LOAD_ERROR;
    }

    // Set load options, and run the image

    EFI_LOADED_IMAGE_PROTOCOL *chained_image_LIP;
    status = EBS->HandleProtocol(loaded_handle, &EFI_loaded_image_protocol_guid,
            (void **)&chained_image_LIP);

    chained_image_LIP->LoadOptions = (void *)cmdline;
    chained_image_LIP->LoadOptionsSize = (strlen(cmdline) + 1) * sizeof(CHAR16);

    status = EBS->StartImage(loaded_handle, nullptr, nullptr);

    return status;
}

EFI_STATUS load_tsbp(EFI_HANDLE ImageHandle, const CHAR16 *exec_path, const CHAR16 *cmdLine);

struct menu_entry {
    enum entry_type_t {
        CHAIN,
        LINUX_CHAIN,
        TOSAITHE
    };

    std::wstring description;
    entry_type_t entry_type = CHAIN;
    std::wstring exec_path;
    std::wstring cmdline;

    menu_entry() { }

    menu_entry(const CHAR16 *description_p, entry_type_t entry_type_p, const CHAR16 *exec_path_p,
            const CHAR16 *cmdline_p)
        : description(description_p), entry_type(entry_type_p), exec_path(exec_path_p), cmdline(cmdline_p) { }
};

void skip_ws(std::string_view &sv)
{
    while (sv.length() > 0 && (sv[0] == ' ' || sv[0] == '\t' || sv[0] == '\r' || sv[0] == '\n')) {
        sv.remove_prefix(1);
    }
}

void skip_to_next_line(std::string_view &sv)
{
    while (!sv.empty() && sv[0] != '\r' && sv[0] != '\n') {
        sv.remove_prefix(1);
    }

    if (sv.empty()) return;

    while (!sv.empty() && (sv[0] == '\r' || sv[0] == '\n')) {
        sv.remove_prefix(1);
    }
}

bool is_ident_lead(char c)
{
    return c >= 'a' && c <= 'z';
}

bool is_ident(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
}

std::string_view read_ident(std::string_view &sv)
{
    const char *start = sv.data();
    while (!sv.empty() && is_ident(sv[0])) sv.remove_prefix(1);
    return std::string_view(start, sv.data() - start);
}

class parse_exception : public std::exception
{
    const char *what_msg;
public:
    parse_exception(const char *msg) noexcept : what_msg(msg) { }
    const char *what() const noexcept override { return what_msg; }
};

static const char * const msg_colon_after_entry = "expecting ':' after 'entry'";
static const char * const msg_lbrace_after_entry = "expecting '{' after 'entry:'";
static const char * const msg_rbrace_after_entry = "expecting '}' at end of entry";
static const char * const msg_equals_after_var = "expecting '=' after identifier in entry setting";
static const char * const msg_value_after_equals = "expecting value after '=' in entry setting";
static const char * const msg_quote_end_string = "expecting ' (quote) at end of string value";
static const char * const msg_unrecognized_value = "unrecognized setting value";
static const char * const msg_unrecognized_entry_type = "unrecognized entry type";
static const char * const msg_unrecognized_setting = "unrecognized setting";

class utf8to16
{
    std::wstring output;

public:
    void process(char c)
    {
        int i = c;
        if ((i & 0x80u) == 0) {
            // plain ascii
            output += (wchar_t)i;
        } else {
            // TODO
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
};


std::wstring read_assignment_value(std::string_view &conf)
{
    skip_ws(conf);
    if (conf.empty() || conf[0] != '=') throw parse_exception {msg_equals_after_var};
    conf.remove_prefix(1);
    skip_ws(conf);
    if (conf.empty()) throw parse_exception {msg_value_after_equals};

    if (is_ident_lead(conf[0])) {
        std::string_view value = read_ident(conf);
        // TODO check for trailing junk (allow trailing comment)
        skip_to_next_line(conf);

        utf8to16 uu;
        for (char c : value) {
            uu.process(c);
        }

        return uu.get_output();
    }
    else if (conf[0] == '\'') {
        conf.remove_prefix(1);
        utf8to16 uu;
        while (!conf.empty() && conf[0] != '\'') {
            uu.process(conf[0]);
            conf.remove_prefix(1);
        }

        if (conf.empty()) {
            throw parse_exception {msg_quote_end_string};
        }

        // TODO check for trailing junk (allow trailing comment)
        skip_to_next_line(conf);

        return uu.get_output();
    }

    throw parse_exception {msg_unrecognized_value};
}

// parse an entry - everything between braces
menu_entry parse_entry(std::string_view &conf)
{
    menu_entry entry;

    while (!conf.empty() && conf[0] != '}') {
        if (conf[0] == '#') {
            skip_to_next_line(conf);
        }
        else if (is_ident_lead(conf[0])) {
            std::string_view ident = read_ident(conf);
            std::wstring value = read_assignment_value(conf);
            if (ident == "description") {
                entry.description = std::move(value);
            }
            else if (ident == "exec") {
                entry.exec_path = std::move(value);
            }
            else if (ident == "type") {
                if (value == L"chain") {
                    entry.entry_type = menu_entry::CHAIN;
                }
                else if (value == L"linux_chain") {
                    entry.entry_type = menu_entry::LINUX_CHAIN;
                }
                else if (value == L"tosaithe") {
                    entry.entry_type = menu_entry::TOSAITHE;
                }
                else {
                    throw parse_exception {msg_unrecognized_entry_type};
                }
            }
            else if (ident == "cmdline") {
                entry.cmdline = std::move(value);
            }
        }
        else {
            return entry;
        }

        skip_ws(conf);
    }

    return entry;
}

std::vector<menu_entry> parse_config(char *conf_buf, UINTN buf_size)
{
    std::vector<menu_entry> result;
    std::string_view conf {conf_buf, buf_size};
    std::string_view sv_entry = "entry";

    skip_ws(conf);

    while (!conf.empty()) {
        if (conf[0] == '#') {
            skip_to_next_line(conf);
        }
        else if (is_ident_lead(conf[0])) {
            std::string_view ident = read_ident(conf);
            if (ident == sv_entry) {
                skip_ws(conf);
                if (conf.empty() || conf[0] != ':') throw parse_exception {msg_colon_after_entry};
                conf.remove_prefix(1); skip_ws(conf);
                if (conf.empty() || conf[0] != '{') throw parse_exception {msg_lbrace_after_entry};
                conf.remove_prefix(1); skip_ws(conf);
                result.push_back(parse_entry(conf));
                if (conf.empty() || conf[0] != '}') throw parse_exception {msg_rbrace_after_entry};
                conf.remove_prefix(1);
            }
            else {
                throw parse_exception {msg_unrecognized_setting};
            }
        }

        skip_ws(conf);
    }

    return result;
}

extern "C"
EFI_STATUS
EFIAPI
EfiMain (
    IN EFI_HANDLE        ImageHandle,
    IN EFI_SYSTEM_TABLE  *SystemTable
    )
{
    EST = SystemTable;
    EBS = SystemTable->BootServices;
    EFI_con_out = SystemTable->ConOut;

    EFI_con_out->ClearScreen(EFI_con_out);

    con_write(L"Tosaithe boot menu\r\n");
    con_write(L"Firmware vendor: ");
    con_write(SystemTable->FirmwareVendor);
    con_write(L"\r\n\r\n");

    // for debugging:
    // EFI_LOADED_IMAGE_PROTOCOL *loadedImage;
    // EBS->HandleProtocol(ImageHandle, &EFI_loaded_image_protocol_guid, (void **)&loadedImage);
    // con_write(L"Loaded image base = "); con_write_hex((uint64_t) loadedImage->ImageBase); con_write(L"\r\n\r\n");

    auto conf_path = efi_unique_ptr_wrap(resolve_relative_path(ImageHandle, L"\\tosaithe.conf"));
    if (conf_path == nullptr) {
        // An error message should already be out, but let's make it clear why we will abort now:
        con_write(L"Could not load '\\tosaithe.conf'.\r\n");
        return EFI_LOAD_ERROR;
    }

    std::vector<menu_entry> menu;

    efi_unique_ptr<char> conf_buf;
    UINTN conf_size;

    try {
        conf_buf = efi_unique_ptr_wrap((char *) load_entire_file(conf_path.get(), &conf_size));
    }
    catch (load_file_exception &lfe) {
        con_write(L"Could not load 'tosaithe.conf'");
        if (lfe.reason == load_file_exception::CANNOT_OPEN_FILE) {
            con_write(L" - can't open; ");
            if (lfe.status == EFI_NOT_FOUND) {
                con_write(L" file not found.");
            }
            else {
                con_write(L" error ");
                con_write(lfe.status);
                con_write(L".");
            }
        }
        else {
            con_write(L" - system error.");
        }
        con_write(L"\r\n");
        return EFI_LOAD_ERROR;
    }

    conf_path.reset();

    try {
        menu = parse_config(conf_buf.get(), conf_size);
    }
    catch (parse_exception &pe) {
        utf8to16 uu;
        uu.process(pe.what());

        con_write(L"Error in tosaithe.conf: ");
        con_write(uu.get_output().c_str());

        return EFI_LOAD_ERROR;
    }

    conf_buf.reset();

    EFI_con_out->SetAttribute(EFI_con_out, EFI_YELLOW);
    con_write(L"Please make a selection:\r\n\r\n");
    EFI_con_out->SetAttribute(EFI_con_out, EFI_LIGHTCYAN);

    unsigned i = 1;
    for (const auto &entry : menu) {
        con_write(i);
        con_write(L". ");
        con_write(entry.description.c_str());
        con_write(L"\r\n");
        i++;

        if (i == 10) {
            con_write(L"( too many entries! )\r\n");
            break;
        }
    }

    prompt_for_key:

    EFI_con_out->SetAttribute(EFI_con_out, EFI_LIGHTGRAY);
    con_write(L"\r\n=>");

    UINTN eventIndex = 0;
    EBS->WaitForEvent(1, &SystemTable->ConIn->WaitForKey, &eventIndex);

    EFI_INPUT_KEY key_pr;
    if (EFI_ERROR(SystemTable->ConIn->ReadKeyStroke(SystemTable->ConIn, &key_pr))) {
        con_write(L"Error reading keyboard.\r\n");
        return EFI_LOAD_ERROR;
    }

    // Echo key
    EFI_con_out->SetAttribute(EFI_con_out, EFI_WHITE);
    CHAR16 key_str[4];
    key_str[0] = key_pr.UnicodeChar;
    key_str[1] = L'\r'; key_str[2] = L'\n';
    key_str[3] = 0;
    con_write(key_str);
    EFI_con_out->SetAttribute(EFI_con_out, EFI_LIGHTGRAY);

    if (key_pr.UnicodeChar >= L'1' && key_pr.UnicodeChar <= L'9') {
        unsigned index = key_pr.UnicodeChar - L'1';
        if (index >= menu.size()) {
            con_write(L"Not a valid menu entry.\r\n");
            goto prompt_for_key;
        }
        const menu_entry &entry = menu[index];

        try {
            if (entry.entry_type == menu_entry::CHAIN) {
                return chain_load(ImageHandle, entry.exec_path.c_str(), entry.cmdline.c_str());
            } else if (entry.entry_type == menu_entry::LINUX_CHAIN) {
                return chain_load(ImageHandle, entry.exec_path.c_str(), entry.cmdline.c_str());
            } else {
                return load_tsbp(ImageHandle, entry.exec_path.c_str(), entry.cmdline.c_str());
            }
        }
        catch (std::bad_alloc &b) {
            con_write(L"Error: not enough memory.\r\n");
        }
    }
    else {
        con_write(L"Not a valid menu entry.\r\n");
    }

    goto prompt_for_key;
}
