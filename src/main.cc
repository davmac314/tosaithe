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
    EFI_FILE_PROTOCOL *file_to_load;
    try {
        file_to_load = open_file(dev_path);
    }
    catch (open_file_exception &ofe) {
        if (ofe.reason == open_file_exception::NO_FSPROTOCOL_FOR_DEV_PATH) {
            throw load_file_exception(load_file_exception::NO_FSPROTOCOL_FOR_DEV_PATH);
        }
        else if (ofe.reason == open_file_exception::CANNOT_OPEN_VOLUME) {
            throw load_file_exception(load_file_exception::CANNOT_OPEN_VOLUME, ofe.status);
        }
        else if (ofe.reason == open_file_exception::NO_DPTT_PROTOCOL) {
            throw load_file_exception(load_file_exception::NO_DPTT_PROTOCOL);
        }
        else /* CANNOT_OPEN_FILE */ {
            throw load_file_exception(load_file_exception::CANNOT_OPEN_FILE, ofe.status);
        }
    }

    efi_file_handle file_to_load_hndl { file_to_load };

    EFI_FILE_INFO *load_file_info = get_file_info(file_to_load);
    if (load_file_info == nullptr) {
        throw load_file_exception(load_file_exception::CANNOT_GET_FILE_SIZE);
    }

    UINTN read_amount = load_file_info->FileSize;
    free_pool(load_file_info);

    void *load_address = alloc_pool(read_amount);
    if (load_address == nullptr) {
        throw std::bad_alloc();
    }

    EFI_STATUS status = file_to_load_hndl.read(&read_amount, load_address);
    if (EFI_ERROR(status)) {
        free_pool(load_address);
        throw load_file_exception(load_file_exception::CANNOT_READ_FILE, status);
    }

    if (buf_size_ptr) *buf_size_ptr = read_amount;
    return load_address;
}

static EFI_DEVICE_PATH_PROTOCOL *resolve_relative_path(EFI_HANDLE image_handle, const CHAR16 *path)
{
    EFI_DEVICE_PATH_FROM_TEXT_PROTOCOL *text2dp_proto =
            (EFI_DEVICE_PATH_FROM_TEXT_PROTOCOL *)locate_protocol(EFI_device_path_from_text_protocol_guid);

    if (text2dp_proto == nullptr) {
        con_write(L"EFI_DEVICE_PATH_FROM_TEXT protocol not supported.\r\n");
        return nullptr;
    }

    EFI_DEVICE_PATH_PROTOCOL *path_devpath = text2dp_proto->ConvertTextToDevicePath(path);

    // Media (0x4) file path (0x4)
    if (path_devpath->Type != 0x4 || path_devpath->SubType != 0x04) {
        // Not a file path, assume it's an absolute device path
        return path_devpath;
    }

    // Find our volume device path, resolve relative to that

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

    unsigned fp_offs = find_file_path(image_path);
    if (fp_offs == (unsigned)-1) {
        con_write(L"Image device path does not appear to refer to filesystem.\r\n");
        return nullptr;
    }

    unsigned path_devpath_sz = find_devpath_size(path_devpath);

    // need to reallocate
    EFI_DEVICE_PATH_PROTOCOL *new_devpath =
            (EFI_DEVICE_PATH_PROTOCOL *) alloc_pool(fp_offs + path_devpath_sz);
    if (new_devpath == nullptr) {
        throw std::bad_alloc();
    }

    // Copy original path, up to where file path begins
    memcpy(new_devpath, image_path, fp_offs);
    // Append new file path
    memcpy((char *)new_devpath + fp_offs, path_devpath, path_devpath_sz);

    free_pool(path_devpath);

    return new_devpath;
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

    // Note that the UEFI spec is *fantastically* vague about what "LoadOptions" should really contain.
    // It's supposedly *binary* data, but the EFI shell uses it to pass the command line to any application
    // it runs (including the command name). If started as part of a boot option the data is just taken
    // from the EFI variable which defines the boot option (this is vaguely explained in the "Boot Manager"
    // chapter of the UEFI spec). Linux expects it to be a command line *without* a command name (i.e. is
    // inconsistent with what the EFI shell provides).
    //
    // In absence of cohesion and sanity in the rest of the world, then, we'll just pass the command line
    // exactly as it was provided by the user (i.e. not necessarily with the command name as part of the
    // command line).
    chained_image_LIP->LoadOptions = (void *)cmdline;
    chained_image_LIP->LoadOptionsSize = (strlen(cmdline) + 1) * sizeof(CHAR16);

    status = EBS->StartImage(loaded_handle, nullptr, nullptr);

    return status;
}

EFI_STATUS load_tsbp(EFI_HANDLE ImageHandle, const EFI_DEVICE_PATH_PROTOCOL *exec_path,
        const char *cmdLine);

struct menu_entry {
    enum entry_type_t {
        CHAIN,
        TOSAITHE
    };

    std::wstring description;
    entry_type_t entry_type = CHAIN;
    std::wstring exec_path;
    std::string cmdline;

    menu_entry() { }

    menu_entry(const CHAR16 *description_p, entry_type_t entry_type_p, const CHAR16 *exec_path_p,
            const char *cmdline_p)
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


std::string read_assignment_value(std::string_view &conf)
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

        return std::string(value.data(), value.length());
    }
    else if (conf[0] == '\'') {
        conf.remove_prefix(1);
        std::string result;
        while (!conf.empty() && conf[0] != '\'') {
            result += conf[0];
            conf.remove_prefix(1);
        }

        if (conf.empty()) {
            throw parse_exception {msg_quote_end_string};
        }

        // TODO check for trailing junk (allow trailing comment)
        skip_to_next_line(conf);

        return result;
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
            std::string value = read_assignment_value(conf);
            if (ident == "description") {
                entry.description = utf8toUCS2::convert(value.c_str());
            }
            else if (ident == "exec") {
                entry.exec_path = utf8toUCS2::convert(value.c_str());
            }
            else if (ident == "type") {
                if (value == "chain") {
                    entry.entry_type = menu_entry::CHAIN;
                }
                else if (value == "tosaithe") {
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

    EFI_con_out->SetAttribute(EFI_con_out, EFI_WHITE);
    con_write(L"Tosaithe");
    EFI_con_out->SetAttribute(EFI_con_out, EFI_LIGHTGRAY);
    con_write(L" boot menu\r\n");

    auto display_revision = [](uint32_t revision) {
        unsigned revision_major = revision >> 16;
        unsigned revision_minor = revision & 0xFFFFu;
        con_write(revision_major);
        con_write(L".");
        con_write(revision_minor);
    };

    // Some system info:
    con_write(L"Firmware vendor: ");
    EFI_con_out->SetAttribute(EFI_con_out, EFI_LIGHTCYAN);
    con_write(SystemTable->FirmwareVendor);
    EFI_con_out->SetAttribute(EFI_con_out, EFI_LIGHTGRAY);
    con_write(L"\r\nFirmware revision: ");
    EFI_con_out->SetAttribute(EFI_con_out, EFI_LIGHTCYAN);
    display_revision(SystemTable->FirmwareRevision);
    EFI_con_out->SetAttribute(EFI_con_out, EFI_LIGHTGRAY);
    con_write(L"\r\nUEFI revision: ");
    EFI_con_out->SetAttribute(EFI_con_out, EFI_LIGHTCYAN);
    display_revision(SystemTable->Hdr.Revision);
    EFI_con_out->SetAttribute(EFI_con_out, EFI_LIGHTGRAY);
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

    auto explain_load_file_failure = [](const load_file_exception &lfe) {
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
    };

    try {
        conf_buf = efi_unique_ptr_wrap((char *) load_entire_file(conf_path.get(), &conf_size));
    }
    catch (load_file_exception &lfe) {
        con_write(L"Could not load 'tosaithe.conf'");
        explain_load_file_failure(lfe);
        con_write(L"\r\n");
        return EFI_LOAD_ERROR;
    }

    conf_path.reset();

    try {
        menu = parse_config(conf_buf.get(), conf_size);
    }
    catch (parse_exception &pe) {
        utf8toUCS2 uu;
        uu.process(pe.what());

        con_write(L"Error in tosaithe.conf: ");
        con_write(uu.get_output().c_str());
        con_write(L"\r\n");

        return EFI_LOAD_ERROR;
    }

    conf_buf.reset();

    unsigned entry_offs = 0;

    display_menu:

    EFI_con_out->SetAttribute(EFI_con_out, EFI_YELLOW);
    con_write(L"Please make a selection:\r\n\r\n");
    EFI_con_out->SetAttribute(EFI_con_out, EFI_LIGHTCYAN);

    for (unsigned i = 0; i < 10; ++i) {
        if (i + entry_offs >= menu.size())
            break;

        // Write 'n' where n is 1 2 3 4 5 6 7 8 9 or 0
        EFI_con_out->SetAttribute(EFI_con_out, EFI_WHITE);
        if (i != 9) {
            con_write(i+1);
        }
        else {
            con_write((uint64_t)0);
        }
        EFI_con_out->SetAttribute(EFI_con_out, EFI_LIGHTCYAN);
        con_write(L". ");

        auto &entry = menu[i + entry_offs];
        con_write(entry.description.c_str());
        con_write(L"\r\n");
    }

    EFI_con_out->SetAttribute(EFI_con_out, EFI_LIGHTBLUE);
    con_write(L"\r\n[  ");
    bool have_nav = false;
    if (entry_offs + 10 < menu.size()) {
        // "next"
        EFI_con_out->SetAttribute(EFI_con_out, EFI_WHITE);
        con_write(L"n");
        EFI_con_out->SetAttribute(EFI_con_out, EFI_LIGHTGRAY);
        con_write(L"ext ");
        have_nav = true;
    }
    if (entry_offs > 0) {
        // "previous"
        EFI_con_out->SetAttribute(EFI_con_out, EFI_WHITE);
        con_write(L"p");
        EFI_con_out->SetAttribute(EFI_con_out, EFI_LIGHTGRAY);
        con_write(L"revious ");
        have_nav = true;
    }
    if (have_nav) {
        EFI_con_out->SetAttribute(EFI_con_out, EFI_LIGHTBLUE);
        con_write(L" |  ");
    }
    // "exit"
    EFI_con_out->SetAttribute(EFI_con_out, EFI_LIGHTGRAY);
    con_write(L"e");
    EFI_con_out->SetAttribute(EFI_con_out, EFI_WHITE);
    con_write(L"x");
    EFI_con_out->SetAttribute(EFI_con_out, EFI_LIGHTGRAY);
    con_write(L"it  ");

    // "shutdown"
    EFI_con_out->SetAttribute(EFI_con_out, EFI_WHITE);
    con_write(L"s");
    EFI_con_out->SetAttribute(EFI_con_out, EFI_LIGHTGRAY);
    con_write(L"hutdown  ");

    EFI_con_out->SetAttribute(EFI_con_out, EFI_LIGHTBLUE);
    con_write(L"]\r\n");

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
    if (key_pr.UnicodeChar == 0) {
        key_str[0] = L'?';
    }
    key_str[1] = L'\r'; key_str[2] = L'\n';
    key_str[3] = 0;
    con_write(key_str);
    EFI_con_out->SetAttribute(EFI_con_out, EFI_LIGHTGRAY);

    if (key_pr.UnicodeChar >= L'0' && key_pr.UnicodeChar <= L'9') {
        unsigned index;
        if (key_pr.UnicodeChar == L'0') {
            index = 10;
        }
        else {
            index = key_pr.UnicodeChar - L'1';
        }
        if (index + entry_offs >= menu.size()) {
            con_write(L"Not a valid menu entry.\r\n");
            goto prompt_for_key;
        }
        const menu_entry &entry = menu[index + entry_offs];

        try {
            if (entry.entry_type == menu_entry::CHAIN) {
                std::wstring cmdline16 = utf8toUCS2::convert(entry.cmdline.c_str());
                EFI_STATUS status = chain_load(ImageHandle, entry.exec_path.c_str(), cmdline16.c_str());
                if (status == EFI_LOAD_ERROR) {
                    // error message has already been displayed
                    con_write(L"\r\n");
                    goto prompt_for_key;
                }
                if (status != EFI_SUCCESS) {
                    con_write(L"\r\nApplication returned error status: 0x");
                    con_write_hex(status);
                }
            } else {
                EFI_DEVICE_PATH_PROTOCOL *kernel_devpath = resolve_relative_path(ImageHandle,
                        entry.exec_path.c_str());
                if (kernel_devpath != nullptr) {
                    load_tsbp(ImageHandle, kernel_devpath, entry.cmdline.c_str());
                    // if this fails an error message has already been displayed
                }
            }
            EFI_con_out->SetAttribute(EFI_con_out, EFI_WHITE);
            con_write(L"\r\n\r\nTosaithe");
            EFI_con_out->SetAttribute(EFI_con_out, EFI_LIGHTGRAY);
            con_write(L" boot menu - enter selection; [");
            EFI_con_out->SetAttribute(EFI_con_out, EFI_WHITE);
            con_write(L"space");
            EFI_con_out->SetAttribute(EFI_con_out, EFI_LIGHTGRAY);
            con_write(L"] to show menu\r\n");
            goto prompt_for_key;
        }
        catch (std::bad_alloc &b) {
            con_write(L"Error: not enough memory.\r\n");
        }
    }
    else if (key_pr.UnicodeChar == L'n') {
        if (entry_offs + 10 < menu.size()) {
            entry_offs += 10;
            con_write(L"\r\n\n\n");
            goto display_menu;
        }
        else {
            con_write(L"No more menu entries.");
        }
    }
    else if (key_pr.UnicodeChar == L'p') {
        if (entry_offs > 0) {
            entry_offs -= 10;
            con_write(L"\r\n\n\n");
            goto display_menu;
        }
        else {
            con_write(L"No preceding menu entries.");
        }
    }
    else if (key_pr.UnicodeChar == L's') {
        SystemTable->RuntimeServices->ResetSystem(EfiResetShutdown, EFI_SUCCESS, 0, nullptr);
    }
    else if (key_pr.UnicodeChar == L'x') {
        con_write(L"\r\n");
        return EFI_SUCCESS;
    }
    else if (key_pr.UnicodeChar == L' ') {
        con_write(L"\r\n");
        goto display_menu;
    }
    else {
        con_write(L"Not a valid key/entry (press space to redisplay menu).\r\n");
    }

    goto prompt_for_key;
}
