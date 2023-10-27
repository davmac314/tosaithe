#include <string>
#include <vector>
#include <cstdint>

struct menu_entry {
    enum entry_type_t {
        CHAIN,
        TOSAITHE
    };

    std::wstring description;
    entry_type_t entry_type = CHAIN;
    std::wstring exec_path;
    std::string cmdline;
    std::wstring initrd_path;

    menu_entry() { }
};

struct ts_config {
    uint16_t pref_gop_width = 0;
    uint16_t pref_gop_height = 0;
    bool clear_screen = true;
    std::vector<menu_entry> entries;
};

class parse_exception : public std::exception
{
    const char *what_msg;
public:
    parse_exception(const char *msg) noexcept : what_msg(msg) { }
    const char *what() const noexcept override { return what_msg; }
};

ts_config parse_config(char *conf_buf, uint64_t buf_size);
