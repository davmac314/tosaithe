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

class parse_exception : public std::exception
{
    const char *what_msg;
public:
    parse_exception(const char *msg) noexcept : what_msg(msg) { }
    const char *what() const noexcept override { return what_msg; }
};

std::vector<menu_entry> parse_config(char *conf_buf, uint64_t buf_size);
