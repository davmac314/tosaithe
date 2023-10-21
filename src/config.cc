#include <vector>
#include <string>

#include "config.h"
#include "tosaithe-util.h"

// Config file parsing.

static const char * const msg_colon_after_entry = "expecting ':' after 'entry'";
static const char * const msg_lbrace_after_entry = "expecting '{' after 'entry:'";
static const char * const msg_rbrace_after_entry = "expecting '}' at end of entry";
static const char * const msg_equals_after_var = "expecting '=' after identifier in entry setting";
static const char * const msg_value_after_equals = "expecting value after '=' in entry setting";
static const char * const msg_quote_end_string = "expecting ' (quote) at end of string value";
static const char * const msg_unrecognized_value = "unrecognized setting value";
static const char * const msg_unrecognized_entry_type = "unrecognized entry type";
static const char * const msg_unrecognized_setting = "unrecognized setting";


static void skip_ws(std::string_view &sv)
{
    while (sv.length() > 0 && (sv[0] == ' ' || sv[0] == '\t' || sv[0] == '\r' || sv[0] == '\n')) {
        sv.remove_prefix(1);
    }
}

static void skip_to_next_line(std::string_view &sv)
{
    while (!sv.empty() && sv[0] != '\r' && sv[0] != '\n') {
        sv.remove_prefix(1);
    }

    if (sv.empty()) return;

    while (!sv.empty() && (sv[0] == '\r' || sv[0] == '\n')) {
        sv.remove_prefix(1);
    }
}

static bool is_ident_lead(char c)
{
    return c >= 'a' && c <= 'z';
}

static bool is_ident(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
}

static std::string_view read_ident(std::string_view &sv)
{
    const char *start = sv.data();
    while (!sv.empty() && is_ident(sv[0])) sv.remove_prefix(1);
    return std::string_view(start, sv.data() - start);
}

static std::string read_assignment_value(std::string_view &conf)
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
static menu_entry parse_entry(std::string_view &conf)
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
            else if (ident == "initrd") {
                entry.initrd_path = utf8toUCS2::convert(value.c_str());
            }
        }
        else {
            return entry;
        }

        skip_ws(conf);
    }

    return entry;
}

std::vector<menu_entry> parse_config(char *conf_buf, uint64_t buf_size)
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
