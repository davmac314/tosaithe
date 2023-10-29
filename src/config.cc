#include <charconv>
#include <vector>
#include <string>

#include "config.h"
#include "tosaithe-util.h"

// Config file parsing.

static const char * const msg_colon_after_entry = "expecting ':' after 'entry'";
static const char * const msg_lbrace_after_entry = "expecting '{' after 'entry:'";
static const char * const msg_rbrace_after_entry = "expecting '}' at end of entry";
static const char * const msg_equals_after_var = "expecting '=' after identifier in entry setting";
static const char * const msg_value_after_equals = "expecting value after '=' in setting";
static const char * const msg_quote_end_string = "expecting ' (quote) at end of string value";
static const char * const msg_unrecognized_value = "unrecognized setting value";
static const char * const msg_unrecognized_entry_type = "unrecognized entry type";
static const char * const msg_unrecognized_setting = "unrecognized setting";
static const char * const msg_invalid_value = "invalid value";
static const char * const msg_expected_eol = "expected end-of-line after value";

static void skip_ws(std::string_view &sv, int &line_num)
{
    while (!sv.empty() && (sv[0] == ' ' || sv[0] == '\t' || sv[0] == '\r' || sv[0] == '\n')) {
        if (sv[0] == '\n') line_num++;
        sv.remove_prefix(1);
    }
}

static void skip_to_next_line(std::string_view &sv, int &line_num)
{
    while (!sv.empty() && sv[0] != '\r' && sv[0] != '\n') {
        sv.remove_prefix(1);
    }

    if (sv.empty()) return;

    while (!sv.empty() && (sv[0] == '\r' || sv[0] == '\n')) {
        if (sv[0] == '\n') line_num++;
        sv.remove_prefix(1);
    }
}

// Read over whitespace/comments until the next line; error if encountering non-whitespace
static void read_over_eol(std::string_view &sv, int &line_num)
{
    while (!sv.empty() && (sv[0] == ' ' || sv[0] == '\t' || sv[0] == '\r')) {
        sv.remove_prefix(1);
    }

    if (sv.empty() || sv[0] == '\n')
        return;

    if (sv[0] != '#')
        throw parse_exception {line_num, msg_expected_eol};

    // skip over comment
    skip_to_next_line(sv, line_num);
    return;
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

static std::string read_assignment_value(std::string_view &conf, int &line_num)
{
    skip_ws(conf, line_num);
    if (conf.empty() || conf[0] != '=') throw parse_exception {line_num, msg_equals_after_var};
    conf.remove_prefix(1);
    skip_ws(conf, line_num);
    if (conf.empty()) throw parse_exception {line_num, msg_value_after_equals};

    if (is_ident_lead(conf[0])) {
        std::string_view value = read_ident(conf);
        read_over_eol(conf, line_num);

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
            throw parse_exception {line_num, msg_quote_end_string};
        }

        conf.remove_prefix(1); // closing quote
        read_over_eol(conf, line_num);
        return result;
    }

    throw parse_exception {line_num, msg_unrecognized_value};
}

// parse an entry - everything between braces
static menu_entry parse_entry(std::string_view &conf, int &line_num)
{
    menu_entry entry;

    while (!conf.empty() && conf[0] != '}') {
        if (conf[0] == '#') {
            skip_to_next_line(conf, line_num);
        }
        else if (is_ident_lead(conf[0])) {
            std::string_view ident = read_ident(conf);
            std::string value = read_assignment_value(conf, line_num);
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
                    throw parse_exception {line_num, msg_unrecognized_entry_type};
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

        skip_ws(conf, line_num);
    }

    return entry;
}

ts_config parse_config(char *conf_buf, uint64_t buf_size)
{
    ts_config config;
    std::vector<menu_entry> &entries = config.entries;
    std::string_view conf {conf_buf, buf_size};
    std::string_view sv_entry = "entry";
    std::string_view sv_preferred_res = "preferred_resolution";
    std::string_view sv_clearscreen = "clear_screen";

    int line_num = 1;

    skip_ws(conf, line_num);

    while (!conf.empty()) {
        if (conf[0] == '#') {
            skip_to_next_line(conf, line_num);
        }
        else if (is_ident_lead(conf[0])) {
            std::string_view ident = read_ident(conf);
            if (ident == sv_entry) {
                skip_ws(conf, line_num);
                if (conf.empty() || conf[0] != ':') throw parse_exception {line_num, msg_colon_after_entry};
                conf.remove_prefix(1); skip_ws(conf, line_num);
                if (conf.empty() || conf[0] != '{') throw parse_exception {line_num, msg_lbrace_after_entry};
                conf.remove_prefix(1); skip_ws(conf, line_num);
                entries.push_back(parse_entry(conf, line_num));
                if (conf.empty() || conf[0] != '}') throw parse_exception {line_num, msg_rbrace_after_entry};
                conf.remove_prefix(1);
            }
            else if (ident == sv_preferred_res) {
                std::string res_v = read_assignment_value(conf, line_num);
                char *first = &res_v[0];
                char *last = first + res_v.length();
                unsigned width, height;
                auto [ptr_w, ec_w] = std::from_chars(first, last, width);
                if (ec_w != std::errc{} || width == 0) {
                    throw parse_exception {line_num, msg_invalid_value};
                }
                if (ptr_w == last || (*ptr_w != 'x' && *ptr_w != '*')) {
                    throw parse_exception {line_num, msg_invalid_value};
                }
                ptr_w++;
                auto [ptr_h, ec_h] = std::from_chars(ptr_w, last, height);
                if (ec_h != std::errc{} || ptr_h != last || height == 0) {
                    throw parse_exception {line_num, msg_invalid_value};
                }
                config.pref_gop_width = width;
                config.pref_gop_height = height;
            }
            else if (ident == sv_clearscreen) {
                std::string res_v = read_assignment_value(conf, line_num);
                if (res_v == "true") {
                    config.clear_screen = true;
                }
                else if (res_v == "false") {
                    config.clear_screen = false;
                }
                else {
                    throw parse_exception {line_num, msg_invalid_value};
                }
            }
            else {
                throw parse_exception {line_num, msg_unrecognized_setting};
            }
        }

        skip_ws(conf, line_num);
    }

    return config;
}
