#ifndef CPU_X86_64_INCLUDED
#define CPU_X86_64_INCLUDED 1

#include <cstdint>

// An entry in a descriptor table
struct DT_entry {
    uint64_t data;
};

enum class dt_size_t {
    s16, s32, s64
};

// For the following types, bit 0 is "accessed" bit, set by CPU on access. For code/data we set
// the 5th bit (hence "16+" in all values). This is copied into the "S" flag, it isn't technically
// part of the type.
enum class GDT_entry_type_id : uint8_t {
    DT_RWDATA = 16+2,
    DT_ROCODE = 16+10 // code, execute/read (no write)
};

struct GDT_entry_reg {
    uint16_t limit_0_15; // limit bits 0-15
    uint16_t base_0_15;  // base bits 0-15

    // 5th byte (offset 4)
    uint8_t base_16_23;  // base bits 16-23

    // 6th byte
    uint8_t entry_type : 4;
    uint8_t flag_s : 1;  // descriptor type 0=system 1=code/data (affects entry_type meaning)
    uint8_t dpl : 2;  // privilege level required to access (0 = highest privilege)
    uint8_t p : 1;    // segment present (if 0, loading descriptor will trap)

    // 7th byte
    uint8_t limit_16_19 : 4;
    uint8_t available : 1; // available for use by OS
    uint8_t flag_L : 1;    // 1=64-bit code segment, 0=32/16 bit segment or data segment
    uint8_t flag_sz : 1; // 0=16 bit, 1=32 bit; must be 0 for 64-bit segment (i.e. if L is 1)
                         // 32/16 bit: affects eg default operand size for code segments, stack pointer
                         // size for stack segment, upper limit of expand-down segment
    uint8_t flag_gr : 1; // granularity, if set limit is in 4kb granularity (otherwise byte)

    // Final byte
    uint8_t base_24_31;

    // Constructor with a standard set of parameters. Will create an entry with the specified
    // base and limit, type, bit size (16/32/64), and with DPL=0 (i.e. highest privilege level).
    // If g4k_limit is true, the specified limit is adjusted (real_limit = (limit+1) * 4096 - 1).
    constexpr GDT_entry_reg(uint32_t base, uint32_t limit, bool g4k_limit,
            GDT_entry_type_id entry_type_p, dt_size_t size_p) :
        limit_0_15(limit & 0xFFFFu),
        base_0_15(base & 0xFFFFu),
        base_16_23((base & 0xFF0000u) >> 16),
        entry_type((uint8_t)entry_type_p & 0x0Fu),
        flag_s((((uint8_t)entry_type_p & 0x10u) == 0) ? 0 : 1),
        dpl(0),
        p(1),
        limit_16_19((limit & 0x0F0000u) >> 16),
        available(0),
        flag_L((size_p == dt_size_t::s64) ? 1 : 0),
        flag_sz((size_p == dt_size_t::s16 || size_p == dt_size_t::s64) ? 0 : 1),
        flag_gr(g4k_limit),
        base_24_31((base & 0xFF000000u) >> 24)
    {
    }

    // Constructor with a standard set of parameters. Will create an entry with the specified
    // base and limit, type, bit size (16/32/64), and DPL (privilege level).
    // If g4k_limit is true, the specified limit is adjusted (real_limit = (limit+1) * 4096 - 1).
    constexpr GDT_entry_reg(uint32_t base, uint32_t limit, bool g4k_limit,
            GDT_entry_type_id entry_type_p, dt_size_t size_p, uint8_t dpl_p) :
        limit_0_15(limit & 0xFFFFu),
        base_0_15(base & 0xFFFFu),
        base_16_23((base & 0xFF0000u) >> 16),
        entry_type((uint8_t)entry_type_p & 0x0Fu),
        flag_s((((uint8_t)entry_type_p & 0x10u) == 0) ? 0 : 1),
        dpl(dpl_p),
        p(1),
        limit_16_19((limit & 0x0F0000u) >> 16),
        available(0),
        flag_L((size_p == dt_size_t::s64) ? 1 : 0),
        flag_sz((size_p == dt_size_t::s16 || size_p == dt_size_t::s64) ? 0 : 1),
        flag_gr(g4k_limit),
        base_24_31((base & 0xFF000000u) >> 24)
    {
    }

    constexpr operator DT_entry()
    {
        return DT_entry
            {
                (uint64_t)limit_0_15
                | (uint64_t(base_0_15) << 16)
                | (uint64_t(base_16_23) << 32)
                | (uint64_t(entry_type) << 40)
                | (uint64_t(flag_s) << 44)
                | (uint64_t(dpl) << 45)
                | (uint64_t(p) << 47)
                | (uint64_t(limit_16_19) << 48)
                | (uint64_t(available) << 52)
                | (uint64_t(flag_L) << 53)
                | (uint64_t(flag_sz) << 54)
                | (uint64_t(flag_gr) << 55)
                | (uint64_t(base_24_31) << 56)
            };
    }
};

// readable 16-bit code segment, base 0, 64k limit, non-conforming
inline constexpr GDT_entry_reg cons_DT_code16_descriptor()
{
    return GDT_entry_reg(0, 0xFFFFu, false, GDT_entry_type_id::DT_ROCODE, dt_size_t::s16);
}

inline constexpr GDT_entry_reg cons_DT_data16_descriptor()
{
    return GDT_entry_reg(0, 0xFFFFu, false, GDT_entry_type_id::DT_RWDATA, dt_size_t::s16);
}

// readable 32-bit code segment, base 0, 4GB limit (4kb granular), non-conforming
inline constexpr GDT_entry_reg cons_DT_code32_descriptor()
{
    return GDT_entry_reg(0, 0x000FFFFFu, true, GDT_entry_type_id::DT_ROCODE, dt_size_t::s32);
}

// standard (grows-up) 32-bit data segment, base 0, 4GB limit (4kb granular)
inline constexpr GDT_entry_reg cons_DT_data32_descriptor()
{
    return GDT_entry_reg(0, 0x000FFFFFu, true, GDT_entry_type_id::DT_RWDATA, dt_size_t::s32);
}

// readable 64-bit code segment, base 0, 4GB limit (ignored), non-conforming
inline constexpr GDT_entry_reg cons_DT_code64_descriptor()
{
    // Note base and limit will be ignored
    return GDT_entry_reg(0, 0x000FFFFFu, true, GDT_entry_type_id::DT_ROCODE, dt_size_t::s64);
}

#endif
