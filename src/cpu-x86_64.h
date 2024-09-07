#ifndef CPU_X86_64_INCLUDED
#define CPU_X86_64_INCLUDED 1

#include <cstdint>

// MSRs
const uint32_t IA32_EFER = 0xC0000080;
const uint32_t IA32_FS_BASE = 0xC0000100;
const uint32_t IA32_GS_BASE = 0xC0000101;
const uint32_t IA32_KERNEL_GS_BASE = 0xC0000102;


// An entry in a descriptor table
struct descr_tbl_entry {
    uint64_t data;
};

// Argument to LGDT instruction will be this format:
struct lgdt64_params {
    uint16_t size;
    descr_tbl_entry *base; /* linear base address */
} __attribute__((packed));


// General format GDT entry; note that some entries expand to 16 bytes (2 regular entries) in
// long (64-bit) mode.

// In long mode bases are ignored (except for FS, GS registers) and limits are always ignored.
// segments DS, ES don't really exist; all access is via code segment. Segment register Loads
// however may still trap? and will load limits that will apply in compatible mode (i.e when
// running 32/16 bit code). Paging forms the only protection mechanism.

// Entry types (including system bit):

// For the following types, bit 0 is "accessed" bit, set by CPU on access. For code/data we set
// the 5th bit (hence "16+" in all values). This is copied into the "S" flag, it isn't technically
// part of the type.
const static uint16_t DT_RODATA = 16+0;
const static uint16_t DT_RWDATA = 16+2;
const static uint16_t DT_RODATA_EXPANDDOWN = 16+4;
const static uint16_t DT_RWDATA_EXPANDDOWN = 16+6;
const static uint16_t DT_CODE = 16+8; // code, execute-only (no read/write)
const static uint16_t DT_ROCODE = 16+10; // code, execute/read (no write)
const static uint16_t DT_CODE_CONFORMING = 16+12; // code, conforming, execute-only (no read/write)
const static uint16_t DT_ROCODE_CONFORMING = 16+14; // code, conforming, execute/read (no write)
// Note, stack segments must be read/write data segments
// "expand down" means the usable address range is limit-MAX rather than 0-limit, in theory this
// could be used for stacks in a (stack segment != data segment) model (not typical!).
// "conforming" allows execution at a lower privilege level (i.e. it's possible to jump to this
// code segment with a privilege level lower than the code segment's privilege level; execution
// will continue with the lower privilege level, i.e. this won't elevate privilege).

const static uint16_t DT_UPPER8 = 0;           // upper 8 bytes of a long descriptor
                                               // (upper half of LDT/TSS descriptor in long mode)

const static uint16_t DT_TSS16_AVAILABLE = 1;  // 16-bit TSS, available (reserved in long mode)
const static uint16_t DT_LDT = 2;              // LDT descriptor
const static uint16_t DT_TSS16_BUSY = 3;       // 16-bit TSS, available (reserved in long mode)
const static uint16_t DT_CALLGATE16 = 4;       // 16-bit call gate (reserved in long mode)
const static uint16_t DT_TASKGATE = 5;         // task gate (reserved in long mode)
const static uint16_t DT_INTERRUPTGATE16 = 6;  // 16-bit interrupte gate (reserved in long mode)
const static uint16_t DT_TRAPGATE16 = 7;       // 16-bit trap gate (reserved in long mode)
// type 8 is reserved
const static uint16_t DT_TSS_AVAIL = 9;        // 32/64 bit TSS, not busy
// type 10 is reserved
const static uint16_t DT_TSS_BUSY = 11;        // 32/64 bit TSS, busy
const static uint16_t DT_CALLGATE = 12;        // 32/64 bit call gate
// type 13 is reserved
const static uint16_t DT_INTERRUPTGATE = 14;   // 32/64 bit interrupt gate
const static uint16_t DT_TRAPGATE = 15;        // 32/64 bit trap gate



enum class dt_size_t {
    s16, s32, s64
};

// A "regular" GDT entry. Can be implicitly converted to descr_tbl_entry.
struct gdt_entry {
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
    constexpr gdt_entry(uint32_t base, uint32_t limit, bool g4k_limit,
            uint16_t entry_type_p, dt_size_t size_p) :
        limit_0_15(limit & 0xFFFFu),
        base_0_15(base & 0xFFFFu),
        base_16_23((base & 0xFF0000u) >> 16),
        entry_type(entry_type_p & 0x0Fu),
        flag_s(((entry_type_p & 0x10u) == 0) ? 0 : 1),
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
    constexpr gdt_entry(uint32_t base, uint32_t limit, bool g4k_limit,
            uint16_t entry_type_p, dt_size_t size_p, uint8_t dpl_p) :
        limit_0_15(limit & 0xFFFFu),
        base_0_15(base & 0xFFFFu),
        base_16_23((base & 0xFF0000u) >> 16),
        entry_type(entry_type_p & 0x0Fu),
        flag_s(((entry_type_p & 0x10u) == 0) ? 0 : 1),
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

    constexpr operator descr_tbl_entry()
    {
        return descr_tbl_entry
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

// Interrupt gate / task gate entry (valid in the IDT). For 64-bit IDT, this is half of a pair.
struct idt_entry {
    uint16_t offset_0_15; // offset bits 0-15

    uint16_t sselector;   // segment selector (must identify 64-bit code segment)

    uint16_t ist : 3;     // interrupt stack table selector (0 = none) (64-bit IDT only)
    uint16_t z0 : 1;      // 0
    uint16_t z1 : 1;      // 0
    uint16_t z2 : 3;      // 000
    uint16_t dtype : 5;   // descriptor type (interrupt or trap gate)
    uint16_t dpl : 2;     // reqd privilege level
    uint16_t p : 1;       // present?

    uint16_t offset_16_31; // offset bits 16-31

    idt_entry(void *offset, uint16_t sselector_p, uint16_t dtype_p, uint16_t dpl_p = 0,
            uint16_t p_p = 1, uint16_t ist_p = 0)
        : offset_0_15((uintptr_t)offset & 0xFFFFu),
          sselector(sselector_p),
          ist(0),
          z0(0), z1(0), z2(0),
          dtype(dtype_p),
          dpl(dpl_p),
          p(p_p),
          offset_16_31((uintptr_t)offset >> 16)
    {
    }

    constexpr operator descr_tbl_entry()
    {
        return descr_tbl_entry {
            (uint64_t)offset_0_15
            | ((uint64_t)sselector << 16)
            | ((uint64_t)ist << 32)
            | ((uint64_t)z0 << 35)
            | ((uint64_t)z1 << 36)
            | ((uint64_t)z2 << 37)
            | ((uint64_t)dtype << 40)
            | ((uint64_t)dpl << 45)
            | ((uint64_t)p << 47)
            | ((uint64_t)offset_16_31 << 48)
        };
    }
};


// The expanded upper portion of a 16-byte TSS or LDT (i.e. a TSS or LDT in 64-bit mode), or IDT entry
struct descr_tbl_exp_entry {
    uint32_t base_address_32_63;  // base address bits 32-63
    uint32_t reserved;

    constexpr operator descr_tbl_entry()
    {
        return descr_tbl_entry { (uint64_t)base_address_32_63 };
    }
};


// readable 16-bit code segment, base 0, 64k limit, non-conforming
inline constexpr gdt_entry cons_dt_code16_descriptor()
{
    return gdt_entry(0, 0xFFFFu, false, DT_ROCODE, dt_size_t::s16);
}

// readable 16-bit data segment, base 0, 64k limit, non-conforming
inline constexpr gdt_entry cons_dt_data16_descriptor()
{
    return gdt_entry(0, 0xFFFFu, false, DT_RWDATA, dt_size_t::s16);
}

// readable 32-bit code segment, base 0, 4GB limit (4kb granular), non-conforming
inline constexpr gdt_entry cons_dt_code32_descriptor()
{
    return gdt_entry(0, 0x000FFFFFu, true, DT_ROCODE, dt_size_t::s32);
}

// readable 32-bit code segment, base 0, 4GB limit (4kb granular), non-conforming
//  dpl = privilege level (0 = highest, 3 = lowest)
inline constexpr gdt_entry cons_dt_code32_descriptor(uint8_t dpl)
{
    return gdt_entry(0, 0x000FFFFFu, true, DT_ROCODE, dt_size_t::s32, dpl);
}

// standard (grows-up) 32-bit data segment, base 0, 4GB limit (4kb granular), dpl = 0
inline constexpr gdt_entry cons_dt_data32_descriptor()
{
    return gdt_entry(0, 0x000FFFFFu, true, DT_RWDATA, dt_size_t::s32);
}

// standard (grows-up) 32-bit data segment, base 0, 4GB limit (4kb granular)
//  dpl = required privilege level (0 = highest, 3 = lowest)
inline constexpr gdt_entry cons_dt_data32_descriptor(uint8_t dpl)
{
    return gdt_entry(0, 0x000FFFFFu, true, DT_RWDATA, dt_size_t::s32, dpl);
}

// readable 64-bit code segment, base 0, 4GB limit (ignored), non-conforming
inline constexpr gdt_entry cons_dt_code64_descriptor()
{
    // Note base and limit will be ignored
    return gdt_entry(0, 0x000FFFFFu, true, DT_ROCODE, dt_size_t::s64);
}

// readable 64-bit code segment, base 0, 4GB limit (ignored), non-conforming
//  dpl = required privilege level (0 = highest, 3 = lowest)
inline constexpr gdt_entry cons_dt_code64_descriptor(uint8_t dpl)
{
    // Note base and limit will be ignored
    return gdt_entry(0, 0x000FFFFFu, true, DT_ROCODE, dt_size_t::s64);
}

// Note there is not really such a thing as 64-bit data descriptor. You can use a regular 32-bit
// descriptor, though; the base and limit will be ignored anyway. You can also use a null selector
// (except for SS in CPL 3).

// Construct a dummy LDT with a single entry
inline constexpr gdt_entry cons_ldt_descriptor(uint32_t base)
{
    return gdt_entry(base, 7, false, DT_LDT, dt_size_t::s16);
}

// 2nd half of a 64-bit LDT or TSS descriptor. base_32_63 specifies the upper 32 bits of the
// 64-bit base address.
inline constexpr descr_tbl_exp_entry cons_dt64_upper(uint32_t base_32_63)
{
    return descr_tbl_exp_entry{base_32_63, 0};
}

inline descr_tbl_exp_entry cons_dt64_upper(void *base_ptr)
{
    return descr_tbl_exp_entry{(uint32_t)((uint64_t)base_ptr >> 32), 0};
}

// Construct a 32/64 bit TSS descriptor (first half of the latter). The limit is a 20-bit value.
inline constexpr gdt_entry cons_tss_descriptor(uint32_t base_0_31, uint32_t limit)
{
    return gdt_entry(base_0_31, limit, false, DT_TSS_AVAIL, dt_size_t::s16);
}


// 64-bit mode Task State Segment (TSS).
struct tss64_struct {
    uint32_t reserved_0 = 0; // Note, the presence of this means every 8-byte value following is
                             // aligned on a 4-byte but not 8-byte boundary.

    uint64_t RSP0 = 0;  // Stack pointer for privilege level 0
    uint64_t RSP1 = 0;  // Stack pointer for privilege level 1
    uint64_t RSP2 = 0;  // Stack pointer for privilege level 2

    uint64_t reserved_28 = 0;

    uint64_t IST1 = 0;  // "Interrupt Stack Table" 1 through 7
    uint64_t IST2 = 0;
    uint64_t IST3 = 0;
    uint64_t IST4 = 0;
    uint64_t IST5 = 0;
    uint64_t IST6 = 0;
    uint64_t IST7 = 0;

    uint64_t reserved_92 = 0;
    uint16_t reserved_100 = 0;

    uint16_t io_map_base;  // Offset, within this TSS, of the I/O map

    // Default constructor which puts the IOMapBase at the end of the structure. Note the IOMap is
    // variable-sized and ends at the TSS end. A TSS sized the same as this structure will
    // therefore have no IOMap. All ISTs and RSPs will be set 0.
    constexpr tss64_struct() : io_map_base(sizeof(tss64_struct)) { }

} __attribute__((packed));

// Interrupt descriptor table entry (64-bit mode).
struct idt64_entry {
    descr_tbl_entry lower;
    descr_tbl_entry upper;
};

// Argument to LIDT is in this format:
struct lidt64_params {
    uint16_t size;
    idt64_entry *base; /* linear base address */
} __attribute__((packed));


// CPUID instruction data formats.
// These are names as follows. For variants where input is EAX:
//
//    cpuid_<eax-input-value>_<output-register>
//
//    eg:  cpuid_01_ecx - format for ECX output from CPUID with EAX=1 on input
//
// Where the input is both EAX and ECX:
//
//    cpuid_<eax-input-value>_<ecx-input-value>_<output-register>
//
//    eg:  cpuid_07_00_ebx - format for EBX output from CPUID with EAX=7,ECX=0 on input
//
// Details can be found in:
//  Intel Software Developer's Manual Volume 2 - CPUID instruction
//  AMD64 Programmer's Manual Volume 3 - Appendix E "Obtaining Processor Information via the CPUID
//        instruction"
// The AMD documentation (rev 3.34) however contains a few errors/omissions.

struct cpuid_01_eax {
    uint32_t stepping_id : 4;
    uint32_t model : 4;
    uint32_t family_id : 4;
    uint32_t processor_type : 2;
    uint32_t reserved1 : 2;
    uint32_t extended_model_id : 4;
    uint32_t extended_family_id : 8;
    uint32_t reserved2 : 4;
};

struct cpuid_01_ecx {
    uint32_t ft_sse3 : 1; // SSE3
    uint32_t ft_pclmulqdq : 1; // PCLMULQDQ carry-less multiply
    uint32_t ft_dtes64 : 1; // 64-bit debug store area (AMD: reserved)
    uint32_t ft_monitor : 1; // MONITOR/MWAIT
    uint32_t ft_dscpl : 1; // CPL qualified debug store (AMD: reserved)
    uint32_t ft_vmx : 1; // Virtual machine extensions (AMD: reserved)
    uint32_t ft_smx : 1; // Safer mode extensions (AMD: reserved)
    uint32_t ft_eist : 1; // Enhanced Intel Speed Step technology (AMD: reserved)
    uint32_t ft_tm2 : 1; // Thermal monitor 2 (AMD: reserved)
    uint32_t ft_ssse3 : 1; // SSSE3
    uint32_t ft_cnxtid : 1; // L1 context ID (AMD: reserved)
    uint32_t ft_sdbg : 1; // Silicon debug (IA32_DEBUG_INTERFACE MSR) (AMD: reserved)
    uint32_t ft_fma : 1; // FMA extensions
    uint32_t ft_cmpxchg16b : 1; // CMPXCHG16B instruction
    uint32_t ft_xtpr_update_control : 1; // IA32_MISC_ENABLE[bit 23] can be changed (AMD: reserved)
    uint32_t ft_pdcm : 1; // Perfmon and Debug capability (IA32_PERF_CAPABILITIES) (AMD: reserved)
    uint32_t reserved6 : 1;
    uint32_t ft_pcid : 1; // Process context IDs, CR4.PCIDE
                          // (AMD: reserved, PCID support implied by cpuid_07_00_ebx.ft_invpcid)
                          // => using cpuid_07_00_ebx.ft_invpcid instead is suggested.
    uint32_t ft_dca : 1; // Pre-fetch from memory-mapped device (AMD: reserved)
    uint32_t ft_sse4_1 : 1; // SSE4.1
    uint32_t ft_sse4_2 : 1; // SSE4.2
    uint32_t ft_x2apic : 1; // x2APIC
    uint32_t ft_movbe : 1; // MOVBE instruction (move and swap byte order)
    uint32_t ft_popcnt : 1; // POPCNT instruction
    uint32_t ft_tsc_deadline : 1; // LAPIC timer supports TSC deadline mode (AMD: reserved)
    uint32_t ft_aesni : 1; // AESNI instruction extensions
    uint32_t ft_xsave : 1; // XSAVE/XRSTOR/XSETBV/XGETBV instructions, XCR0 register
    uint32_t osxsave : 1; // set when CR4[bit 18] set, i.e. os has enabled XSAVE
    uint32_t ft_avx : 1; // AVX instructions/registers
    uint32_t ft_f16c : 1; // Half-precision convert instruction
    uint32_t ft_rdrand : 1; // RDRAND instruction
    uint32_t ft_raz : 1; // reserved for use by hypervisors / not used
};

struct cpuid_01_edx {
    uint32_t ft_fpu : 1; // FPU on chip
    uint32_t ft_vme : 1; // Virtual-8086 Mode Enhancement
    uint32_t ft_de : 1; // Debugging extensions
    uint32_t ft_pse : 1; // Page size extensions
    uint32_t ft_tsc : 1; // Timestamp counter
    uint32_t ft_msr : 1; // RDMSR/WRMSR support
    uint32_t ft_pae : 1; // Physical address extensions
    uint32_t ft_mce : 1; // Machine check exception
    uint32_t ft_cx8 : 1; // CMPXCHG8B support
    uint32_t ft_apic : 1; // APIC on chip
    uint32_t reserved3 : 1;
    uint32_t ft_sep : 1; // SYSENTER/SYSEXIT
    uint32_t ft_mtrr : 1; // MTRRs
    uint32_t ft_pge : 1; // Pagetable Global bit
    uint32_t ft_mca : 1; // Machine check architecture
    uint32_t ft_cmov : 1; // CMOV instruction
    uint32_t ft_pat : 1; // Page Attribute Table
    uint32_t ft_pse36 : 1; // Page Size Extension
    uint32_t ft_psn : 1; // Processor serial number
    uint32_t ft_clflsh : 1; // CLFLUSH instruction
    uint32_t reserved4 : 1;
    uint32_t ft_ds : 1; // Debug store
    uint32_t ft_acpi : 1; // Thermal monitor and clock control
    uint32_t ft_mmx : 1; // MMX technology
    uint32_t ft_fxsr : 1; // FXSAVE/FXRSTORE instructions
    uint32_t ft_sse : 1; // SSE extensions
    uint32_t ft_sse2 : 1; // SSE2
    uint32_t ft_ss : 1; // Self-snoop
    uint32_t ft_htt : 1; // Hyperthreading
    uint32_t ft_tm : 1; // Thermal monitor
    uint32_t reserved5 : 1;
    uint32_t ft_pbe : 1; // Pending Brk enable
};

struct cpuid_07_00_ebx {
    // Notables:  fsgsbase, smep, invpcid, rdseed, smap
    // Note that AMD64 Architecture Programmer's Manual (rev 3.34) lists rdpcid feature in ebx bit
    // 22, but it is actually ecx bit 22.
    uint32_t ft_fsgsbase : 1; // support for RDFSBASE/RDGSBASE/WRFSBASE/WRGSBASE
    uint32_t ft_tsc_adjust : 1; // support for IA32_TSC_ADJUST MSR (AMD: reserved)
    uint32_t ft_sgx : 1; // support for Intel's SGX (AMD: reserved)
    uint32_t ft_bmi1 : 1; // support for BMI1 bit manipulation instruction extensions
    uint32_t ft_hle : 1; // support for HLE (AMD: reserved)
    uint32_t ft_avx2 : 1; // support for AVX2 instructions
    uint32_t ft_fdp_excptn_only : 1; // FPU Data Pointer updated only on x86 exceptions (AMD: reserved)
    uint32_t ft_smep : 1; // Supervisor Mode Execution Prevention
    uint32_t ft_bmi2 : 1; // support for BMI2 bitmask instruction extensions
    uint32_t ft_enh_repmovsb : 1; // supports Enhanced REP MOVSB/STOSB (AMD: reserved, but documented
                                  // in Processor Programming Reference for family 19h model 21h...)
    uint32_t ft_invpcid : 1; // INVPCID instruction support
    uint32_t ft_rtm : 1; // RTM (AMD: reserved)
    uint32_t ft_rdtm : 1; // Intel: RDT (Resource Director Tech) monitoring capability
                          // AMD: PQM (Platform QOS Monitoring support)
    uint32_t ft_depr_fpu_cs_ds : 1; // FPU CS and DS are deprecated (AMD: reserved)
    uint32_t ft_mpx : 1; // Intel MPX (AMD: reserved)
    uint32_t ft_rdta : 1; // Intel: RDT allocation capability, AMD: QOS Enforcement support
    uint32_t ft_avx512f : 1; // AVX512F
    uint32_t ft_avx512dq : 1; // AVX512DQ
    uint32_t ft_rdseed : 1; // RDSEED instruction support
    uint32_t ft_adx : 1; // ADCX, ADOX instruction support
    uint32_t ft_smap : 1; // Supervisor Mode Access Prevention
    uint32_t ft_avx512ifma : 1; // AVX512-IFMA
    uint32_t reserved : 1; //  reserved
      // INCORRECTLY documented by AMD as RDPID instruction / TSC_AUX MSR
      // (which actually comes from ecx register!).
    uint32_t ft_clflushopt : 1; // CLFLUSHOPT instruction
    uint32_t ft_clwb : 1; // CLWB instruction
    uint32_t ft_ipt : 1; // Intel Processor Trace (AMD: reserved)
    uint32_t ft_avx512pf : 1; // AVX512-PF (Intel Xeon Phi processors only) (AMD: reserved)
    uint32_t ft_avx512er : 1; // AVX512-ER (Intel Xeon Phi processors only) (AMD: reserved)
    uint32_t ft_avx512cd : 1; // AVX512CD (AMD: reserved)
    uint32_t ft_sha : 1; // SHA instructions
    uint32_t ft_avx512bw : 1; // AVX512BW
    uint32_t ft_avx512vl : 1; // AVX512VL
};

struct cpuid_07_00_ecx {
    // Notables: ft_umip, ft_la57
    uint32_t ft_prefetchwt1 : 1; // PREFETCHWT1 instruction (Intel Xeon Phi only) (AMD: Reserved)
    uint32_t ft_avx512_vbmi : 1; // AVX VBMI instructions (Intel) (AMD: Reserved)
    uint32_t ft_umip : 1; // User-mode instruction prevention, enabled via CR4.en_umip
    uint32_t ft_pku : 1; // Protection keys for user pages
    uint32_t ft_ospke : 1; // Set if CR4.en_pk has been set
    uint32_t ft_waitpkg : 1; // UMWAIT/UMONITOR instructions (Intel) (AMD: Reserved)
    uint32_t ft_avx512_vbmi2 : 1; // AVX VBMI2 instructions (Intel) (AMD: Reserved)
    uint32_t ft_cet_ss : 1; // CET shadow stack features
    uint32_t ft_gfni : 1; // Galois field new instructions (Intel SSE) (AMD: Reserved)
    uint32_t ft_vaes : 1; // Vector AES (crypto) instructions (AVX)
    uint32_t ft_vpclmulqdq : 1; // VPCLMULQDQ instruction
    uint32_t ft_avx512_vnn : 1; // AVX VNN instructions (Intel) (AMD: Reserved)
    uint32_t ft_avx512_bitalg : 1; // AVX BITALG (bit algorithm) instructions (Intel) (AMD: Reserved)
    uint32_t ft_tme_en : 1; // Memory encryption, IA32_TME_CAPABILITY MSR etc. (Intel) (AMD: Reserved)
    uint32_t ft_avx512_vpopcntdq : 1; // AVX VPOPCNTDQ instruction (Intel) (AMD: Reserved)
    uint32_t reserved1 : 1;
    uint32_t ft_la57 : 1; // Support for LA57 (57-bit linear addressing, 5-level page tables)
    uint32_t val_mawau : 5; // Value used by BNDLDX/BNDSTX instructions (Intel MPX; defunct)
                            // (AMD: Reserved)
    uint32_t ft_rdpid : 1; // RDPID and IA32_TSC_AUX MSR available (Intel) (AMD: Reserved)
    uint32_t ft_kl : 1; // Key Locker support (Intel) (AMD: Reserved)
    uint32_t ft_buslocktrap : 1; // Report bus locks via #DB exception (AMD) (Intel: Reserved)
    uint32_t ft_cldemote : 1; // CLDEMOTE instruction, cache-line demote (Intel) (AMD: Reserved)
    uint32_t reserved3 : 1;
    uint32_t ft_movdiri : 1; // MOVDIRI instruction (Intel) (AMD: Reserved)
    uint32_t ft_movdir64b : 1; // MOVDIR64B instruction (Intel) (AMD: Reserved)
    uint32_t reserved4 : 1;
    uint32_t ft_sgx_lc : 1; // Support for SGX Launch Configuration (Intel) (AMD: Reserved)
    uint32_t ft_pks : 1; // Protection keys for supervisor pages (Intel) (AMD: Reserved)
};

struct cpuid_80000001_ecx {
    // Notables: none are terribly important; most are AMD-only.
    uint32_t ft_lahfsahf64 : 1; // LAHF/SAHF instructions available in 64-bit mode (part of x86-64-v2)
    uint32_t ft_cmplegacy : 1; // "Core multi-processing legacy mode" (Intel: reserved)
    uint32_t ft_svm : 1; // Secure Virtual Machine (Intel: reserved)
    uint32_t ft_extapicspc : 1; // "Extended APIC space" (Intel: reserved)
    uint32_t ft_altmovcr8 : 1; // LOCK MOV CR0 means MOV CR8 (i.e. allow CR8 access in non-64-bit mode)
                               // (Intel: reserved)
    uint32_t ft_lzcnt : 1; // LZCNT supported ("ABM"; x86-64-v3)
    uint32_t ft_sse4a : 1; // SSE4a (Intel: reserved)
    uint32_t ft_masse : 1; // misaligned SSE support (Intel: reserved)
    uint32_t ft_prefetchw : 1; // PREFETCH (AMD), PREFETCHW (AMD+Intel)
    uint32_t ft_osvw : 1; // "OS-Visible Workaround" (Intel: reserved)
    uint32_t ft_ibs : 1; // IBS, Instruction-based sampling (Intel: reserved)
    uint32_t ft_xop : 1; // XOP (AMD XOP instruction support, mostly deprecated) (Intel: reserved)
    uint32_t ft_skinit : 1; // SKINIT and STGI supported (virtualisation) (Intel: reserved)
    uint32_t ft_watchdog : 1; // Watchdog timer support, inc. supprot for MSRC001_0074 (Intel: reserved)
    uint32_t reserved1 : 1;
    uint32_t ft_lwp : 1; // Lightweight profiling support (Intel: reserved)
    uint32_t ft_fma4 : 1; // four-operand FMA instruction support (Intel: reserved)
    uint32_t ft_tce : 1; // Translation Cache Extension (Intel: reserved)
    uint32_t reserved2 : 3;
    uint32_t ft_tbm : 1; // Trailing-bit manipulation instructions (dropped since Zen) (Intel: reserved)
    uint32_t ft_topex : 1; // Topology extensions support (Intel: reserved)
    uint32_t ft_perfctrext : 1; // Performance counter extensions (Intel: reserved)
    uint32_t ft_perfctrextnb : 1; // NB Performance counter extensions (Intel: reserved)
    uint32_t reserved3 : 1;
    uint32_t ft_dab : 1; // Data-access breakpoint support (Intel: reserved)
    uint32_t ft_perftsc : 1; // Performance time-stamp counter, MSRC001_0280 (Intel: reserved)
    uint32_t ft_perfctrextllc : 1; // L3 performance counter extension (Intel: reserved)
    uint32_t ft_monitorx : 1; // support for MWAITX and MONIOTORX (Intel: reserved)
    uint32_t ft_bam31 : 1; // Breakpoint Addressing masking extended to bit 31 (Intel: reserved)
    uint32_t reserved4 : 1;
};

struct cpuid_80000001_edx {
    // This leaf should always be available on 64-bit processors (since it contains the bit which
    // indicates support for 64-bit operation, defined as ft_amd64 below).
    // AMD documents many of these bits as idential to for cpuid_01_edx, whereas Intel classes them as
    // "reserved" (though presumably matches AMD in current processors).
    // Some important features described include ft_nx, ft_1gbpages
    uint32_t reserved1 : 11;  // Note: AMD documents these as corresponding to same bits in cpuid_01_edx
    uint32_t ft_syscallret : 1; // SYSCALL/SYSRET. On intel, only reads true in 64-bit mode.
                                // Unofficially: always available on 64-bit processors.
    uint32_t reserved2: 8;    // Note: AMD documents bits 12-17 as corresponding to cpuid_01_edx[12:17]
    uint32_t ft_nx : 1; // XD Execute Disable / NX No-execute support
    uint32_t reserved3: 1;
    uint32_t ft_mmxext : 1; // AMD extensions to MMX (Intel: reserved)
    uint32_t ft_mmx : 1; // as per cpuid_01_edx.ft_mmx (Intel: reserved)
    uint32_t ft_fxsr : 1; // as per cpuid_01_edx.ft_fxsr (Intel: reserved)
    uint32_t ft_ffxsr : 1; // FXSAVE/FXRSTOR optimisations (Intel: reserved)
                           // Indicates support for FFXSR to be enabled via IA32_EFER
    uint32_t ft_1gbpages : 1; // 1 GB pages
    uint32_t ft_rdtscp : 1; // RDTSCP and IA32_TSC_AUX MSR
    uint32_t reserved4: 1;
    uint32_t ft_amd64: 1; // 64-bit mode (incl. long mode) support
    uint32_t ft_3dnowext : 1; // 3DNow! (TM) instruction extensions (Intel: reserved)
    uint32_t ft_3dnow : 1; // 3DNow! (TM) instructions (support droppsed since 2010) (Intel: reserved)
};

// CPUID instructions. These are templated to be be able to take arbitrary argument types;
// the arguments must be the correct size.

template <typename T_EAX, typename T_EBX, typename T_ECX, typename T_EDX>
[[gnu::always_inline]]
inline void cpuid(uint32_t leaf, T_EAX &eax_r, T_EBX &ebx_r, T_ECX &ecx_r, T_EDX &edx_r) {
    asm (
        "cpuid"
        : "=a"(eax_r), "=b"(ebx_r), "=c"(ecx_r), "=d"(edx_r)
        : "a"(leaf)
    );
}

template <typename T_EAX, typename T_EBX, typename T_ECX, typename T_EDX>
[[gnu::always_inline]]
inline void cpuid(uint32_t leaf, uint32_t subleaf, T_EAX &eax_r, T_EBX &ebx_r, T_ECX &ecx_r, T_EDX &edx_r) {
    asm (
        "cpuid"
        : "=a"(eax_r), "=b"(ebx_r), "=c"(ecx_r), "=d"(edx_r)
        : "a"(leaf), "c"(subleaf)
    );
}

// Read and write MSR values.

[[gnu::always_inline]]
inline void write_msr(uint32_t msr_id, uint32_t val_high, uint32_t val_low) {
    asm volatile (
        "wrmsr"
            :
            : "c"(msr_id), "a"(val_low), "d"(val_high)
    );
}

[[gnu::always_inline]]
inline void read_msr(uint32_t msr_id, uint32_t &val_high, uint32_t &val_low) {
    asm volatile (
        "rdmsr"
            : "=a"(val_low), "=d"(val_high)
            : "c"(msr_id)
    );
}

// Read and write CR0, CR2, CR3, CR4, and CR8 control registers.
// Note that CR1 is reserved and cannot be read/written; CR5, CR6, and CR7 don't exist.
// CR0 is 32 bits in width; others are 64 bits.

// CR0 - primary control register. Reserved bits should not be modified, i.e. the process
// to alter should be to read the current value, set/clear desired bits, and write.
// Long mode requires that f_pe and f_pg are set.
struct control_reg_cr0 {
    uint32_t en_pe : 1; // protection enable
    uint32_t en_mp : 1; // monitor coprocessor
    uint32_t en_em : 1; // emulation of coprocessor
    uint32_t fl_ts : 1; // task switched
    uint32_t fl_et : 1; // extension type (read-only and forced to 1 by modern processors)
    uint32_t en_ne : 1; // numeric error (when clear, signal FP errors via interrupt routed externally;
                       // should be set for modern OSes which support multiple cores)
    uint32_t reserved1 : 10;
    uint32_t en_wp : 1; // write-protect; prevent supervisor writes to read-only pages
    uint32_t reserved2 : 1;
    uint32_t en_am : 1; // alignment mask; when set enables AC flag (EFLAGS) to control alignment
                       // checking in CPL 3.
    uint32_t reserved3 : 10;
    uint32_t en_nw : 1; // not write-through
    uint32_t en_cd : 1; // cache disable
    uint32_t en_pg : 1; // paging enable
};

[[gnu::always_inline]]
inline uint32_t read_cr0_num() {
    uint64_t r;
    asm (
        "movq %%cr0, %0"
        : "=r"(r)
    );
    return (uint32_t)r;
}

[[gnu::always_inline]]
inline control_reg_cr0 read_cr0() {
    struct {
        control_reg_cr0 reg_low;
        uint32_t reg_high;
    } r;
    asm (
        "movq %%cr0, %0"
        : "=r"(r)
    );
    return r.reg_low;
}

[[gnu::always_inline]]
inline void write_cr0(uint32_t value) {
    asm volatile (
        "movq %0, %%cr0"
        :
        : "r"((uint64_t)value)
    );
}

[[gnu::always_inline]]
inline void write_cr0(control_reg_cr0 value) {
    struct {
        control_reg_cr0 reg;
        uint32_t high;
    } v;
    v.reg = value;
    v.high = 0;
    asm volatile (
        "movq %0, %%cr0"
        :
        : "r"(v)
    );
}

// The CR2 register contains the page fault linear address on a page fault (#PF) exception.

[[gnu::always_inline]]
inline uint64_t read_cr2() {
    uint64_t r;
    asm (
        "movq %%cr3, %0"
        : "=r"(r)
    );
    return r;
}

[[gnu::always_inline]]
inline void write_cr2(uint64_t value) {
    asm volatile (
        "movq %0, %%cr3"
        :
        : "r"(value)
    );
}

// The CR3 register specifies the page directory pointer table / PML4 / PML5, i.e. the top-level
// directory in the page tables, and some control bits to control caching of the page table
// structure (which should generally be left as 0, i.e. enable full write-back caching). If PCIDs
// are enabled it contains the current PCID in the lower bits (instead of caching control).

[[gnu::always_inline]]
inline uint64_t read_cr3() {
    uint64_t r;
    asm (
        "movq %%cr3, %0"
        : "=r"(r)
    );
    return r;
}

[[gnu::always_inline]]
inline void write_cr3(uint64_t value) {
    asm volatile (
        "movq %0, %%cr3"
        :
        : "r"(value)
    );
}

// CR4: used to enable various optional features. In most cases the feature availability is indicated
// by a CPUID-returned flag.

struct control_reg_cr4 {
    uint32_t en_vme : 1; // virtual-8086 mode extensions
    uint32_t en_pvi : 1; // protected-mode virtual interrupts
    uint32_t en_tsd : 1; // timestamp disable; if set restrict RDTSC[P] to privilege level 0
    uint32_t en_de : 1; // debugging extensions
    uint32_t en_pse : 1; // page-size extensions, enables 4MB pages in protected mode, N/A in long mode
    uint32_t en_pae : 1; // physical address extensions (4-level page tables); required in long mode
    uint32_t en_mce : 1; // machine-check enable
    uint32_t en_pge : 1; // page global enable (paging should be enabled before PGE is set acc. to Intel)
    uint32_t en_pce : 1; // performance monitoring counter enable (if set allows RDPCM at any privilege)
    uint32_t en_osfxsr : 1; // OS supports FXAVE/FXRSTOR, enables SSE/SSEx
    uint32_t en_osxmmexcpt : 1; // OS unmasked exception support (generate #XM vs #UD on SSE fp exception)
    uint32_t en_umip : 1; // User mode instruction prevention, prevent certain instructions in CPL>9
    uint32_t en_la57 : 1; // 57-bit linear addressing, 5 level page tables. Cannot be modified in 64-bit
                          // mode
    uint32_t en_vmx : 1; // VMX-enable (Intel) (AMD: reserved)
    uint32_t en_smx : 1; // SMX-enable (Intel) (AMD: reserved)
    uint32_t reserved1 : 1;
    uint32_t en_fsgsbase : 1; // Enable {RD,WR}{FS,GS}BASE instructions
    uint32_t en_pcid : 1; // Enable process-context identifiers
    uint32_t en_osxsave : 1; // XSAVE and extended states, required for AVX
    uint32_t en_kl : 1; // Key-Locker (Intel) (AMD: reserved)
    uint32_t en_smep : 1; // SMEP, prevent supervisor execution of code in user pages
    uint32_t en_smap : 1; // SMAP, prevent (some) supervisor access to code in user pages
    uint32_t en_pke : 1; // Protection keys for user pages
    uint32_t en_cet : 1; // Control-flow enforcement
    uint32_t reserved2 : 1;
    uint32_t en_pks : 1; // Protection keys for supervisor pages (AMD: reserved)
    uint32_t reserved3 : 6;
};

[[gnu::always_inline]]
inline uint64_t read_cr4_num() {
    uint64_t r;
    asm (
        "movq %%cr4, %0"
        : "=r"(r)
    );
    return r;
}

[[gnu::always_inline]]
inline control_reg_cr4 read_cr4() {
    struct {
        control_reg_cr4 reg_low;
        uint32_t reg_high;
    } r;
    asm (
        "movq %%cr4, %0"
        : "=r"(r)
    );
    return r.reg_low;
}

[[gnu::always_inline]]
inline void write_cr4(control_reg_cr4 value) {
    struct {
        control_reg_cr4 reg;
        uint32_t high;
    } v;
    v.reg = value;
    v.high = 0;
    asm volatile (
        "movq %0, %%cr4"
        :
        : "r"(v)
    );
}

[[gnu::always_inline]]
inline void write_cr4(uint64_t value) {
    asm volatile (
        "movq %0, %%cr4"
        :
        : "r"(value)
    );
}

[[gnu::always_inline]]
inline uint64_t read_cr8() {
    uint64_t r;
    asm (
        "movq %%cr8, %0"
        : "=r"(r)
    );
    return r;
}

[[gnu::always_inline]]
inline void write_cr8(uint64_t value) {
    asm volatile (
        "movq %0, %%cr8"
        :
        : "r"(value)
    );
}

#endif
