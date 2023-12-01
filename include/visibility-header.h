// An EFI program can be loaded anywhere in memory. For x86-64, the normal GCC "mcmodel" of small
// can result in strange misbehaviour if a program is loaded at a high address, because the
// compiler expects symbols to be addressable using 31-bit values (addresses may get sign-extended
// in generated code). However, "-mcmodel=large" generates inefficient code. To combat this we
// stick with the "small" model but compile with "-fpie" to encourage the compiler to use offsets
// from RIP to access symbols.

// However, for external symbols the compiler assumes that it must go through a GOT (Global Offset
// Table). The GOT is an artifact of ELF-style position-independent executables (and shared
// libraries) which makes no sense in the EFI world. It doesn't even make sense for "static PIE"
// ELF executables which is the closest analogue to the PE-based EFI executable we want to
// produce; unfortunately there is no simple command-line argument to avoid GOT references though.
// So, we resort to this header which we magically "-include" before every source file: it will
// set the visibility of all symbols to "hidden" thus preventing GOT-based access.

// Note that "-fvisibility=hidden" is not sufficient - it affects only symbols with definitions.
// We must use the following pragma:

#pragma GCC visibility push(hidden)

// Also disable LIBUNWIND's own visibility annotations which it employs inconsistently, which
// upsets clang:
#define _LIBUNWIND_DISABLE_VISIBILITY_ANNOTATIONS 1
