# Tosaithe

Tosaithe is a minimalistic UEFI-firmware menu/bootloader. It can chain-load other EFI programs
and loaders, including Linux kernels, and has basic support for the Stivale2 boot protocol. It is
currently x86-64 only.

This is free software, with as few restrictions as legally possible. It comes with no warranty
and will not be supported by the original author. Use it at your own risk.

I began writing Tosaithe when I was experimenting with writing a "toy" OS kernel. Using Stivale2,
via its flagship Limine bootloader, allowed me to get off the ground quickly. However, Limine did
not (at the time) work properly on my desktop machine and had design flaws that bothered me
greatly (eg it wrote to disks at boot time when trying to identify boot partition), which have
been fixed now as far as I know. There's little reason to use Tosaithe in preference to Limine now.

Tosaithe mainly serves now as:

* An example UEFI bootloader
* ... written in C++, exceptions and all
* ... that can be built using standard Linux toolchain (GCC and GNU binutils)
* ... that doesn't require EDK II or GNU-EFI

It also serves as an example client of the bmcxxabi, bmunwind, and libbmcxx libraries which
together provide a C++ runtime and standard library.

## Limitations of Stivale2 implementation

For Stivale2, only 64-bit ELF kernels are supported, and most optional features are not implemented
(no terminal is provided, no PMRs, only 4-level page tables are supported). High-half kernels are
supported but pointers in the information tags given to the kernel will not be adjusted to the high
half. 

Position independence is not supported (the kernel will be loaded at its nominal address).

The Stivale2 requirement that PIC and APIC IRQs are disabled is not currently implemented. The
kernel should ensure IRQs are masked itself before enabling interrupts.

No text mode is available in UEFI. The kernel will be booted regardless of whether it supports
support from framebuffer. A framebuffer tag will be provided to the kernel if possible.

## Building Tosaithe

Requires GCC and Binutils (may or may not work with Clang/LLVM/LLD). I have built with GCC 9.4.0
and Binutils 2.37. I recommend not trying to use older Binutils as there have been bugs with the
PE+ output format support. Binutils must have been built with appropriate support (this is usually
the case with distro-provided Binutils, use `--enable-targets=x86_64-none-pe,x86_64-none-pep` when
configuring if building it yourself).

1. `sh clone-libs.sh` to clone the dependencies
2. `sh rebuild-libs.sh` to build the dependencies (in-tree)
3. `make` to build Tosaithe.

## Installing Tosaithe

Copy `tosaithe.efi` to your EFI system partition. You can copy it over `\EFI\BOOT\bootx64.efi` in
order to boot with it, but I highly recommend you don't do that until you're sure that it works; copy
it somewhere else and run it via Grub or the UEFI shell for example. (Check your motherboard manual
for access to see if UEFI shell access is possible; check web for help using it). 

You will need a `tosaithe.conf` text file (UTF-8) in the root directory of the same partition. This
should look something like:

```
entry: {
    description = 'Linux - 5.10.47'
    type = chain
    exec = '\vmlinuz-5.10.47'
    cmdline = 'linux root=/dev/sda1'
}

entry: {
    description = 'EFI Shell'
    type = chain
    exec = '\EFI\Shell.efi'
    cmdline = 'Shell.efi'
}

entry: {
    description = 'My Stivale2 Kernel'
    type = stivale2
    exec = '\mykernel.elf'
    cmdline = ''
}
```

Note that when chaining to an EFI program (when `type = chain`) the command line should include
the program name as first argument. Paths are on the boot partition (or rather the partition that
Tosaithe itself is run from).

## Using Tosaithe

When Tosaithe runs it reads the configuration file, prints a banner and lists the entries found in
order. The entries are numbered and to select an entry you press the corresponding number on the
keyboard.

This is of course very limited - it only properly supports up to 9 entries.
