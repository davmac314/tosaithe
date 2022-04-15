# Tosaithe

**This is a work-in-progress!**
(it somewhat works, but is not complete).

Tosaithe is a minimalistic UEFI-firmware menu/bootloader. It can chain-load other EFI programs
and loaders, including Linux kernels, and has basic support for a bespoke boot protocol (the
"Tosaithe boot protocol" or "TSBP"). It is currently x86-64 only.

This is free software, with as few restrictions as legally possible. It comes with no warranty
and will not be supported by the original author. Use it at your own risk.

I began writing Tosaithe when I was experimenting with writing a "toy" OS kernel. Not being
satisfied with other alternatives, for various reasons, I decided (in the true spirit of OS
development) to write one myself. I had originally toyed with the Stivale2 protocol, but would
prefer something lighter-weight. Stivale2 seems like a good protocol for getting kernels off
the ground quickly, because it can do lot of setup for you; implementing a complete Stivale2
loader on the other hand seems like a major undertaking.

(There is a partial Stivale2 implementation in the source tree but it is no longer included as
part of the build. It worked as proof-of-concept for very particular kernels but is nowhere near
being spec compliant, and I have little personal interest in completing it. If you need a Stivale2
loader, look for "Limine").

Tosaithe mainly serves now as:

* An example UEFI bootloader
* ... written in C++, exceptions and all
* ... that can be built using standard Linux toolchain (GCC and GNU binutils)
* ... that doesn't require EDK II or GNU-EFI

It also serves as an example client of the bmcxxabi, bmunwind, and libbmcxx libraries which
together provide a C++ runtime and standard library.

## The Tosaithe boot protocol (TSBP)

To be written...

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
the program name as first argument. Paths are on the boot partition (or rather, the partition that
Tosaithe itself is run from).

## Using Tosaithe

When Tosaithe runs it reads the configuration file, prints a banner and lists the entries found in
order. The entries are numbered and to select an entry you press the corresponding number on the
keyboard.

This is of course very limited - it only properly supports up to 9 entries.
