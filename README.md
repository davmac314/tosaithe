# Tosaithe

_Preliminary - no official release yet_

Tosaithe is a minimalistic UEFI-firmware menu/bootloader. It can chain-load other EFI programs
and loaders, including Linux kernels, and has basic support for a bespoke boot protocol and
kernel image format (the "Tosaithe boot protocol" or "TSBP"). It is currently x86-64 only.

This is free software, with as few restrictions as legally possible. It comes with no warranty
and will not be supported by the original author. Use it at your own risk.

I began writing Tosaithe when I was experimenting with writing a "toy" OS kernel. Not being
satisfied with other alternatives, for various reasons, I decided (in the true spirit of OS
development) to write one myself. Other bootloaders available at the time did not fit my
requirements. 

Tosaithe mainly serves now as the reference implementation for the Tosaithe Boot Protocol (TSBP).

It is also:

* An example UEFI bootloader / boot menu
* ... written in C++, exceptions and all
* ... that can be built using standard Linux toolchain (GCC and GNU binutils)
* ... that doesn't require EDK II or GNU-EFI

It also serves as an example client of the bmcxxabi, bmunwind, and libbmcxx libraries which
together provide a C++ runtime and standard library.

## The Tosaithe boot protocol (TSBP)

There is a [specification document](doc/TSBP.md) for the protocol in this repository.

A "Bare Bones" [example](barebones/) is also included.

Key features:

* Uses ELF format kernels, easily constructed with commonly available toolchains
* Kernels are loaded and mapped into the "high half" (or "negative") address space by the loader
* Memory map, firmware information, and framebuffer details are passed to the kernel
* Supports passing kernel command line and initial ramdisk image

## Building Tosaithe

Requires GCC and Binutils (builds with Clang, but requires GNU Binutilfs "BFD" linker). I have
built with GCC 11.4.0 and Binutils 2.39. I recommend not trying to use older Binutils as there
have been bugs with the PE+ output format support. Binutils must have been built with appropriate
support (this is usually the case with distro-provided Binutils, use
`--enable-targets=x86_64-none-pe,x86_64-none-pep` when configuring if building it yourself).

1. `sh clone-libs.sh` or `sh clone-libs.sh https` to clone the dependencies. Use the latter to
    clone via https, which avoids needing to have your ssh public key enrolled with Github.
2. `sh rebuild-libs.sh` to build the dependencies (in-tree)
3. `make` to build Tosaithe.

## Installing Tosaithe

Copy `tosaithe.efi` to your EFI system partition. You can copy it over `\EFI\BOOT\bootx64.efi` in
order to boot with it (maybe), but I highly recommend you don't do that until you're sure that it
works; copy it somewhere else and run it via Grub or the UEFI shell for example. Documentation for
these is found elsewhere.

You will need a `tosaithe.conf` text file (UTF-8) in the root directory of the same partition. This
should look something like:

```
entry: {
    description = 'Linux - 5.10.47'
    type = chain
    exec = '\linux-5.10.47'
    cmdline = 'root=/dev/sda1 initrd=initrd.img'
}

entry: {
    description = 'EFI Shell'
    type = chain
    exec = '\EFI\Shell.efi'
    cmdline = 'Shell.efi'
}

entry: {
    description = 'My Tosaithe Kernel'
    type = tosaithe
    exec = '\mykernel.elf'
    cmdline = ''
}
```

Note that when chaining to an EFI program (when `type = chain`) the command line should include
the program name as first argument to emulate the EFI shell, but this is not what all programs
expect (eg Linux kernel doesn't want it). Paths are on the boot partition (or rather, the
partition that Tosaithe itself is run from) or specified as full EFI device paths.

If using a full device path, note the textual form of device paths as documented in the UEFI
specification (at least up until 2.10) is very wrong. Notable deviations by UEFI implementations
(including EDK2) from the spec include:

* Device paths do not begin with a leading slash or backslash, i.e. the first device node in a
  device path is not preceded by a slash, despite that the UEFI spec claim that "each [node is]
  preceded by a [slash]".
* There is a forward-slash between device path nodes in a device path, never a backslash, contrary
  to the spec which claims either slash or backslash character may separate nodes.
* Device paths do not accumulate leading slashes as each node is appended. The grammar in the spec
  is completely wrong; the slash goes between device nodes.
* A file path device node (at the end of the device path) uses backslash as path element separator
  and is preceded by a leading backslash (immediately following the forward slash which separates
  the file path node from the previous node in the path).
  
See for example:
* https://github.com/tianocore/edk2/blob/master/MdePkg/Library/UefiDevicePathLib/DevicePathFromText.c
* https://github.com/tianocore/edk2/blob/master/MdePkg/Library/UefiDevicePathLib/DevicePathToText.c

An example path looks something like:
```
PciRoot(0x0)/Pci(0x3,0x0)/Sata(0x0,0xFFFF,0x0)/HD(1,MBR,0xBE1AFDFA,0x3F,0xFBC1)/\some\file.txt
```
(Yes, UEFI paths are unwieldy!).

## Using Tosaithe

When Tosaithe runs it reads the configuration file, prints a banner and lists the entries found in
order. The entries are numbered and to select an entry you press the corresponding number on the
keyboard.

Use the 'n' and 'p' to navigate to the next and previous page, respectively, if there are more
than 10 entries in the menu. Use 'x' to exit Tosaithe, 's' to shut down the system. Press space
to refresh the display of menu items.

## Alternatives

If you are looking for a boot menu / bootloader / protocol and Tosaithe doesn't cut it for you,
I strongly recommend checking out [Limine](https://github.com/limine-bootloader/limine); see its
protocol specification [here](https://github.com/limine-bootloader/limine/blob/trunk/PROTOCOL.md).
