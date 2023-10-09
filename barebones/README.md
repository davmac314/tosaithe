# TSBP bare bones kernel

This is an example "bare-bones" (i.e. almost absolutely minimal) kernel for use with a loader 
using the Tosaithe Boot Protocol (TSBP). It is intended only as an example of how to get
started.

It is x86-64 only. It should build on any recent Linux system with the system GCC and binutils.

To build:
- run "make"

To run (in qemu):
- build Tosaithe, or copy a pre-built image to `bootdisk/EFI/BOOT/BOOTX64.EFI` (replacing the
  existing symlink)
- first make sure you have the OVMF UEFI firmware files in this directory. You need both
  `OVMF_CODE-pure-efi.fd` and `OVMF_VARS-pure-efi.fd` files. You can get them here:
  https://github.com/davmac314/edk2/releases/tag/r20231001
- run "make run"
