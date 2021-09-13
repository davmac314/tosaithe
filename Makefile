TOPDIR ::= $(PWD)

# Short version: EFI requires -mcmodel=large, or -fpie.
# Long version: The default model, small, expects the program to be loaded in the
# lower 2GB of the address space; a real EFI BIOS may not follow this restriction, with some
# *really* weird behaviour as a result.
#   (On a Gigabyte motherboard I have, program always gets loaded just under the 4GB mark; it
# somewhat works with -mcmodel=small, but pointers to constants are - *occasionally* - loaded with
# "movq" instruction which *sign extends* them. I lost hours of my life debugging this).
#   On the other hand, -fpie avoids the issue because loads of addresses will be done PC-relative.
# For x86-64 this gives smaller code (and fewer relocations).

EFICFLAGS ::= -ffreestanding -fbuiltin -fshort-wchar -march=x86-64 -mno-sse -mno-mmx -mno-red-zone -fno-stack-protector -fpie
#gcc docs say ms-abi may require this, but I've not found that to be the case: -maccumulate-outgoing-args
CFLAGS ::= -g -Os -Wall
CXXFLAGS ::= $(CFLAGS) -fno-rtti
CXX=g++
CC=gcc

LIBBMCXX_CPPFLAGS ::= -isysroot $(TOPDIR)/dummy-sysroot
LIBBMCXX_CXXPPFLAGS ::= -isysroot $(TOPDIR)/dummy-sysroot -nostdinc++
CPPFLAGS ::= -isysroot $(TOPDIR)/dummy-sysroot -isystem "$(TOPDIR)/libbmcxx/include"
CXXPPFLAGS ::= -isysroot $(TOPDIR)/dummy-sysroot -nostdinc++ -isystem /home/davmac/prog/libbmcxx/include -I $(TOPDIR)/include

export EFICFLAGS CXXFLAGS CXXPPFLAGS CXX

all:
	$(MAKE) -C src all

lib/libcxxabi.a:
	$(MAKE) -C bmcxxabi CXXPPFLAGS="$(CXXPPFLAGS)" CXXFLAGS="$(CXXFLAGS) $(EFICFLAGS)" CXX="$(CXX)" OUTDIR="$(TOPDIR)/lib" 

lib/libunwind.a:
	$(MAKE) -C bmunwind CC="$(CC)" CXX="$(CXX)" CFLAGS="$(CFLAGS) $(EFICFLAGS)" CXXFLAGS="$(CXXFLAGS) $(EFICFLAGS)" \
	  CPPFLAGS="$(CPPFLAGS)" CXXPPFLAGS="$(CXXPPFLAGS)" OUTDIR="$(TOPDIR)/lib"

lib/libbmcxx.a:
	$(MAKE) -C libbmcxx CC="$(CC)" CXX="$(CXX)" CFLAGS="$(CFLAGS) $(EFICFLAGS)" CXXFLAGS="$(CXXFLAGS) $(EFICFLAGS)" \
	  CPPFLAGS="$(LIBBMCXX_CPPFLAGS)" CXXPPFLAGS="$(LIBBMCXX_CXXPPFLAGS)" OUTDIR="$(TOPDIR)/lib"

run-in-qemu:
	cd src; $(MAKE) run-in-qemu

clean:
	$(MAKE) -C src clean
