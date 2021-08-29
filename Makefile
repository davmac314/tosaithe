TOPDIR ::= $(PWD)

EFICFLAGS ::= -ffreestanding -fbuiltin -fshort-wchar -march=x86-64 -mno-sse -mno-mmx -mno-red-zone -fno-stack-protector
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
	$(MAKE) -C bmunwind CC="$(CC)" CXX="$(CXX)" CFLAGS="$(CFLAGS) $(EFICFLAGS)" CXXFLAGS="$(CXXFLAGS EFICFLAGS)" \
	  CPPFLAGS="$(CPPFLAGS)" CXXPPFLAGS="$(CXXPPFLAGS)" OUTDIR="$(TOPDIR)/lib"

lib/libbmcxx.a:
	$(MAKE) -C libbmcxx CC="$(CC)" CXX="$(CXX)" CFLAGS="$(CFLAGS) $(EFICFLAGS)" CXXFLAGS="$(CXXFLAGS EFICFLAGS)" \
	  CPPFLAGS="$(LIBBMCXX_CPPFLAGS)" CXXPPFLAGS="$(LIBBMCXX_CXXPPFLAGS)" OUTDIR="$(TOPDIR)/lib"

run-in-qemu:
	cd src; $(MAKE) run-in-qemu

clean:
	$(MAKE) -C src clean
