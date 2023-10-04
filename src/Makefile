EFICFLAGS ?= -ffreestanding -fshort-wchar -maccumulate-outgoing-args -march=x86-64 -mno-sse -mno-mmx -mno-red-zone -fno-stack-protector
# -mabi=ms
CXXFLAGS ?= -g -Os -Wall -fno-rtti

# (Not needed if using primary link method below)
#ELF2EFI64=elf2efi64

all: tosaithe.efi

# We have to link twice: the first time as ELF, to produce the .eh_frame_hdr section (--eh-frame-hdr).
# The second time to convert to PEI.
tosaithe.efi: main.o tosaithe-proto.o tosaithe-util.o cxxsupport.o
	ld -q -nostdlib -Bsymbolic -T link-elf.lds \
	  main.o tosaithe-proto.o tosaithe-util.o cxxsupport.o \
	  --eh-frame-hdr \
	  -L ../lib -lunwind -lcxxabi -lbmcxx \
	  -Map=tosaithe.efi.so.map -o tosaithe.efi.so
	ld --strip-all -nostdlib -Bsymbolic \
	  tosaithe.efi.so \
	  -T link-elf-efi.lds -Map=tosaithe.efi.map \
	  -o tosaithe.efi --oformat pei-x86-64 \
	  -m i386pep --subsystem 10 --image-base 0 \
	  --enable-reloc-section

# Alternative linking method: works with lld (ld.lld), but requires elf2efi
#tosaithe.efi: main.o tosaithe-proto.o cxxsupport.o
#	ld -Map tosaithe.efi.so.map -q -Bsymbolic -Bsymbolic-functions -T link-elf.lds \
#	  -o tosaithe.efi.so \
#	  main.o tosaithe-proto.o cxxsupport.o \
#	  --eh-frame-hdr \
#	  -L ../lib -lunwind -lcxxabi -lbmcxx \
#	  -Map=tosaithe.efi.so.map -o tosaithe.efi.so
#	strip --strip-debug -o tosaithe-stripped.efi.so tosaithe.efi.so
#	$(ELF2EFI64) --subsystem=10 tosaithe-stripped.efi.so tosaithe.efi

main.o: main.cc
	$(CXX) $(CXXPPFLAGS) $(EFICFLAGS) $(CXXFLAGS) -c main.cc

tosaithe-proto.o: tosaithe-proto.cc
	$(CXX) $(CXXPPFLAGS) $(EFICFLAGS) $(CXXFLAGS) -c tosaithe-proto.cc

tosaithe-util.o: tosaithe-util.cc
	$(CXX) $(CXXPPFLAGS) $(EFICFLAGS) $(CXXFLAGS) -c tosaithe-util.cc

cxxsupport.o: cxxsupport.cc
	$(CXX) $(CXXPPFLAGS) $(EFICFLAGS) $(CXXFLAGS) -c cxxsupport.cc

# Everything below here is concerned with building disk images and running in QEMU

disk.img: tosaithe.efi
	rm -f disk.img
	@echo "==="
	@echo "Please create disk image (disk.img). On linux use 'make disk.img-linux'"
	@echo "==="
	@exit 1

# Create "image", a directory used to create a virtual FAT image
image-dir: tosaithe.efi
	mkdir -p image
	cp tosaithe.efi image
	cp ../doc/tosaithe.conf.example image/tosaithe.conf

# Create a disk image with the tosaithe.efi executable on it (Linux).
# requires mtools and dosfstools. This is an example as alternative to the above
# if you want a "real" disk image.
disk.img-linux: tosaithe.efi
	dd if=/dev/zero of=disk.img bs=512 count=93750 # 48Mb
	/sbin/sfdisk disk.img < sfdisk.input # create partition table ("label") and EFI system partition
	# start=2048 end=93716 sectors=91669
	/usr/sbin/mkfs.fat -F 32 --offset=2048 -S 512 disk.img $$((91669 * 512 / 1024))
	mmd -i disk.img@@1M ::/EFI
	mmd -i disk.img@@1M ::/EFI/BOOT	
	mcopy -i disk.img@@1M tosaithe.efi ::/EFI/BOOT/bootx64.efi
	mcopy -i disk.img@@1M ../doc/tosaithe.conf.example ::/tosaithe.conf

run-in-qemu: image-dir
	@if [ ! -e OVMF_CODE-pure-efi.fd -o ! -e OVMF_VARS-pure-efi.fd ]; then \
	    echo "!!! OVMF firmware images are missing; please download them to this directory."; \
	    exit 1; \
	fi
	qemu-system-x86_64 -s \
	  -drive if=pflash,format=raw,unit=0,file=OVMF_CODE-pure-efi.fd,readonly=on \
	  -drive if=pflash,format=raw,unit=1,file=OVMF_VARS-pure-efi.fd \
	  -net none  \
	  -drive file=fat:rw:image,media=disk,format=raw \
	  -debugcon file:ovmf-debug.log -global isa-debugcon.iobase=0x402

run-disk-img-qemu: disk.img
	@if [ ! -e OVMF_CODE-pure-efi.fd -o ! -e OVMF_VARS-pure-efi.fd ]; then \
	    echo "!!! OVMF firmware images are missing; please download them to this directory."; \
	    exit 1; \
	fi
	qemu-system-x86_64 -s \
	  -drive if=pflash,format=raw,unit=0,file=OVMF_CODE-pure-efi.fd,readonly=on \
	  -drive if=pflash,format=raw,unit=1,file=OVMF_VARS-pure-efi.fd \
	  -net none  \
	  -drive file=disk.img \
	  -debugcon file:ovmf-debug.log -global isa-debugcon.iobase=0x402
	
clean:
	rm -f main.o tosaithe-proto.o tosaithe.efi.so tosaithe.efi disk.img
	rm -rf image
