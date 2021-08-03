ELF2EFI64=elf2efi64

EFICFLAGS=-ffreestanding -fshort-wchar -mabi=ms -maccumulate-outgoing-args -march=x86-64 -mno-sse -mno-mmx -mno-red-zone -fno-stack-protector
CCFLAGS=-Os -Wall -fno-rtti -fno-exceptions

#tosaithe.efi: main.o
#	ld -Map tosaithe.efi.so.map -q -Bsymbolic -Bsymbolic-functions -T link-elf-efi.lds \
#	  -o tosaithe.efi.so \
#	  main.o
#	strip --strip-debug -o tosaithe-stripped.efi.so tosaithe.efi.so
#	$(ELF2EFI64) --subsystem=10 tosaithe-stripped.efi.so tosaithe.efi

tosaithe.efi: main.o
	ld --strip-debug -nostdlib -Bsymbolic \
	  main.o \
	  -T link-elf-efi.lds -Map=tosaithe.efi.map \
	  -o tosaithe.efi --oformat pei-x86-64 \
	  -m i386pep --subsystem 10 --image-base 0 \
	  --enable-reloc-section

main.o: main.cc
	g++ -g -Os $(EFICFLAGS) $(CCFLAGS) -c main.cc

# Everything below here is concerned with building disk images and running in QEMU

disk.img: tosaithe.efi
	rm disk.img
	echo "Please create disk image (disk.img). On linux use 'make disk.img-linux'"
	exit 1

# Create "image", a directory used to create a virtual FAT image
image-dir: tosaithe.efi
	mkdir -p image
	cp tosaithe.efi image

# Create a disk image with the tosaithe.efi executable on it (Linux).
# requires mtools and dosfstools. This is an example as alternative to the above
# if you want a "real" disk image.
disk.img-linux: tosaithe.efi
	dd if=/dev/zero of=disk.img bs=512 count=93750 # 48Mb
	/sbin/sfdisk disk.img < sfdisk.input # create partition table ("label") and EFI system partition
	# start=2048 end=93716 sectors=91669
	/usr/sbin/mkfs.fat -F 32 --offset=2048 -S 512 disk.img $$((91669 * 512 / 1024))
	mcopy -i disk.img@@1M tosaithe.efi ::/

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

clean:
	rm -f main.o tosaithe.efi.so tosaithe.efi disk.img
	rm -rf image
