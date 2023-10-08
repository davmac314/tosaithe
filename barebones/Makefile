CC = gcc -march=x86-64 -mno-red-zone -mgeneral-regs-only -fno-pie -fno-stack-protector -ffreestanding
CPPFLAGS = -I../include

all: kernel.elf

KERNEL_OBJECTS=kernel.o

kernel.elf: $(KERNEL_OBJECTS) link-script.lds
	$(LD) -Map kernel.elf.map -e tsbp_entry -T link-script.lds -o kernel.elf \
	    $(KERNEL_OBJECTS)

run: kernel.elf
	if [ ! -e OVMF_CODE-pure-efi.fd ]; then \
	    echo "You must copy OVMF files here, see README"; \
	    exit 1; \
	fi
	cp kernel.elf bootdisk
	qemu-system-x86_64 \
	  -drive if=pflash,format=raw,unit=0,file=OVMF_CODE-pure-efi.fd,readonly=on \
          -drive if=pflash,format=raw,unit=1,file=OVMF_VARS-pure-efi.fd \
          -net none  \
          -drive file=fat:rw:bootdisk,media=disk,format=raw

$(KERNEL_OBJECTS): %.o: %.c
	$(CC) $(CPPFLAGS) $(CCFLAGS) -c $< -o $@

$(KERNEL_OBJECTS:.o=.d): %.d: %.c
	$(CC) $(CPPFLAGS) -MM -MP -MG -MF $@ $<

clean:
	rm -rf kernel.elf $(KERNEL_OBJECTS) *.d

include $(KERNEL_OBJECTS:.o=.d)
