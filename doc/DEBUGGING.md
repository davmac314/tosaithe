# Debugging Tosaithe

Debugging a UEFI application is tricky. I haven't worked out how to attach debugging information
to a PE file (EFI executable) so that (a) it will still execute and (b) GDB will read the debug
info, but also, the firmware will load the PE image at an arbitrary address.
 
Here's how I do it with Tosaithe, assuming it starts and gets as far as showing the initial banner:

1. Uncomment the lines in EfiMain which find and print the "Loaded image base". Re-build.
3. Run Tosaithe in Qemu, with "-s" passed to Qemu (so that you can connect via GDB).
   Watch for the "Loaded image base = " line giving the run-time address of the image.
   Add the offset of the .text section in order to find the address of the .text section.
4. Run GDB (without arguments) in the directory containing "tosaithe.efi.so". This is an ELF
   version of the Tosaithe binary, which should be content-wise identical with the "tosaithe.efi"
   binary. The ELF version however includes debugging symbols.

        (gdb) target remote :1234
      
        (gdb) add-symbol-file tosaithe.efi.so -o 0xABCD1234
   
   where `0xABCD1234` is the "Loaded image base" address printed by Tosaithe.
   
You now should be able to use GDB as normal.

If Tosaithe doesn't get as far as printing the "Loaded image base" things will be more difficult,
but you can guess the loaded image base by looking at the current `%rip` value (if you can guess
what function it's currently in, you can look up that function in the link map generated in
tosaithe.efi.so.map).

If you need to set a "break point" at a particular place that gets hit *before* you can connect
with GDB, use code like the following:

    volatile bool do_halt = true;
    while (do_halt) {
        asm volatile ("pause");
    }

Once you've connected with GDB, you can "set do_halt = false" and then step to your heart's
content.
