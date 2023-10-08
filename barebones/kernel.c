#include <tosaithe-proto.h>

struct opaque;

extern struct opaque KERNEL_STACK_TOP;  // defined in linker script

tosaithe_entry_header ts_entry_hdr __attribute__((section(".tsbp_hdr"), used)) = {
        'T' + ('S' << 8) + ('B' << 16) + ('P' << 24),
        0, // version
        0, // min required loader version
        (uintptr_t)&KERNEL_STACK_TOP,
        1  // flags - require framebuffer
};

void tsbp_entry(tosaithe_loader_data *tosaithe_data)
{
    // Draw a test pattern, if we have a 32bpp framebuffer
    if (tosaithe_data->framebuffer_addr != 0 && tosaithe_data->framebuffer_bpp == 32) {
        // We'll assume the framebuffer is appropriately aligned
        uint32_t *f = (uint32_t *)tosaithe_data->framebuffer_addr;

        // How much to increment a pointer to advance to the first pixel of the next row?
        // This is the pitch minus the bytes making up the row:
        uint32_t post_row_incr = (tosaithe_data->framebuffer_pitch - (tosaithe_data->framebuffer_width * 4)) / 4;

        // Display red-green-blue test pattern
        unsigned r_height = tosaithe_data->framebuffer_height / 3;
        unsigned g_height = r_height * 2;
        unsigned b_height = tosaithe_data->framebuffer_height;

        unsigned y;
        for (y = 0; y < r_height; y++) {
            for (unsigned x = 0; x < tosaithe_data->framebuffer_width; x++) {
                uint32_t pixel = (uint32_t)-1;
                pixel >>= (32 - tosaithe_data->red_mask_size);
                pixel <<= tosaithe_data->red_mask_shift;
                *f = pixel;
                f++;
            }
            f += post_row_incr;
        }

        for ( ; y < g_height; y++) {
            for (unsigned x = 0; x < tosaithe_data->framebuffer_width; x++) {
                uint32_t pixel = (uint32_t)-1;
                pixel >>= (32 - tosaithe_data->green_mask_size);
                pixel <<= tosaithe_data->green_mask_shift;
                *f = pixel;
                f++;
            }
            f += post_row_incr;
        }

        for ( ; y < b_height; y++) {
            for (unsigned x = 0; x < tosaithe_data->framebuffer_width; x++) {
                uint32_t pixel = (uint32_t)-1;
                pixel >>= (32 - tosaithe_data->blue_mask_size);
                pixel <<= tosaithe_data->blue_mask_shift;
                *f = pixel;
                f++;
            }
            f += post_row_incr;
        }
    }

    // interrupts are still disabled...
    while (1) {
        asm volatile ( "hlt\n" );
    }
}
