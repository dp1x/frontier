/* libpng harness: decode a PNG and report ACCEPT/REJECT.
 *
 * Build:  cc -O2 -o libpng_decode libpng_decode.c -lpng -lz
 * Run:    ./libpng_decode <file.png> ...
 */
#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>
#include <png.h>

static void on_error(png_structp png_ptr, png_const_charp msg) {
    fprintf(stderr, "libpng: %s\n", msg);
    longjmp(*((jmp_buf *)png_get_error_ptr(png_ptr)), 1);
}

static int decode_one(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) { fprintf(stderr, "%s: cannot open\n", path); return 2; }

    unsigned char sig[8];
    if (fread(sig, 1, 8, fp) != 8 || png_sig_cmp(sig, 0, 8)) {
        fprintf(stderr, "%s: bad signature\n", path);
        fclose(fp);
        return 2;
    }

    png_structp png = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png) { fclose(fp); return 2; }
    png_infop info = png_create_info_struct(png);
    if (!info) { png_destroy_read_struct(&png, NULL, NULL); fclose(fp); return 2; }

    jmp_buf jb;
    png_set_error_fn(png, &jb, on_error, NULL);
    if (setjmp(jb)) {
        png_destroy_read_struct(&png, &info, NULL);
        fclose(fp);
        printf("%s REJECT\n", path);
        return 1;
    }

    png_init_io(png, fp);
    png_set_sig_bytes(png, 8);
    png_read_info(png, info);
    png_uint_32 w, h;
    int bit_depth, color_type, interlace;
    png_get_IHDR(png, info, &w, &h, &bit_depth, &color_type, &interlace, NULL, NULL);
    png_read_update_info(png, info);

    png_bytep *rows = malloc(sizeof(png_bytep) * h);
    for (png_uint_32 i = 0; i < h; i++) {
        rows[i] = malloc(png_get_rowbytes(png, info));
    }
    png_read_image(png, rows);
    png_read_end(png, NULL);

    for (png_uint_32 i = 0; i < h; i++) free(rows[i]);
    free(rows);
    png_destroy_read_struct(&png, &info, NULL);
    fclose(fp);
    printf("%s ACCEPT %lux%lu\n", path, (unsigned long)w, (unsigned long)h);
    return 0;
}

int main(int argc, char **argv) {
    int rc = 0;
    for (int i = 1; i < argc; i++) {
        int r = decode_one(argv[i]);
        if (r == 2) rc = 2;
    }
    if (argc < 2) {
        fprintf(stderr, "usage: %s <png>...\n", argv[0]);
        return 2;
    }
    return rc;
}
