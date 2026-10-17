/* libspng harness: decode a PNG and report ACCEPT/REJECT.
 *
 * Build:  cc -O2 -o libspng_decode libspng_decode.c -lspng -lpng? (libspng uses zlib)
 *         Typically: cc -O2 -o libspng_decode libspng_decode.c -lspng -lz
 */
#include <stdio.h>
#include <stdlib.h>
#include <spng.h>

static int decode_one(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) { fprintf(stderr, "%s: cannot open\n", path); return 2; }

    spng_ctx *ctx = spng_ctx_new(0);
    if (!ctx) { fclose(fp); return 2; }

    int err = spng_set_png_file(ctx, fp);
    if (err) {
        fprintf(stderr, "%s: spng_set_png_file: %s\n", path, spng_strerror(err));
        spng_ctx_free(ctx); fclose(fp);
        printf("%s REJECT\n", path);
        return 1;
    }

    struct spng_ihdr ihdr;
    err = spng_get_ihdr(ctx, &ihdr);
    if (err) {
        fprintf(stderr, "%s: spng_get_ihdr: %s\n", path, spng_strerror(err));
        spng_ctx_free(ctx); fclose(fp);
        printf("%s REJECT\n", path);
        return 1;
    }

    size_t img_size = 0;
    err = spng_decoded_image_size(ctx, SPNG_FMT_RGBA8, &img_size);
    if (err) {
        fprintf(stderr, "%s: spng_decoded_image_size: %s\n", path, spng_strerror(err));
        spng_ctx_free(ctx); fclose(fp);
        printf("%s REJECT\n", path);
        return 1;
    }

    unsigned char *img = malloc(img_size);
    if (!img) { spng_ctx_free(ctx); fclose(fp); return 2; }

    err = spng_decode_image(ctx, img, img_size, SPNG_FMT_RGBA8, 0);
    free(img);
    spng_ctx_free(ctx);
    fclose(fp);

    if (err) {
        fprintf(stderr, "%s: spng_decode_image: %s\n", path, spng_strerror(err));
        printf("%s REJECT\n", path);
        return 1;
    }
    printf("%s ACCEPT %ux%u\n", path, ihdr.width, ihdr.height);
    return 0;
}

int main(int argc, char **argv) {
    int rc = 0;
    if (argc < 2) {
        fprintf(stderr, "usage: %s <png>...\n", argv[0]);
        return 2;
    }
    for (int i = 1; i < argc; i++) {
        int r = decode_one(argv[i]);
        if (r == 2) rc = 2;
    }
    return rc;
}
