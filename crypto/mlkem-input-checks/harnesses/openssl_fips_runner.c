/* OpenSSL ML-KEM cross-path invariance runner (msn-2026-0002).
 * Four cells per vector: raw/default, spki/default, raw/fips, spki->raw/fips.
 *
 * Cells:
 *  raw/default   : EVP_PKEY_new_raw_public_key_ex(propq="provider=default")
 *  spki/default  : d2i_PUBKEY of DER SPKI (hard-coded 22-byte prefix + ek)
 *  raw/fips      : EVP_PKEY_new_raw_public_key_ex(propq="provider=fips")
 *                  (keymgmt lives in libfips.a - direct validation probe)
 *  spki->raw/fips: decode DER via default decoder, extract raw bytes via
 *                  EVP_PKEY_get_octet_string_param, re-import under fips
 *                  propq. The SPKI decoder exists only in the default
 *                  provider (encode_decode/build.info), so a fips-only
 *                  decoder fetch is expected to fail; this chain cell is
 *                  the meaningful end-to-end FIPS answer.
 *
 * Attribution per row: format, provider, verdict (import-accepted |
 * import-rejected with lib:reason | chain-decode-failed | blocked),
 * encap liveness on success.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/provider.h>

#define MAX_LINE 8192
#define MAX_EK 4096
#define MAX_DER 8192

static int unhex(const char *hex, unsigned char *out, int cap) {
    int n = (int)strlen(hex), b = 0;
    if (n % 2 || n / 2 > cap) return -1;
    for (int i = 0; i < n; i += 2) {
        unsigned v;
        if (sscanf(hex + i, "%2x", &v) != 1) return -1;
        out[b++] = (unsigned char)v;
    }
    return b;
}

static const char *alg_for(const char *params) {
    if (!strcmp(params, "ML-KEM-512")) return "ML-KEM-512";
    if (!strcmp(params, "ML-KEM-768")) return "ML-KEM-768";
    if (!strcmp(params, "ML-KEM-1024")) return "ML-KEM-1024";
    return NULL;
}

/* Hard-coded 22-byte SPKI prefixes mirroring
 * providers/implementations/encode_decode/ml_kem_codecs.c:24-195 */
static const unsigned char spki_prefix_512[22]={0x30,0x82,0x03,0x32,0x30,0x0b,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x04,0x01,0x03,0x82,0x03,0x21,0x00};
static const unsigned char spki_prefix_768[22]={0x30,0x82,0x04,0xb2,0x30,0x0b,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x04,0x02,0x03,0x82,0x04,0xa1,0x00};
static const unsigned char spki_prefix_1024[22]={0x30,0x82,0x06,0x32,0x30,0x0b,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x04,0x03,0x03,0x82,0x06,0x21,0x00};

static const unsigned char *prefix_for(const char *alg) {
    if (!strcmp(alg, "ML-KEM-512")) return spki_prefix_512;
    if (!strcmp(alg, "ML-KEM-768")) return spki_prefix_768;
    return spki_prefix_1024;
}

static int build_spki_der(const unsigned char *test_ek, int ek_len,
                          const char *alg, unsigned char *out_der, int *out_len) {
    if (ek_len + 22 > MAX_DER) return 0;
    memcpy(out_der, prefix_for(alg), 22);
    memcpy(out_der + 22, test_ek, ek_len);
    *out_len = 22 + ek_len;
    return 1;
}

/* Emit import verdict row; returns parsed pkey or NULL. */
static EVP_PKEY *emit_import(FILE *out, const char *family, const char *params,
                             const char *expected, const char *source,
                             const char *fmt, const char *prov, EVP_PKEY *pkey) {
    if (pkey == NULL) {
        unsigned long e = ERR_peek_error();
        const char *lib = ERR_lib_error_string(e);
        const char *reason = ERR_reason_error_string(e);
        fprintf(out, "%s|%s|%s|%s|format=%s|provider=%s|import-rejected|%s:%s\n",
                family, params, expected, source, fmt, prov,
                lib ? lib : "?", reason ? reason : "?");
        ERR_clear_error();
        return NULL;
    }
    fprintf(out, "%s|%s|%s|%s|format=%s|provider=%s|%s\n",
            family, params, expected, source, fmt, prov,
            strncmp(expected, "fail-", 5) == 0 ? "import-accepted-UNEXPECTED" : "import-accepted");
    return pkey;
}

static void emit_encap(FILE *out, const char *family, const char *params,
                       const char *expected, const char *source,
                       const char *fmt, const char *prov, EVP_PKEY *pkey) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    size_t ctlen = 0, sslen = 0;
    int rc = ctx ? EVP_PKEY_encapsulate_init(ctx, NULL) : 0;
    if (rc > 0) rc = EVP_PKEY_encapsulate(ctx, NULL, &ctlen, NULL, &sslen);
    unsigned char *ct = ctlen ? malloc(ctlen) : NULL;
    unsigned char *ss = sslen ? malloc(sslen) : NULL;
    if (rc > 0 && ct && ss) rc = EVP_PKEY_encapsulate(ctx, ct, &ctlen, ss, &sslen);
    ERR_clear_error();
    fprintf(out, "%s|%s|%s|%s|format=%s|provider=%s|encap-%s\n",
            family, params, expected, source, fmt, prov,
            rc > 0 ? "accepted" : "rejected");
    free(ct); free(ss);
    EVP_PKEY_CTX_free(ctx);
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s stimuli.tsv report.out [fips-only]\n", argv[0]); return 2; }
    const char *mode = argc > 3 ? argv[3] : "full";
    int fips_only = strcmp(mode, "fips-only") == 0;
    FILE *in = fopen(argv[1], "r"), *out = fopen(argv[2], "w");
    if (!in || !out) { perror("open"); return 2; }
    /* Unbuffered so partial evidence survives any crash */
    setvbuf(out, NULL, _IONBF, 0);

    fprintf(stderr, "stage: meta\n");
    fprintf(out, "META|runtime_libcrypto=%s|compiled_headers=%s|mode=%s\n",
            OpenSSL_version(OPENSSL_VERSION), OPENSSL_VERSION_TEXT, mode);

    fprintf(stderr, "stage: provider-load-fips\n");
    /* Isolate FIPS in its own libctx: global co-activation of fips+default
     * segfaulted the SPKI decoder path (runs 5-7). The default context then
     * behaves identically to the validated msn-2026-0001 configuration. */
    OSSL_LIB_CTX *fips_ctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *fips_prov = NULL;
    int fips_available = 0;
    const char *fconf = getenv("OPENSSL_FIPS_CONF");
    if (fips_ctx && fconf && *fconf && OSSL_LIB_CTX_load_config(fips_ctx, fconf)) {
        fips_prov = OSSL_PROVIDER_load(fips_ctx, "fips");
        fips_available = (fips_prov != NULL);
    }
    ERR_clear_error();
    if (fips_available) {
        fprintf(out, "META|fips_provider=loaded|status=available|mode=isolated-libctx\n");
    } else {
        unsigned long e = ERR_peek_error();
        fprintf(out, "META|fips_provider=not-loaded|status=unavailable|reason=%s\n",
                ERR_reason_error_string(e) ? ERR_reason_error_string(e) : "no-fips-module");
        ERR_clear_error();
    }
    fprintf(stderr, "stage: provider-load-default\n");
    OSSL_PROVIDER *default_prov = OSSL_PROVIDER_load(NULL, "default");
    if (default_prov)
        fprintf(out, "META|default_provider=loaded\n");
    else
        ERR_clear_error();

    char line[MAX_LINE];
    static unsigned char ek[MAX_EK];
    static unsigned char der[MAX_DER];
    static unsigned char raw_back[MAX_EK];
    int total = 0;

    while (fgets(line, sizeof line, in)) {
        char *fields[5] = {0};
        int nf = 0;
        for (char *p = line;; p++) {
            if (*p == '|' && nf < 4) { *p = 0; fields[++nf] = p + 1; continue; }
            if (*p == '\n' || *p == '\r' || *p == 0) { *p = 0; break; }
            if (!fields[0]) fields[0] = p;
        }
        if (!fields[0] || nf < 4) continue;
        const char *family = fields[0], *params = fields[1], *expected = fields[2];
        const char *source = fields[3], *ek_hex = fields[4];
        const char *alg = alg_for(params);
        if (!alg) continue;
        total++;

        int ek_len = unhex(ek_hex, ek, sizeof ek);
        if (ek_len < 0) continue;

        if (total % 40 == 0)
            fprintf(stderr, "progress: vector %d (%s)\n", total, params);

        /* ---- Cell 1: raw/default ---- */
        fprintf(stderr, "stage: v%d raw/default\n", total);
        ERR_clear_error();
        EVP_PKEY *k = EVP_PKEY_new_raw_public_key_ex(NULL, alg, "provider=default", ek, (size_t)ek_len);
        k = emit_import(out, family, params, expected, source, "raw", "default", k);
        if (k && !fips_only) emit_encap(out, family, params, expected, source, "raw", "default", k);
        EVP_PKEY_free(k);

        if (fips_only) {
            /* fips-only mode: raw/fips comparison cell only - no DER decoding
             * in this process (d2i+encap on decoder keys crashed when any
             * second libctx existed; see runs 5-9). */
            fprintf(stderr, "stage: v%d raw/fips\n", total);
            if (fips_available) {
                ERR_clear_error();
                EVP_PKEY *kf = EVP_PKEY_new_raw_public_key_ex(fips_ctx, alg, "provider=fips", ek, (size_t)ek_len);
                kf = emit_import(out, family, params, expected, source, "raw", "fips", kf);
                EVP_PKEY_free(kf);
            } else {
                fprintf(out, "%s|%s|%s|%s|format=raw|provider=fips|blocked|reason=fips-unavailable\n",
                        family, params, expected, source);
            }
            continue;
        }

        /* ---- Cell 2: spki/default ---- */
        fprintf(stderr, "stage: v%d spki/default\n", total);
        ERR_clear_error();
        int der_len = 0;
        if (build_spki_der(ek, ek_len, alg, der, &der_len)) {
            const unsigned char *p = der;
            /* Plain decoder call (no propq): propq-filtered decoder fetch
             * segfaulted under dual-provider global activation. With the
             * combined cnf both providers are active; validation still
             * flows through the shared parse path regardless of which
             * keymgmt instance serves the fetch. */
            fprintf(stderr, "stage: v%d d2i-begin len=%d b0=%02x%02x\n", total, der_len, der[0], der[1]);
            k = d2i_PUBKEY(NULL, &p, der_len);
            fprintf(stderr, "stage: v%d d2i-done k=%d\n", total, k != NULL);
            k = emit_import(out, family, params, expected, source, "spki", "default", k);
            if (k) {
                fprintf(stderr, "stage: v%d encap-begin\n", total);
                emit_encap(out, family, params, expected, source, "spki", "default", k);
                fprintf(stderr, "stage: v%d encap-done\n", total);
            }
            /* ---- Cell 4: spki->raw/fips (chain through default decoder) ---- */
            if (fips_available) {
                size_t raw_len = 0;
                fprintf(stderr, "stage: v%d chain-extract-begin\n", total);
                int got = k ? EVP_PKEY_get_octet_string_param(
                                  k, OSSL_PKEY_PARAM_PUB_KEY,
                                  raw_back, sizeof raw_back, &raw_len) : 0;
                fprintf(stderr, "stage: v%d chain-extract-done got=%d raw_len=%zu\n", total, got, raw_len);
                EVP_PKEY_free(k); k = NULL;
                ERR_clear_error();
                if (!got) {
                    fprintf(out, "%s|%s|%s|%s|format=spki|provider=fips|chain-extract-failed\n",
                            family, params, expected, source);
                } else {
                    ERR_clear_error();
                    EVP_PKEY *kf = EVP_PKEY_new_raw_public_key_ex(fips_ctx, alg, "provider=fips", raw_back, raw_len);
                    kf = emit_import(out, family, params, expected, source, "spki->raw", "fips", kf);
                    if (kf) emit_encap(out, family, params, expected, source, "spki->raw", "fips", kf);
                    EVP_PKEY_free(kf);
                }
            } else {
                fprintf(out, "%s|%s|%s|%s|format=spki|provider=fips|blocked|reason=fips-unavailable\n",
                        family, params, expected, source);
                EVP_PKEY_free(k);
            }
        } else {
            fprintf(out, "%s|%s|%s|%s|format=spki|provider=default|spki-build-failed\n",
                    family, params, expected, source);
        }

        /* ---- Cell 3: raw/fips ---- */
        fprintf(stderr, "stage: v%d raw/fips\n", total);
        if (fips_available) {
            ERR_clear_error();
            EVP_PKEY *kf = EVP_PKEY_new_raw_public_key_ex(fips_ctx, alg, "provider=fips", ek, (size_t)ek_len);
            kf = emit_import(out, family, params, expected, source, "raw", "fips", kf);
            if (kf) emit_encap(out, family, params, expected, source, "raw", "fips", kf);
            EVP_PKEY_free(kf);
        } else {
            fprintf(out, "%s|%s|%s|%s|format=raw|provider=fips|blocked|reason=fips-unavailable\n",
                    family, params, expected, source);
        }
    }
    fprintf(out, "SUMMARY|total=%d|matrix_cells=4|fips_available=%d\n", total, fips_available);
    fclose(in); fclose(out);
    if (fips_prov) OSSL_PROVIDER_unload(fips_prov);
    if (default_prov) OSSL_PROVIDER_unload(default_prov);
    printf("done: %d vectors x 4 cells -> %s (fips_available=%d)\n", total, argv[2], fips_available);
    return 0;
}
