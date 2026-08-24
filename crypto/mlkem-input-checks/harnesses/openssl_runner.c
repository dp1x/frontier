/* OpenSSL ML-KEM stimulus runner (msn-2026-0001).
 * Raw-bytestring public-key import (EVP_PKEY_new_raw_public_key_ex) followed
 * by EVP_PKEY_encapsulate on success; records import verdict and encapsulate
 * verdict SEPARATELY so check placement is observable.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>

#define MAX_LINE 8192

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

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: %s stimuli.tsv report.out\n", argv[0]); return 2; }
    FILE *in = fopen(argv[1], "r"), *out = fopen(argv[2], "w");
    if (!in || !out) { perror("open"); return 2; }

    fprintf(out, "META|openssl=%s\n", OPENSSL_VERSION_TEXT);
    char line[MAX_LINE];
    static unsigned char ek[4096];
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
        if (ek_len < 0) { fprintf(out, "%s|%s|%s|%s|hex-error\n", family, params, expected, source); continue; }

        /* Placement probe A: raw-key import. */
        ERR_clear_error();
        EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key_ex(NULL, alg, NULL, ek, (size_t)ek_len);
        if (pkey == NULL) {
            unsigned long e = ERR_peek_error();
            const char *lib = ERR_lib_error_string(e), *reason = ERR_reason_error_string(e);
            fprintf(out, "%s|%s|%s|%s|import-rejected|%s:%s:%s\n", family, params,
                    expected, source, lib ? lib : "?", reason ? reason : "?",
                    expected[0] == 'f' && expected[5] == 't' ? "length-or-modulus" : "unexpected");
            ERR_clear_error();
            continue;
        }
        if (strncmp(expected, "fail-", 5) == 0) {
            fprintf(out, "%s|%s|%s|%s|import-accepted-UNEXPECTED\n", family, params, expected, source);
        } else {
            fprintf(out, "%s|%s|%s|%s|import-accepted\n", family, params, expected, source);
        }
        /* Liveness: full encapsulation through the imported key. */
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
        size_t ctlen = 0, sslen = 0;
        int rc = ctx ? EVP_PKEY_encapsulate_init(ctx, NULL) : 0;
        if (rc > 0) rc = EVP_PKEY_encapsulate(ctx, NULL, &ctlen, NULL, &sslen);
        unsigned char *ct = ctlen ? malloc(ctlen) : NULL, *ss = sslen ? malloc(sslen) : NULL;
        if (rc > 0 && ct && ss) rc = EVP_PKEY_encapsulate(ctx, ct, &ctlen, ss, &sslen);
        fprintf(out, "%s|%s|%s|%s|encap-%s\n", family, params, expected, source,
                rc > 0 ? "accepted" : "rejected");
        free(ct); free(ss); EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(pkey);
    }
    fprintf(out, "SUMMARY|total=%d\n", total);
    fclose(in); fclose(out);
    printf("done: %d vectors -> %s\n", total, argv[2]);
    return 0;
}
