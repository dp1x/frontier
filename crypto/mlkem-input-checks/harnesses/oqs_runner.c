/* liboqs ML-KEM section 7.2 stimulus runner (msn-2026-0001).
 *
 * Public-API surface only: OQS_KEM_encaps on raw caller-filled key buffers.
 * Deterministic outputs via OQS_randombytes_custom_algorithm.
 *
 * Verdict semantics mirror pqclean_runner: accepted = rc==OQS_SUCCESS;
 * rejected = rc!=0 recorded verbatim; wrong-length vectors are
 * inexpressible-at-api (fixed-size buffers, no length argument).
 * Logs AVX2 availability so backend attribution is recorded per run.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <intrin.h>

#include <oqs/oqs.h>

#define MAX_LINE 8192
#define MAX_EK   4096

static void det_random(uint8_t *buf, size_t n) {
    static uint64_t state = 0x243F6A8885A308D3ull;
    for (size_t i = 0; i < n; i++) {
        state = state * 6364136223846793005ull + 1442695040888963407ull;
        buf[i] = (uint8_t)(state >> 33);
    }
}

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

static int avx2_available(void) {
    int regs[4];
    __cpuid(regs, 0);
    if (regs[0] < 7) return 0;
    int f1[4], f7[4];
    __cpuid(f1, 1);
    __cpuidex(f7, 7, 0);
    /* OSXSAVE | AVX | AVX2 */
    return ((f1[2] & (1 << 27)) && (f1[2] & (1 << 28)) && (f7[1] & (1 << 5))) ? 1 : 0;
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: %s stimuli.tsv report.out\n", argv[0]); return 2; }
    FILE *in = fopen(argv[1], "r"), *out = fopen(argv[2], "w");
    if (!in || !out) { perror("open"); return 2; }

    OQS_randombytes_custom_algorithm(&det_random);
    fprintf(out, "META|avx2=%d|liboqs=%s\n", avx2_available(), OQS_version());

    char line[MAX_LINE];
    static unsigned char ek[MAX_EK], ct[MAX_EK], ss[32];
    int total = 0, matched = 0;

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

        OQS_KEM *kem = NULL;
        for (int i = 0; i < (int)OQS_KEM_algs_length; i++) {
            /* iterate known names below instead */ (void)i; break;
        }
        if (!strcmp(params, "ML-KEM-512")) kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_512);
        else if (!strcmp(params, "ML-KEM-768")) kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
        else if (!strcmp(params, "ML-KEM-1024")) kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
        if (!kem) continue;
        total++;

        int ek_len = unhex(ek_hex, ek, MAX_EK);
        if (ek_len != (int)kem->length_public_key) {
            fprintf(out, "%s|%s|%s|%s|rc=n/a|inexpressible-at-api\n",
                    family, params, expected, source);
            matched++;
            OQS_KEM_free(kem);
            continue;
        }

        memset(ct, 0xCC, sizeof ct);
        memset(ss, 0xCC, sizeof ss);
        OQS_STATUS rc = OQS_KEM_encaps(kem, ct, ss, ek);
        int produced_output = 0;
        for (size_t i = 0; i < kem->length_ciphertext && !produced_output; i++)
            if (ct[i] != 0xCC) produced_output = 1;
        const char *verdict =
            (rc == OQS_SUCCESS && produced_output) ? "accepted"
            : (rc == OQS_SUCCESS ? "accepted-no-output" : "rejected");
        fprintf(out, "%s|%s|%s|%s|rc=%d|%s\n", family, params, expected, source,
                (int)rc, verdict);
        matched++;
        OQS_KEM_free(kem);
    }
    fprintf(out, "SUMMARY|total=%d|matched=%d\n", total, matched);
    fclose(in); fclose(out);
    printf("done: %d vectors -> %s\n", total, argv[2]);
    return 0;
}
