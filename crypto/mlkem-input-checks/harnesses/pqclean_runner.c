/* PQClean ML-KEM section 7.2 stimulus runner (msn-2026-0001).
 *
 * Reads the flattened TSV stimulus file, runs every vector whose params match
 * the linked schemes through PQClean's crypto_kem_enc_derand (fixed coins =>
 * deterministic outputs), prints one result line per vector plus a summary.
 * Exit code 0 = infrastructure OK (vector verdicts live in the report).
 *
 * Verdict semantics:
 *   accepted       - enc returned 0 AND wrote ciphertext bytes (PQClean's API
 *                    cannot signal invalid keys; nonzero rc would be a surprise)
 *   inexpressible-at-api - wrong-length vector: the pointer ABI carries no
 *                    length, so the type check cannot even be expressed here;
 *                    we do NOT call the function (calling would read past the
 *                    buffer = caller contract violation, not a check result)
 *
 * Usage: pqclean_runner.exe <stimuli.tsv> <report.out>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Deterministic stub: this harness only calls *_enc_derand, but kem.obj
   references PQCLEAN_randombytes via crypto_kem_enc, so the link needs it. */
#include <stdint.h>
void PQCLEAN_randombytes(uint8_t *out, size_t n) {
    memset(out, 0xA5, n);
}

int PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_derand(unsigned char *ct, unsigned char *ss,
                                                 const unsigned char *pk, const unsigned char *coins);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(unsigned char *ct, unsigned char *ss,
                                                 const unsigned char *pk, const unsigned char *coins);
int PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc_derand(unsigned char *ct, unsigned char *ss,
                                                  const unsigned char *pk, const unsigned char *coins);

#define MAX_LINE 8192
#define MAX_EK   4096

typedef int (*enc_derand_fn)(unsigned char *, unsigned char *, const unsigned char *,
                             const unsigned char *);

typedef struct Scheme {
    const char *name;
    int ek_len;
    int ct_len;
    enc_derand_fn fn;
} Scheme;

static const Scheme SCHEMES[] = {
    {"ML-KEM-512", 800, 768, PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_derand},
    {"ML-KEM-768", 1184, 1088, PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand},
    {"ML-KEM-1024", 1568, 1568, PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc_derand},
};
#define N_SCHEMES ((int)(sizeof(SCHEMES) / sizeof(SCHEMES[0])))

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

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: %s stimuli.tsv report.out\n", argv[0]); return 2; }
    FILE *in = fopen(argv[1], "r"), *out = fopen(argv[2], "w");
    if (!in || !out) { perror("open"); return 2; }

    static const unsigned char COINS[32] = {0}; /* fixed coins: deterministic */
    char line[MAX_LINE];
    static unsigned char ek[MAX_EK], ct[MAX_EK], ss[32];
    int total = 0, matched = 0, surprises = 0;

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

        const Scheme *sc = NULL;
        for (int i = 0; i < N_SCHEMES; i++)
            if (!strcmp(params, SCHEMES[i].name)) sc = &SCHEMES[i];
        if (!sc) continue;
        total++;

        int ek_len = unhex(ek_hex, ek, MAX_EK);
        if (ek_len < 0) { fprintf(out, "%s|%s|hex-error|%s\n", family, params, source); surprises++; continue; }
        if (ek_len != sc->ek_len) {
            fprintf(out, "%s|%s|%s|%s|rc=n/a|inexpressible-at-api\n",
                    family, params, expected, source);
            matched++;
            continue;
        }

        memset(ct, 0xCC, sizeof ct);
        memset(ss, 0xCC, sizeof ss);
        int rc = sc->fn(ct, ss, ek, COINS);
        int produced_output = 0;
        for (int i = 0; i < sc->ct_len && !produced_output; i++)
            if (ct[i] != 0xCC) produced_output = 1;
        const char *verdict =
            (rc == 0 && produced_output) ? "accepted"
                                         : (rc == 0 ? "accepted-no-output" : "rejected");
        if (rc != 0 || !produced_output) surprises++;
        fprintf(out, "%s|%s|%s|%s|rc=%d|%s\n", family, params, expected, source, rc, verdict);
        matched++;
    }
    fprintf(out, "SUMMARY|total=%d|matched=%d|surprises=%d\n", total, matched, surprises);
    fclose(in); fclose(out);
    printf("done: %d vectors, %d surprises, report %s\n", total, surprises, argv[2]);
    return 0;
}
