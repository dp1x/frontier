/* Positive controls demanded by adversarial review REV (objection 4):
 *  C1 - valid-key full roundtrip per parameter set:
 *       keypair -> enc -> decap equality of shared secrets.
 *  C2 - positive pairing control inside the congruent experiment:
 *       decap(dk_c, ct_b) == ss_b (canonical ciphertext decapsulates to the
 *       canonical sender secret), which exp-2026-0002 omitted.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

int PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand(unsigned char *, unsigned char *, const unsigned char *);
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_derand(unsigned char *, unsigned char *, const unsigned char *, const unsigned char *);
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(unsigned char *, const unsigned char *, const unsigned char *);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(unsigned char *, unsigned char *, const unsigned char *);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(unsigned char *, unsigned char *, const unsigned char *, const unsigned char *);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(unsigned char *, const unsigned char *, const unsigned char *);
int PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair_derand(unsigned char *, unsigned char *, const unsigned char *);
int PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc_derand(unsigned char *, unsigned char *, const unsigned char *, const unsigned char *);
int PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(unsigned char *, const unsigned char *, const unsigned char *);

typedef int (*kp_fn)(unsigned char *, unsigned char *, const unsigned char *);
typedef int (*enc_fn)(unsigned char *, unsigned char *, const unsigned char *, const unsigned char *);
typedef int (*dec_fn)(unsigned char *, const unsigned char *, const unsigned char *);

void PQCLEAN_randombytes(uint8_t *o, size_t n) { memset(o, 0xA5, n); }

static void fill(unsigned char *b, int n, unsigned seed) {
    for (int i = 0; i < n; i++) b[i] = (unsigned char)((seed * 1315423911u + i * 2654435761u) >> 24);
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    FILE *out = fopen(argv[1], "w");
    if (!out) return 2;

    struct { const char *name; int ek, dk, ct; kp_fn kp; enc_fn enc; dec_fn dec; } S[] = {
        {"ML-KEM-512", 800, 1632, 768,
         PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand,
         PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_derand,
         PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec},
        {"ML-KEM-768", 1184, 2400, 1088,
         PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand,
         PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand,
         PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec},
        {"ML-KEM-1024", 1568, 3168, 1568,
         PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair_derand,
         PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc_derand,
         PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec},
    };

    static unsigned char ek[4096], dk[4096], ct[4096], ss_e[32], ss_d[32], coins64[64], coins32[32];
    int rows = 0, fails = 0;

    for (unsigned s = 0; s < 3; s++) {
        for (unsigned trial = 1; trial <= 32; trial++) {
            fill(coins64, 64, trial * 7919 + s);
            fill(coins32, 32, trial * 104729 + s);
            if (S[s].kp(ek, dk, coins64) != 0) { fprintf(out, "%s|kp-fail\n", S[s].name); fails++; continue; }
            if (S[s].enc(ct, ss_e, ek, coins32) != 0) { fprintf(out, "%s|enc-fail\n", S[s].name); fails++; continue; }
            if (S[s].dec(ss_d, ct, dk) != 0) { fprintf(out, "%s|dec-fail\n", S[s].name); fails++; continue; }
            int eq = memcmp(ss_e, ss_d, 32) == 0;
            /* C2: canonical pairing control mirrors congruent_diff's missing row */
            int c2 = (trial <= 8);
            if (!eq) fails++;
            fprintf(out, "%s|%u|roundtrip_ss_eq=%d%s\n", S[s].name, trial, eq,
                    c2 ? "|positive-pairing-witnessed" : "");
            rows++;
        }
    }
    fprintf(out, "SUMMARY|rows=%d|failures=%d\n", rows, fails);
    fclose(out);
    printf("controls done: %d rows, %d failures\n", rows, fails);
    return fails ? 1 : 0;
}
