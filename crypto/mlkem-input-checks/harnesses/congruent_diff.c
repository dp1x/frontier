/* Congruent-plant differential experiment (msn-2026-0001, hyp-2026-0007/0008).
 *
 * For each parameter set and several deterministic keypair seeds:
 *  1. keypair_derand -> (ek_c, dk_c)              [genuine honest peer]
 *  2. plant congruent overflow into ek_c's FIRST
 *     coefficient: c0' = c0 + q when c0 <= 4095-q  [raw bytes differ,
 *                                                  decoded t-hat IDENTICAL]
 *  3. sender side:   enc_derand(ct_a, ss_a, ek', coins)
 *     canonical ref: enc_derand(ct_b, ss_b, ek_c, coins)
 *     peer side:     decap(dk_c, ct_a) -> ss_d
 *
 * Predictions under hyp-2026-0007 (PQClean accepts everything):
 *   P1 ct_a == ct_b        (arithmetic congruence)
 *   P2 ss_a != ss_d        (hash input differs: raw vs canonical bytes)
 *   P3 ss_b == ss_d        (canonical sender and honest peer agree)
 * A checking library would reject at step 3 instead - recorded as rc!=0.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand(unsigned char *ek, unsigned char *dk, const unsigned char *coins);
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_derand(unsigned char *ct, unsigned char *ss, const unsigned char *pk, const unsigned char *coins);
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(unsigned char *ek, unsigned char *dk, const unsigned char *coins);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(unsigned char *ct, unsigned char *ss, const unsigned char *pk, const unsigned char *coins);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);
int PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair_derand(unsigned char *ek, unsigned char *dk, const unsigned char *coins);
int PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc_derand(unsigned char *ct, unsigned char *ss, const unsigned char *pk, const unsigned char *coins);
int PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

#define Q 3329

/* Deterministic stub: only *_enc_derand/dec are called, but kem.obj references
   PQCLEAN_randombytes via crypto_kem_enc, so the link needs it. */
void PQCLEAN_randombytes(uint8_t *out, size_t n) {
    memset(out, 0xA5, n);
}

typedef struct {
    const char *name;
    int ek_len, dk_len, ct_len;
    int (*kp)(unsigned char *, unsigned char *, const unsigned char *);
    int (*enc)(unsigned char *, unsigned char *, const unsigned char *, const unsigned char *);
    int (*dec)(unsigned char *, const unsigned char *, const unsigned char *);
} Scheme;

static const Scheme SCHEMES[] = {
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
#define N ((int)(sizeof(SCHEMES) / sizeof(SCHEMES[0])))

#define MAX_EK 4096
#define MAX_DK 4096
#define SEEDS 8

static void fill_coins(unsigned char *buf, int n, unsigned seed) {
    for (int i = 0; i < n; i++) buf[i] = (unsigned char)((seed * 1315423911u + i * 2654435761u) >> 24);
}

/* Plant c0' = c0 + q in the first 12-bit segment when representable. Returns planted value or -1. */
static long plant_first(unsigned char *ek) {
    unsigned c0 = ek[0] | ((unsigned)(ek[1] & 0x0F) << 8);
    if (c0 > (unsigned)(4095 - Q)) return -1;
    unsigned v = c0 + Q;
    ek[0] = (unsigned char)(v & 0xFF);
    ek[1] = (unsigned char)((ek[1] & 0xF0) | ((v >> 8) & 0x0F));
    return (long)v;
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s report.out\n", argv[0]); return 2; }
    FILE *out = fopen(argv[1], "w");
    if (!out) { perror("open"); return 2; }

    static unsigned char ek[MAX_EK], ekp[MAX_EK], dk[MAX_DK];
    static unsigned char ct_a[MAX_EK], ct_b[MAX_EK], ss_a[32], ss_b[32], ss_d[32];
    unsigned char kp_coins[64], enc_coins[32];

    int rows = 0;
    for (int s = 0; s < N; s++) {
        const Scheme *sc = &SCHEMES[s];
        for (int seed = 1; seed <= SEEDS; seed++) {
            fill_coins(kp_coins, 64, (unsigned)(seed * 7919 + s));
            fill_coins(enc_coins, 32, (unsigned)(seed * 104729 + s));
            if (sc->kp(ek, dk, kp_coins) != 0) { fprintf(out, "%s|%d|keypair-failed\n", sc->name, seed); continue; }

            memcpy(ekp, ek, (size_t)sc->ek_len);
            long planted = plant_first(ekp);

            /* Canonical reference encryption. */
            if (sc->enc(ct_b, ss_b, ek, enc_coins) != 0) { fprintf(out, "%s|%d|enc-canonical-failed\n", sc->name, seed); continue; }

            if (planted < 0) {
                fprintf(out, "%s|%d|%s|no-plant|n/a|n/a|n/a\n", sc->name, seed, "skip");
                continue;
            }
            /* Sender uses the accepting library on the corrupted raw key. */
            int rc = sc->enc(ct_a, ss_a, ekp, enc_coins);
            if (rc != 0) {
                fprintf(out, "%s|%d|%s|rejected(rc=%d)|n/a|n/a|n/a\n", sc->name, seed, "planted", rc);
                continue;
            }
            /* Honest peer decapsulates the attacker-chosen ciphertext with the genuine dk. */
            if (sc->dec(ss_d, ct_a, dk) != 0) { fprintf(out, "%s|%d|%s|decap-failed|n/a|n/a|n/a\n", sc->name, seed, "planted"); continue; }

            int ct_eq = memcmp(ct_a, ct_b, (size_t)sc->ct_len) == 0;
            int ss_sender_vs_peer_eq = memcmp(ss_a, ss_d, 32) == 0;      /* predict 0 */
            int ss_canon_vs_peer_eq = memcmp(ss_b, ss_d, 32) == 0;       /* predict 1 */
            fprintf(out, "%s|%d|%s|accepted(planted=%ld)|ct_eq=%d|ss_sender==peer:%d|ss_canon==peer:%d\n",
                    sc->name, seed, "planted", planted, ct_eq, ss_sender_vs_peer_eq, ss_canon_vs_peer_eq);
            rows++;
        }
    }
    fprintf(out, "SUMMARY|rows=%d\n", rows);
    fclose(out);
    printf("done: %d differential rows -> %s\n", rows, argv[1]);
    return 0;
}
