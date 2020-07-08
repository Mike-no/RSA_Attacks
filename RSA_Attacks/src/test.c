/**
 * ########################################################
 * 
 * @author: Michael De Angelis
 * @mat: 560049
 * @project: Esperienze di Programmazione [ESP]
 * @AA: 2019 / 2020
 * 
 * ########################################################
 */

#include "../include/routines_rsa.h"
#include "../include/attacks_rsa.h"

int main(int argc, char** argv){
    if(argc != 2){
        fprintf(stderr, "Usage: test <msg>\n");
        exit(EXIT_FAILURE);
    }

    uint32_t msg = atoi(argv[1]);

    // Seed initialization
    srand((unsigned int)time(NULL));

    // Get random p and q
    uint16_t p = rng_prime();
    fprintf(stdout, "p: %" PRIu16 "\n", p);

    uint16_t q = rng_prime();
    fprintf(stdout, "q: %" PRIu16 "\n", q);

    // Generate n = p * q
    uint32_t n = (uint32_t) p * q;

    // Generate phi_n = (p - 1) * (q - 1)
    uint32_t phi_n = (uint32_t) (p - 1) * (q - 1);
    fprintf(stdout, "phi_n: %" PRIu32 "\n", phi_n);

    // Get random e
    uint16_t e = e_selection(phi_n);

    // Calculate d -> (e ^ (- 1)) mod phi_n
    int32_t x;
    int32_t y;
    gcd_extended(e, phi_n, &x, &y);
    if(x < 0)
        x += phi_n;

    fprintf(stdout, "public key <%" PRIu32 ", %" PRIu32 ">\n", e, n);
    fprintf(stdout, "private key <%" PRId32 ">\n", x);

    fprintf(stdout, "\n********* Encrypts the message *********\n\n");

    uint32_t c = encrypt(msg, e, n);
    if(c == -1){
        fprintf(stderr, "msg too long!\n");
        exit(EXIT_FAILURE);
    }
    fprintf(stdout, "cryptogram: %" PRIu32 "\n", c);

    fprintf(stdout, "\n********* Decrypts the message *********\n\n");
    fprintf(stdout, "decrypt: %" PRIu32 "\n", decrypt(c, x, n));

    fprintf(stdout, "\n---------------- Attacks ----------------");

    // Performs a brute force attack
    brute_force_atk(e, n);
}   