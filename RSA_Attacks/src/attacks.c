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

#include "../include/attacks_rsa.h"

void brute_force_atk(uint32_t e, uint32_t n){
    fprintf(stdout, "\n\n############## Brute Force ##############\n\n");

    uint64_t start = (unsigned long) time(NULL);

    // Loking for p or q
    uint16_t factor;
    for(uint16_t i = 2; i < UINT32_MAX; i++){
        if((n % i) == 0){
            factor = i;
            break;
        }
    }

    uint16_t factor2 = n / factor;                  // Gets the other factor

    uint32_t phi_n = (factor - 1) * (factor2 - 1);  // Calculate phi_n

    // Calculate the private key
    int32_t x;
    int32_t y;
    gcd_extended(e, phi_n, &x, &y);
    if(x < 0)
        x += phi_n;

    uint64_t end = (unsigned long) time(NULL);

    fprintf(stdout, "Completed in %" PRIu64 " ms\nPrivate key: %" PRIu32 "\n", end - start, x);

    fprintf(stdout, "\n#########################################\n");
}