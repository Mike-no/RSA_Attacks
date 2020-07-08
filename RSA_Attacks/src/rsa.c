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

uint64_t modular_exponentiation(uint64_t x, uint64_t y, uint64_t p){
    uint64_t res = 1;
    // Update x if it is more than or equal to p
    x = x % p;  

    while(y > 0){
        // If y is odd multiply x with the product
        if(y & 1)
            res = (res*x) % p;

        y = y >> 1;
        x = (x * x) % p;
    }

    return res;
}

int miller_test(uint16_t d, uint16_t n){
    uint16_t a = 2 + (uint16_t) rand() % (n - 4);

    // Compute (a ^ d) % n
    uint64_t x = modular_exponentiation(a, d, n);

    if(x == 1 || x == n - 1)
        return 1;

    while(d != n - 1){
        x = (x * x) % n;
        d *= 2;

        if(x == 1)
            return 0;
        if(x == n - 1)
            return 1;
    }

    return 0;
}

int is_prime(uint16_t n){
    // Corner cases handling
    if(n <= 1 || n == 4)
        return 0;
    if(n <= 3)
        return 1;

    // Find r such that n = (2 ^ d) * r + 1 for some r >= 1
    uint16_t d = n - 1;
    while(d % 2 == 0)
        d /= 2;

    for(int i = 0; i < MILLER_RABIN_ACCURACY; i++)  // Test 100 times
        if(!miller_test(d, n))
            return 0;

    return 1;
}

uint16_t rng_prime(){
    uint16_t rng_val = (uint16_t) rand();

    while(!is_prime(rng_val))
        rng_val = (uint16_t) rand();

    return rng_val;   // rng_val is probably prime  
}

uint32_t gcd(uint16_t a, uint32_t b){
    if(a == 0)
        return b;

    return gcd(b % a, a);
}

void gcd_extended(uint16_t a, uint32_t b, int32_t* x, int32_t* y){
    // Base case handling
    if(a == 0){
        *x = 0;
        *y = 1;
        return;
    }

    // Application of the recursive algorithm
    int32_t x1, y1;
    gcd_extended(b % a, a, &x1, &y1);

    *x = y1 - (b / a) * x1;
    *y = x1;
}

uint16_t e_selection(uint32_t phi_n){
    uint16_t e = (uint16_t) rand();

    while((e <= 1 || e > phi_n) || gcd(e, phi_n) != 1)
        e = (uint16_t) rand();

    return e;       // exponent is (1, phi_n) & gcd(e, phi_n) = 1
}

uint32_t encrypt(uint32_t msg, uint16_t e, uint32_t n){
    if(msg > n)
        return -1;

    return modular_exponentiation(msg, e, n);   // (msg ^ e) mod n
}

uint32_t decrypt(uint32_t c, uint32_t d, uint32_t n){
    return modular_exponentiation(c, d, n);     // (c ^ d) mod n
}