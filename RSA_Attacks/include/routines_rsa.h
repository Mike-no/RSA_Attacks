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

#ifndef ROUTINES_RSA_H_

#define ROUTINES_RSA_H_

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <inttypes.h>

#define MILLER_RABIN_ACCURACY 100

/**
 * Function used to do modular exponentiation
 * @return (x ^ y) % p
**/
uint64_t modular_exponentiation(uint64_t x, uint64_t y, uint64_t p);

/**
 * Perform the Miller primality test on n
 * @return 1 : if n is prime
 *         0 : if n is composed
**/
int miller_test(uint16_t d, uint16_t n);

/**
 * Use Miller's test (9 times) to verify, with a good chance, 
 * that the input value n is prime or not
 * @return 1 : if n is prime for the Miller-Rabin test
 *         0 : if n is composed
**/ 
int is_prime(uint16_t n);

/**
 * Generate a random 16 bit value with probability 
 * less than 1/(4 ^ 9) of not being prime
 * @return a prime number n
**/ 
uint16_t rng_prime();

/**
 * Simply calcute gcd(a, b)
 * @return gcd(a, b)
**/
uint32_t gcd(uint16_t a, uint32_t b);

/**
 * The extended Euclidean algorithm is particularly useful 
 * when a and b are coprime (or gcd is 1).
 * Since x is the modular multiplicative inverse of 
 * “a mod b”, and y is the modular multiplicative inverse of 
 * “b mod a”.
**/ 
void gcd_extended(uint16_t a, uint32_t b, int32_t* x, int32_t* y);

/**
 * Randomly select e such that e < n and gcd(e, phi_n) = 1
 * @return exponent e
**/ 
uint16_t e_selection(uint32_t phi_n);

/**
 * Encrypt the message msg: m^e mod n
 * msg must be < n (modulo)
 * @return cryptogram
 *         -1 : if msg is bigger than n
**/
uint32_t encrypt(uint32_t msg, uint16_t e, uint32_t n);

/**
 * Decrypt the cryptogram c: c^d mod n
 * @return msg
**/ 
uint32_t decrypt(uint32_t c, uint32_t d, uint32_t n);

#endif // ROUTINES_RSA_H_
