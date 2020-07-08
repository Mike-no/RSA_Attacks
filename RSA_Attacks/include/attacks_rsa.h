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

#ifndef ATTACKS_RSA_H_

#define ATTACKS_RSA_H_

#include "routines_rsa.h"

/**
 * Given the cryptogram, it performs a brute force 
 * attack in search of the private key factoring n
**/ 
void brute_force_atk(uint32_t e, uint32_t n);

#endif // ATTACKS_RSA_H_