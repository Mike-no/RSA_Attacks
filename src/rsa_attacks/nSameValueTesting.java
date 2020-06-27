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

package rsa_attacks;

import java.math.BigInteger;
import java.util.Random;

public class nSameValueTesting {

	public static void main(String[] args) {
		if(args.length != 1) {
			System.out.println("Usage nSameValueTesting <nTry>");
			System.exit(-1);
		}
		
		long start = System.currentTimeMillis();
		int nTry = Integer.parseInt(args[0]);

		// Simulate an n based attack
		for(int i = 0; i < nTry; i++) {
			// Generate p and q such that p != q
			Random rnd = new Random();
			BigInteger p32Bit = null;
			BigInteger q32Bit = null;
			do {
				p32Bit = BigInteger.probablePrime(32, rnd);
				q32Bit = BigInteger.probablePrime(32, rnd);
			} while(p32Bit.equals(q32Bit));
			
			// Generate two RSA object with the same value of n and different exponents; gcd(e1, e2) must be 1
			RSA rsa1 = null;
			RSA rsa2 = null;
			do {
				rsa1 = new RSA(p32Bit, q32Bit);
				rsa2 = new RSA(p32Bit, q32Bit);
			} while(rsa1.getExponent().equals(rsa2.getExponent()) || 
					!rsa1.getExponent().gcd(rsa2.getExponent()).equals(BigInteger.ONE));
			
			rsa1.printInfo();
			rsa2.printInfo();
			
			// Generate a random message less that rsa1.N and rsa2.N
			BigInteger msg;
			do {
				msg = new BigInteger(32, rnd);
			} while(msg.compareTo(rsa1.getN()) >= 0);
			
			System.out.println("Original Random Message: " + msg + System.lineSeparator());
			
			RsaAttacker.nSameValueAttack(rsa1.getN(), rsa1.getExponent(), rsa2.getExponent(), rsa1.encrypt(msg), rsa2.encrypt(msg));
		}
		
		System.out.println("Same n Attack completed in " + (System.currentTimeMillis() - start) + " ms");
	}
}
