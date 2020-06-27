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

public class bruteForceTesting {
	
	public static void main(String[] args) {
		// Perform a set of 10 brute force attacks over 10 differet RSA Objects.
		for(int i = 0; i < 10; i++) {
			// Rsa object used to perform the brute force attack
			RSA rsaObj = new RSA();
			rsaObj.printInfo();
				
			RsaAttacker.bruteForceAttack(rsaObj.getExponent(), rsaObj.getN());
		}
	}
}
