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

public class fermatFactorizationTesting {
	public static void main(String[] args) {
		if(args.length != 1) {
			System.out.println("Usage fermatFactorizationTesting <nTry>");
			System.exit(-1);
		}
		
		int nTry = Integer.parseInt(args[0]);
		
		// Simulate a Fermat Factoring attack with nTry random RSA object 
		long fermatFactoringTimeRqst = 0;
		for(int i = 0; i < nTry; i++) {
			RSA rsaObjFF = new RSA();
			rsaObjFF.printInfo();
			fermatFactoringTimeRqst += RsaAttacker.fermatFactoringAttack(rsaObjFF.getExponent(), rsaObjFF.getN());
		}
		
		System.out.println("Fermat Factoring Attack completed in " + fermatFactoringTimeRqst + " ms");
	}
}
