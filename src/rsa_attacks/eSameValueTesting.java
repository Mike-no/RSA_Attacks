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
import java.util.ArrayList;
import java.util.Random;

public class eSameValueTesting {

	public static void main(String[] args) {
		if(args.length != 1) {
			System.out.println("Usage eSameValueTesting <nTry>");
			System.exit(-1);
		}
		
		long start = System.currentTimeMillis();
		int nTry = Integer.parseInt(args[0]);
		
		// Simulate an exponent based attack with e = 3;
		for(int i = 0; i < nTry; i++) {
			int e = 3;
			ArrayList<RSA> rsaObjs = new ArrayList<RSA>();
			BigInteger ee = new BigInteger("3");
			// Create e user with the same exponent and different value of n = p * q
			for(int j = 0; j < e; j++) {
				rsaObjs.add(new RSA(ee));
				rsaObjs.get(j).printInfo();
			}
		
			// Create the list of the components n of the public key of each users
			ArrayList<BigInteger> n = new ArrayList<BigInteger>();
			for(RSA rsa : rsaObjs)
				n.add(rsa.getN());
			
			// Get the minimum n in order to create a message < n (for the modulo reduction)
			BigInteger min = n.get(0);
			for(int j = 1; j < n.size(); j++)
				if(n.get(j).compareTo(min) < 0)
					min = n.get(j);
			
			// Generate a random message less that min
			Random rnd = new Random();
			BigInteger msg;
			do {
				msg = new BigInteger(32, rnd);
			} while(msg.compareTo(min) >= 0);
			
			// Create the list of the cryptograms generated by each user for the same message msg
			ArrayList<BigInteger> c = new ArrayList<BigInteger>();
			for(RSA rsa : rsaObjs)
				c.add(rsa.encrypt(msg));
			
			System.out.println("Original Random Message: " + msg + System.lineSeparator());
			
			RsaAttacker.eSameValueAttack(e, n, c);
		}
		
		System.out.println("Same Exponent Attack completed in " + (System.currentTimeMillis() - start) + " ms");
	}
}
