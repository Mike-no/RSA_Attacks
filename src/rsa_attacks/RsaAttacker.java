package rsa_attacks;

import java.math.BigInteger;

public final class RsaAttacker {
	private RsaAttacker() {};
	
	private static BigInteger MAX = new BigInteger("4294967296");
	
	/**
	 * Given the public key, it performs a brute force 
	 * attack in search of the private key factoring n.
	 * @param e32Bit 
	 * @param n64Bit
	 * @return Time spent
	 */
	public static long bruteForceAttack(BigInteger e32Bit, BigInteger n64Bit) {
		if(e32Bit == null || n64Bit == null)
			throw new NullPointerException();
		
		System.out.println(System.lineSeparator() + "Brute Force : " + System.lineSeparator());
		
		long start = System.currentTimeMillis();
		
		// Looking for p or q
		BigInteger factor = new BigInteger("1");
		for(BigInteger i = new BigInteger("2"); i.compareTo(MAX) < 0; i = i.add(BigInteger.ONE)) {
			if(n64Bit.mod(i).compareTo(BigInteger.ZERO) == 0) {
				factor = i;
				break;
			}
		}
		
		// Gets the other factor
		BigInteger factor2 = n64Bit.divide(factor);	
		
		// Compute phiN
		BigInteger phiN = factor.subtract(BigInteger.ONE).multiply(factor2.subtract(BigInteger.ONE));
	
		// Compute the private key
		BigInteger privateKey = e32Bit.modInverse(phiN);
		
		long timePassed = System.currentTimeMillis() - start;
		
		System.out.println("Completed in " + timePassed + " ms");
		System.out.println("Private Key : <" + privateKey + ">" + System.lineSeparator());
		
		return timePassed;
	}
	
	/**
	 * Given n, check if is a perfect square
	 * @param n
	 * @return true if n is a perfect square, false otherwise
	 */
	private static boolean isPerfectSquare(BigInteger n) {
		BigInteger sqrt = n.sqrt();
		
		if(sqrt.multiply(sqrt).equals(n) || sqrt.add(BigInteger.ONE).multiply(sqrt.add(BigInteger.ONE)).equals(n))
			return true;
		
		return false;
	}
	
	/**
	 * Given the public key, product of two close values, p and q, 
	 * apply the Fermat factoring algorithm to find the private key.
	 * @param e32Bit
	 * @param n64Bit
	 * @return Time spent
	 */
	public static long fermatFactoringAttack(BigInteger e32Bit, BigInteger n64Bit) {
		if(e32Bit == null || n64Bit == null)
			throw new NullPointerException();
		
		System.out.println(System.lineSeparator() + "Fermat Factoring :" + System.lineSeparator());
		
		long start = System.currentTimeMillis();
		
		// Let k be the smallest positive integer so that k^2 > n
		BigInteger z = n64Bit.sqrt().add(BigInteger.ONE);
		
		// Find the w such that z ^ 2 - n = w ^ 2
		BigInteger w = null;
		while(true) {
			w = z.multiply(z).subtract(n64Bit);
			if(isPerfectSquare(w))
				break;
			
			z = z.add(BigInteger.ONE);
		}
		w = w.sqrt();
		
		// Gets the factors p and q
		BigInteger p = z.add(w);
		BigInteger q = z.subtract(w);
		
		// Compute phiN
		BigInteger phiN = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
			
		// Compute the private key
		BigInteger privateKey = e32Bit.modInverse(phiN);
				
		long timePassed = System.currentTimeMillis() - start;
		
		System.out.println("Completed in " + timePassed + " ms");
		System.out.println("Private Key : <" + privateKey + ">" + System.lineSeparator());
		
		return timePassed;
	}
	
	/**
	 * 
	 * @param e32Bit
	 * @return Time spent
	 */
	public static long eSameValueAttack(BigInteger e32Bit) {
		return 0;
	}
}
