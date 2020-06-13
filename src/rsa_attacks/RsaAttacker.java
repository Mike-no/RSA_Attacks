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
	 * Calculate the nthroot of the given BigInteger
	 * @param n
	 * @param x
	 * @return nthroot of x
	 */
	private static BigInteger nthRoot(int n, BigInteger x) {
	    BigInteger y = BigInteger.ZERO;
	    for(int m = (x.bitLength() - 1) / n; m >= 0; --m) {
	        BigInteger z = y.setBit(m);
	        int cmp = z.pow(n).compareTo(x);
	        if(cmp == 0) 
	        	return z;  // found exact root
	        if(cmp < 0) 
	        	y = z;     // keep bit set
	    }
	    
	    return y; // return floor of exact root
	}
	
	/**
	 * Given a (little) value e and e user that received the same message; use the Chinese rest
	 * theorem to find the only m' < n such that m' congruous m ^ e mod n.
	 * @param e32Bit
	 * @param n64Bits
	 * @param cmsgs
	 * @return Time spent
	 */
	public static long eSameValueAttack(int e32Bit, ArrayList<BigInteger> n64Bits, ArrayList<BigInteger> cmsgs) {
		if(n64Bits == null || cmsgs == null)
			throw new NullPointerException();
		if(e32Bit <= 1 || n64Bits.size() != e32Bit || cmsgs.size() != e32Bit)
			throw new IllegalArgumentException();
		
		System.out.println(System.lineSeparator() + "Same Exponent Attack :" + System.lineSeparator());
		
		long start = System.currentTimeMillis();
		
		// Compute n = n1 * n2 * ... * n_e
		BigInteger nChineseTh = BigInteger.ONE;
		for(BigInteger x : n64Bits)
			nChineseTh = nChineseTh.multiply(x);
		
		// Find m' congrous m ^ e mod n with the Chinese rest theorem
		BigInteger sum = BigInteger.ZERO;
		for(int i = 0; i < n64Bits.size(); i++) {
			BigInteger p = nChineseTh.divide(n64Bits.get(i));
			BigInteger tmp = p.modInverse(n64Bits.get(i));
			sum = sum.add(cmsgs.get(i).multiply(tmp).multiply(p));
		}
		
		BigInteger msg = nthRoot(e32Bit, sum.mod(nChineseTh));
		
		long timePassed = System.currentTimeMillis() - start;
		
		System.out.println("Completed in " + timePassed + " ms");
		System.out.println("Message Discovered : <" + msg + ">" + System.lineSeparator());
		
		return timePassed;
	}
	
	/**
	 * Private class that represent a simple triple
	 */
	private static class Triple {
		private final BigInteger d;
		private final BigInteger s;
		private final BigInteger t;
		
		// Constructor
		private Triple(final BigInteger d, final BigInteger s, final BigInteger t) {
			if(d == null || s == null || t == null)
				throw new NullPointerException();
			
			this.d = d;
			this.s = s;
			this.t = t;
		}
		
		private final BigInteger getD() {
			return d;
		}
		
		private final BigInteger getS() {
			return s;
		}
		
		private final BigInteger getT() {
			return t;
		}
	}
	
	/**
	 * Compute the Extended Euclidean Algorithm with the given value a and b
	 * @param a
	 * @param b
	 * @return Triple that represent the value of the Extended Euclidean Algorithm
	 */
	private static Triple apply(final BigInteger a, final BigInteger b) {
		if(b.equals(BigInteger.ZERO))
			return new Triple(a, BigInteger.ONE, BigInteger.ZERO);
		else {
			final Triple extension = apply(b, a.mod(b));
			return new Triple(extension.getD(), extension.getT(), extension.getS().subtract(a.divide(b).multiply(extension.getT())));
		}
	}
	
	/**
	 * Given 2 users that received the same message with the same value of n; use c1 ^ s * c2 ^ t mod n
	 * to find the the message m.
	 * @param n64Bit
	 * @param e32BitU1
	 * @param e32BitU2
	 * @param c1
	 * @param c2
	 * @return Time spent
	 */
	public static long nSameValueAttack(BigInteger n64Bit, BigInteger e32BitU1, BigInteger e32BitU2, BigInteger c1, BigInteger c2) {
		if(n64Bit == null || e32BitU1 == null || e32BitU2 == null || c1 == null || c2 == null)
			throw new NullPointerException();
		if(!e32BitU1.gcd(e32BitU2).equals(BigInteger.ONE))
			throw new IllegalArgumentException();
		
		System.out.println(System.lineSeparator() + "Same Exponent Attack :" + System.lineSeparator());
		
		long start = System.currentTimeMillis();
		
		// Gets the s and t such that s * e32BitU1 + t * e32BitU2 = 1
		Triple st = apply(e32BitU1, e32BitU2);
		
		// Compute c1 ^ s * c2 ^ t mod n
		BigInteger msg = null;
		if(st.getS().compareTo(BigInteger.ZERO) < 0) {
			BigInteger tmp = c1.modInverse(n64Bit);
			msg = tmp.modPow(st.getS().negate(), n64Bit).multiply(c2.modPow(st.getT(), n64Bit)).mod(n64Bit);
		}
		else {
			BigInteger tmp = c2.modInverse(n64Bit);
			msg = c1.modPow(st.getS(), n64Bit).multiply(tmp.modPow(st.getT().negate(), n64Bit)).mod(n64Bit);
		}
			
		long timePassed = System.currentTimeMillis() - start;
		
		System.out.println("Completed in " + timePassed + " ms");
		System.out.println("Message Discovered : <" + msg + ">" + System.lineSeparator());
		
		return timePassed;
	}
}
