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

import java.util.Random;
import java.math.BigInteger;

public class RSA {
	
	private BigInteger p32Bit;
	private BigInteger q32Bit;
	private BigInteger n64Bit;
	private BigInteger phiN64Bit;
	private BigInteger e32Bit;
	private BigInteger privateKey;
	
	private void initializer(BigInteger p32Bit, BigInteger q32Bit) {
		// Compute n = p * q 
		n64Bit = p32Bit.multiply(q32Bit);
		
		// Compute phiN = (p - 1) * (q - 1)
		phiN64Bit = p32Bit.subtract(BigInteger.ONE).multiply(q32Bit.subtract(BigInteger.ONE));
		
		// Compute e
		e32Bit = eSelection(phiN64Bit);
		
		// Compute d = e ^ (-1) mod phiN
		privateKey = e32Bit.modInverse(phiN64Bit);
	}
	
	// Private method to find the exponent e
	private static BigInteger eSelection(BigInteger phiN64Bit) {
		Random rnd = new Random();
		BigInteger e32Bit;
		
		// Until e <= 1 or e > phiN or gcd(e, phiN) != 1
		do {
			e32Bit = new BigInteger(32, rnd);
		} while((e32Bit.compareTo(BigInteger.ONE) <= 0 || e32Bit.compareTo(phiN64Bit) >= 0) || 
				!e32Bit.gcd(phiN64Bit).equals(BigInteger.ONE) ||
				e32Bit.equals(phiN64Bit.add(BigInteger.TWO).divide(BigInteger.TWO)));
		
		return e32Bit;
	}
	
	/**
	 * Initialize an RSA Object that can be used to Encrypt and Decrypt messages
	 * with random (and odds) p and q.
	 */
	public RSA() {
		Random rnd = new Random();
		
		// Generate random p and q 
		do {
			p32Bit = BigInteger.probablePrime(32, rnd);
			q32Bit = BigInteger.probablePrime(32, rnd);
		} while(p32Bit.equals(q32Bit));
		
		initializer(p32Bit, q32Bit);
	}
	
	/**
	 * Initialize an RSA Object, with the specified exponent e, that can be used to
	 * Encrypt and Decrypt messages with random (and odds) p and q. 
	 * @param e32Bit
	 */
	public RSA(BigInteger e32Bit) {
		if(e32Bit == null)
			throw new NullPointerException();
		if(e32Bit.compareTo(BigInteger.ONE) <= 0)
			throw new IllegalArgumentException();
		
		Random rnd = new Random();
		
		// Generate random p and q 
		do {
			p32Bit = BigInteger.probablePrime(32, rnd);
			q32Bit = BigInteger.probablePrime(32, rnd);
			
			// Compute n = p * q 
			n64Bit = p32Bit.multiply(q32Bit);
			
			// Compute phiN = (p - 1) * (q - 1)
			phiN64Bit = p32Bit.subtract(BigInteger.ONE).multiply(q32Bit.subtract(BigInteger.ONE));
		} while(p32Bit.equals(q32Bit) || !e32Bit.gcd(phiN64Bit).equals(BigInteger.ONE) ||
				e32Bit.compareTo(phiN64Bit) >= 0 || e32Bit.equals(phiN64Bit.add(BigInteger.TWO).divide(BigInteger.TWO)));
	
		this.e32Bit = e32Bit;
		
		// Compute d = e ^ (-1) mod phiN
		privateKey = this.e32Bit.modInverse(phiN64Bit);
	}
	
	/**
	 * Initialize an RSA Object, with the specified values of p and q, that can be used to
	 * Encrypt and Decrypt messages with random (and odds) p and q.
	 * @param p32Bit
	 * @param q32Bit
	 */
	public RSA(BigInteger p32Bit, BigInteger q32Bit) {
		if(p32Bit == null || q32Bit == null)
			throw new NullPointerException();
		if(!p32Bit.isProbablePrime(100) || !q32Bit.isProbablePrime(100) || p32Bit.equals(q32Bit))
			throw new IllegalArgumentException();
		
		this.p32Bit = p32Bit;
		this.q32Bit = q32Bit;
		
		initializer(this.p32Bit, this.q32Bit);
	}
	
	/**
	 * Given a message, it encrypts it
	 * @param msg
	 * @return Encrypted message
	 */
	public BigInteger encrypt(BigInteger msg) {
		if(msg == null)
			throw new NullPointerException();
		if(msg.compareTo(n64Bit) > 0)
			throw new IllegalArgumentException("Msg too long");
		
		return msg.modPow(e32Bit, n64Bit);			// (msg ^ e) mod n
	}
	
	/**
	 * Given a cryptogram, it decipher it
	 * @param c : cryptogram
	 * @return Deciphered message
	 */
	public BigInteger decrypt(BigInteger c) {
		if(c == null)
			throw new NullPointerException();
		
		return c.modPow(privateKey, n64Bit);		// (c ^ privateKey) mod n
	}
	
	/**
	 * Print p, q, n, phiN, public key and private key
	 */
	public void printInfo() {
		System.out.println("p : " + p32Bit);
		System.out.println("q : " + q32Bit);
		System.out.println("phiN : " + phiN64Bit + System.lineSeparator());
		
		System.out.println("public key <" + e32Bit + ", " + n64Bit + ">");
		System.out.println("private key <" + privateKey + ">" + System.lineSeparator());
	}
	
	/**
	 * Return the first member of the public key
	 * @return e32Bit
	 */
	public BigInteger getExponent() {
		return e32Bit;
	}
	
	/**
	 * Return the second member of the public key
	 * @return n64Bit
	 */
	public BigInteger getN() {
		return n64Bit;
	}
	
}
