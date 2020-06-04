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
	
	private static BigInteger two = new BigInteger("2");
	
	// Private method to find the exponent e
	private static BigInteger eSelection(BigInteger phiN64Bit) {
		Random rnd = new Random();
		BigInteger e32Bit;
		
		// Until e <= 1 or e > phiN or gcd(e, phiN) != 1
		do {
			e32Bit = new BigInteger(32, rnd);
		} while((e32Bit.compareTo(BigInteger.ONE) <= 0 || e32Bit.compareTo(phiN64Bit) >= 0) || 
				!e32Bit.gcd(phiN64Bit).equals(BigInteger.ONE) ||
				e32Bit.equals(phiN64Bit.add(two).divide(two)));
		
		return e32Bit;
	}
	
	/**
	 * Initialize an RSA Object that can be used to Encrypt and Decrypt messages
	 * with random (and odds) p and q
	 */
	public RSA(BigInteger e32Bit) {
		Random rnd = new Random();
		
		// Generate random p and q 
		do {
			p32Bit = BigInteger.probablePrime(32, rnd);
			q32Bit = BigInteger.probablePrime(32, rnd);
		} while(p32Bit.equals(q32Bit));
		
		// Compute n = p * q 
		n64Bit = p32Bit.multiply(q32Bit);
		
		// Compute phiN = (p - 1) * (q - 1)
		phiN64Bit = p32Bit.subtract(BigInteger.ONE).multiply(q32Bit.subtract(BigInteger.ONE));
						
		// Compute e
		if(e32Bit == null)
			this.e32Bit = eSelection(phiN64Bit);
		else
			this.e32Bit = e32Bit;
						
		// Compute d = e ^ (-1) mod phiN
		privateKey = this.e32Bit.modInverse(phiN64Bit);
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