package rsa_attacks;

public class Testing {

	public static void main(String[] args) {
		RSA rsaObj = new RSA(null);
		rsaObj.printInfo();
		
		RsaAttacker.bruteForceAttack(rsaObj.getExponent(), rsaObj.getN());

		RsaAttacker.fermatFactoringAttack(rsaObj.getExponent(), rsaObj.getN());
	}
}
