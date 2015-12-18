import java.net.*;
import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.util.Arrays;
import java.math.BigInteger;
import java.util.*;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.interfaces.*;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.security.Key;
import java.nio.file.Files;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.interfaces.*;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.TrustAnchor;
import java.security.cert.PKIXParameters;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;


public class TServidor extends Thread {
	private int ct;
    protected Socket s;
	static final String CIPHER_MODE = "AES/CTR/NoPadding";
	static DHParameterSpec dhSpec;

    TServidor(Socket s, int c, DHParameterSpec dhSpec) {
	ct = c;
	this.s=s;
	this.dhSpec=dhSpec;
    }

    public void run(){
	try {
		
		
		
		String pass = "1234";
		char[] password = pass.toCharArray();
		String alias = "Servidor";
		
		ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
		ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
		
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(new FileInputStream("Servidor.p12"), password);
		PrivateKey privkey = (PrivateKey) keyStore.getKey(alias, password);

		Certificate[] certArray = keyStore.getCertificateChain(alias);
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");  
		CertPath certPath = certFactory.generateCertPath(Arrays.asList(certArray));
		
		
		CertificateFactory factory = CertificateFactory.getInstance("X.509"); 
		Certificate cacert = factory.generateCertificate(new FileInputStream("CA.cer"));
		
		BigInteger bg= dhSpec.getG();
		BigInteger bp= dhSpec.getP();
		oos.writeObject(bg);
		oos.writeObject(bp);
		
	
		Signature sig = Signature.getInstance("SHA1withRSA");
		
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
		kpg.initialize(1024);
		PublicKey kpa = (PublicKey)ois.readObject();
		KeyAgreement dh = KeyAgreement.getInstance("DH");
		KeyPair kp = kpg.generateKeyPair();
		PublicKey dh_bob_pub = kp.getPublic();
		oos.writeObject(dh_bob_pub);
				
		sig.initSign(privkey);
	    sig.update(kpa.getEncoded());
		sig.update(dh_bob_pub.getEncoded());
	    byte[] sig_from_bob = sig.sign();
		oos.writeObject(sig_from_bob);
		oos.writeObject(certPath);
		
		CertPath cert_from_alice = (CertPath) ois.readObject();
		
		CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
		// TrustAnchor representa os pressupostos de confiança que se aceita como válidos
		// (neste caso, unicamente a CA que emitiu os certificados)
		TrustAnchor anchor = new TrustAnchor((X509Certificate) cacert, null);
		// Podemos também configurar o próprio processo de validação
		// (e.g. requerer a presença de determinada extensão).
		PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
		// ...no nosso caso, vamos simplesmente desactivar a verificação das CRLs
		params.setRevocationEnabled(false);
		// Finalmente a validação propriamente dita...
		try {
			CertPathValidatorResult cpvResult = cpv.validate(cert_from_alice, params);
			System.out.println("SE CHEGOU AQUI, TUDO DEVE TER CORRIDO BEM!!!");
		} catch (InvalidAlgorithmParameterException iape) {
			System.err.println("Erro de validação: " + iape);
			System.exit(1);
		} catch (CertPathValidatorException cpve) {
			System.err.println("FALHA NA VALIDAÇÃO: " + cpve);
			System.err.println("Posição do certificado causador do erro: "
                + cpve.getIndex());
		}
		
		List<? extends Certificate> certificados; 
		certificados = new ArrayList<Certificate>();
		certificados = cert_from_alice.getCertificates();
		Certificate certificado = certificados.get(0);
		PublicKey pubkey = certificado.getPublicKey();
		
		byte[] sig_from_alice = (byte[]) ois.readObject();
		sig.initVerify(pubkey);
        sig.update(kpa.getEncoded());
		sig.update(dh_bob_pub.getEncoded());
		if (!sig.verify(sig_from_alice)) {
			System.out.println("Aborted");
		}

		
		
		dh.init(kp.getPrivate());
		Key pk = dh.doPhase(kpa, true);
		
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
		byte[] rawbits = sha256.digest(dh.generateSecret());

		Cipher c = Cipher.getInstance(CIPHER_MODE);
		SecretKey key = new SecretKeySpec(rawbits,0,16,"AES");
		byte ivbits[] = (byte[]) ois.readObject();
		IvParameterSpec iv = new IvParameterSpec(ivbits);
		c.init(Cipher.DECRYPT_MODE, key, iv);
		
		Mac m = Mac.getInstance("HmacSHA1");
		SecretKey mackey = new SecretKeySpec(rawbits,16,16,"HmacSHA1");
		m.init(mackey);
		
		byte ciphertext[], cleartext[], mac[];
	    try {
			while (true) {
				ciphertext = (byte[]) ois.readObject();
				mac = (byte[])ois.readObject();
				if(Arrays.equals(mac, m.doFinal(ciphertext))){
					cleartext = c.update(ciphertext);
					System.out.println(ct + " : " + new String(cleartext, "UTF-8"));
				}
				else{
					//System.exit(1);
					System.out.println(ct + "error");
				}
			}
		} catch (EOFException e) {
			cleartext = c.doFinal();
			System.out.println(ct + " : " + new String(cleartext, "UTF-8"));
			System.out.println("["+ct + "]");
		} finally {
		if (ois!=null) ois.close();
		if (oos!=null) oos.close();
	}
	} catch (Exception e) {
	    e.printStackTrace();
	} 
    }
}