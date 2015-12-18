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
import java.security.AlgorithmParameters;
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
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertPathValidatorException;

public class Cliente {
	static final String CIPHER_MODE = "AES/CTR/NoPadding";

	static DHParameterSpec dhSpec;
    static public void main(String []args) {
	try {
	    Socket s = new Socket("localhost",4567);
	    ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
	    ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
		
		
		String pass = "1234";
		char[] password = pass.toCharArray();
		String alias = "Cliente1";
		
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(new FileInputStream("Cliente.p12"), password);
		PrivateKey privkey = (PrivateKey) keyStore.getKey(alias, password);

		Certificate[] certArray = keyStore.getCertificateChain(alias);
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");  
		CertPath certPath = certFactory.generateCertPath(Arrays.asList(certArray));
		
		CertificateFactory factory = CertificateFactory.getInstance("X.509");
		Certificate cacert = factory.generateCertificate(new FileInputStream("CA.cer"));
		
		
		
		Signature sig = Signature.getInstance("SHA1withRSA");
		BigInteger bg=(BigInteger) ois.readObject();
		BigInteger bp=(BigInteger) ois.readObject();
		dhSpec = new DHParameterSpec(bg,bp);
		
		
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
		kpg.initialize(1024);
		KeyAgreement dh = KeyAgreement.getInstance("DH");
		KeyPair kp = kpg.generateKeyPair();
		PublicKey dh_alice_pub = kp.getPublic();
		oos.writeObject(dh_alice_pub);
		
		PublicKey kpb = (PublicKey) ois.readObject();
		byte[] sig_from_bob = (byte[]) ois.readObject();
		CertPath cert_from_bob = (CertPath) ois.readObject();
		
		oos.writeObject(certPath);
		
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
			CertPathValidatorResult cpvResult = cpv.validate(cert_from_bob, params);
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
		certificados = cert_from_bob.getCertificates();
		Certificate certificado = certificados.get(0);
		PublicKey pubkey = certificado.getPublicKey();
		
		
		
		
		sig.initVerify(pubkey);
        sig.update(dh_alice_pub.getEncoded());
		sig.update(kpb.getEncoded());
		if (!sig.verify(sig_from_bob)) {
			System.out.println("Aborted");
		}

		sig.initSign(privkey);
	    sig.update(dh_alice_pub.getEncoded());
		sig.update(kpb.getEncoded());
	    byte[] sig_from_alice = sig.sign();
		oos.writeObject(sig_from_alice);
        		
		
		
		dh.init(kp.getPrivate());
		Key pk = dh.doPhase(kpb, true);
		
		
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
		byte[] rawbits = sha256.digest(dh.generateSecret());
		
		Mac m = Mac.getInstance("HmacSHA1");
		SecretKey mackey = new SecretKeySpec(rawbits,16,16,"HmacSHA1");

		Cipher c = Cipher.getInstance(CIPHER_MODE);
		SecretKey key = new SecretKeySpec(rawbits,0,16,"AES");
		c.init(Cipher.ENCRYPT_MODE, key);
		byte iv[] = c.getIV();
		m.init(mackey);
		
		oos.writeObject(iv);
		
	    String test;
		BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
		byte ciphertext[];
		byte[] mac=null;
		
	    while((test=stdIn.readLine())!=null) {
			ciphertext = c.update(test.getBytes("UTF-8"));
			if(ciphertext != null){
				mac=m.doFinal(ciphertext);
				oos.writeObject(ciphertext);
				oos.writeObject(mac);
			}
	    }
		oos.writeObject(c.doFinal());
	}
	catch (Exception e){
	    e.printStackTrace();
	}
    }
}