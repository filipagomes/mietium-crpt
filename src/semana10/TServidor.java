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
		
		
		ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
		ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
		
		BigInteger bg= dhSpec.getG();
		BigInteger bp= dhSpec.getP();
		oos.writeObject(bg);
		oos.writeObject(bp);
		
		Path path = Paths.get("publicaAlice.txt");
		byte[] chavepublicaAlicebytes = Files.readAllBytes(path);
		Path path1 = Paths.get("privadaBob.txt");
		byte[] chaveprivadaBobbytes = Files.readAllBytes(path1);
		
		KeyFactory kfactory = KeyFactory.getInstance("RSA");
		
		PrivateKey privateBob = kfactory.generatePrivate(new PKCS8EncodedKeySpec(chaveprivadaBobbytes));
		PublicKey publicaAlice = kfactory.generatePublic(new X509EncodedKeySpec(chavepublicaAlicebytes));
		
		Signature sig = Signature.getInstance("SHA1withRSA");
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
		kpg.initialize(1024);
		PublicKey kpa = (PublicKey)ois.readObject();
		KeyAgreement dh = KeyAgreement.getInstance("DH");
		KeyPair kp = kpg.generateKeyPair();
		PublicKey dh_bob_pub = kp.getPublic();
		oos.writeObject(dh_bob_pub);
		
		
		sig.initSign(privateBob);
	    sig.update(kpa.getEncoded());
		sig.update(dh_bob_pub.getEncoded());
	    byte[] sig_from_bob = sig.sign();
		oos.writeObject(sig_from_bob);
		
		byte[] sig_from_alice = (byte[]) ois.readObject();
		
		sig.initVerify(publicaAlice);
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