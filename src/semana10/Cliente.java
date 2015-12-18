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

public class Cliente {
	static final String CIPHER_MODE = "AES/CTR/NoPadding";

	static DHParameterSpec dhSpec;
    static public void main(String []args) {
	try {
	    Socket s = new Socket("localhost",4567);
	    ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
	    ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
		
		Path path = Paths.get("publicaBob.txt");
		byte[] chavepublicaBobbytes = Files.readAllBytes(path);
		Path path1 = Paths.get("privadaAlice.txt");
		byte[] chaveprivadaAlicebytes = Files.readAllBytes(path1);
		
		KeyFactory kfactory = KeyFactory.getInstance("RSA");
		
		PrivateKey privateAlice = kfactory.generatePrivate(new PKCS8EncodedKeySpec(chaveprivadaAlicebytes));
		PublicKey publicBob = kfactory.generatePublic(new X509EncodedKeySpec(chavepublicaBobbytes));
		
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
		
		sig.initVerify(publicBob);
        sig.update(dh_alice_pub.getEncoded());
		sig.update(kpb.getEncoded());
		if (!sig.verify(sig_from_bob)) {
			System.out.println("Aborted");
		}

		sig.initSign(privateAlice);
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