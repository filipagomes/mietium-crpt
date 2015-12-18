import java.net.*;
import java.util.Random;
import java.nio.*;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import javax.crypto.*;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;



public class Gerar {
	
	static String PASSWORD = "filipa";
	char[] password1 = "tpratico".toCharArray();
    PasswordProtection pass = new PasswordProtection(password1);

	 public static void main(String args[]) throws Exception{
		
		Random rn = new Random();
		
		int eValue = rn.nextInt(100) + 30;
		int bitLength = 1024;
		BigInteger e = new BigInteger(Integer.toString(eValue));

		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(bitLength);
		KeyPair kpb = kpg.generateKeyPair();
		KeyPair kpa = kpg.generateKeyPair();
		
		PrivateKey chaveprivadaBob = kpb.getPrivate();
        byte[] privadaBob = chaveprivadaBob.getEncoded();
        PublicKey chavepublicaBob = kpb.getPublic();
        byte[] publicaBob = chavepublicaBob.getEncoded();
		FileOutputStream out = new FileOutputStream("publicaBob.txt");
        out.write(publicaBob);
        out.close();
		FileOutputStream out1 = new FileOutputStream("privadaBob.txt");
        out1.write(privadaBob);
        out1.close();
		
		
		PrivateKey chaveprivadaAlice = kpa.getPrivate();
        byte[] privadaAlice = chaveprivadaAlice.getEncoded();
        PublicKey chavepublicaAlice = kpa.getPublic();
        byte[] publicaAlice = chavepublicaAlice.getEncoded();
		FileOutputStream out2 = new FileOutputStream("publicaAlice.txt");
        out2.write(publicaAlice);
        out2.close();
		FileOutputStream out3 = new FileOutputStream("privadaAlice.txt");
        out3.write(privadaAlice);
        out3.close();
		
	}
	
	}