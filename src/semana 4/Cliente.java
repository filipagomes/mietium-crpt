import java.net.*;
import java.io.*;

import java.nio.file.Paths;
import java.nio.file.Path;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.security.InvalidKeyException;
import javax.crypto.KeyGenerator;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStoreException;

public class Cliente {

    static public void main(String []args) {
		char[] password = "tpratico".toCharArray();
		PasswordProtection pass = new PasswordProtection(password);
		
	try {
	    Socket s = new Socket("localhost",4567);

	    ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
	    ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
	    String test;
		
		KeyStore keyStore = createKeyStore(args[0], "filipa");
        KeyStore.Entry entry = keyStore.getEntry("key", pass);
        SecretKey keyFound = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
        System.out.println("Found Key: " + keyFound);
        	
		
	    BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
		
	    while((test=stdIn.readLine())!=null) {
			byte[] dataIn = null;
			Cipher e = Cipher.getInstance("RC4");
			e.init(Cipher.ENCRYPT_MODE,keyFound);
			dataIn=test.getBytes();
			byte[] dataout = null;
			dataout = e.doFinal(dataIn);
			oos.writeObject(dataout);
	    }
	}
	catch (Exception e){
	    e.printStackTrace();
	}
    }
	
	private static KeyStore createKeyStore(String fileName, String pw) throws Exception {
        File file = new File(fileName);

        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        if (file.exists()) {
            keyStore.load(new FileInputStream(fileName), pw.toCharArray());
        } else {
            keyStore.load(null, null);
            keyStore.store(new FileOutputStream(fileName), pw.toCharArray());
        }

        return keyStore;
    }
}