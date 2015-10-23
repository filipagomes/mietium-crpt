import java.net.*;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStoreException;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.File;

public class Servidor {

	static private int tcount;
	
	
	
    static public void main(String []args) {
	tcount = 0;
	try {
	    ServerSocket ss = new ServerSocket(4567);
		char[] password = "tpratico".toCharArray();
		PasswordProtection pass = new PasswordProtection(password);
		KeyGenerator kg;
        kg = KeyGenerator.getInstance("RC4");
        kg.init(64);
        SecretKey sk = kg.generateKey();
        byte[] bkey = sk.getEncoded();
		//guarda na KeyStore
        KeyStore keyStore = createKeyStore(args[0], "filipa");
        KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(sk);
        keyStore.setEntry("key", skEntry, pass);
        keyStore.store(new FileOutputStream(args[0]), "filipa".toCharArray());
		//apenas para teste
        System.out.println("Found Key 1: " + sk);
	    
	    while(true) {
		Socket s = ss.accept();
		tcount++;
		TServidor ts = new TServidor(s,tcount, sk);
	        ts.start();
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