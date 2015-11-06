import java.net.*;
import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.MessageDigest;
import java.util.Arrays;

public class Cliente {
	static final String CIPHER_MODE = "AES/CTR/NoPadding";
	static final String UNSAFE_PASSWORD = "PASSWORD!!";

    static public void main(String []args) {
	try {
	    Socket s = new Socket("localhost",4567);

	    ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
	    ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
		
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
		byte[] rawbits = sha256.digest(UNSAFE_PASSWORD.getBytes("UTF-8"));
		
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