import java.net.*;
import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.MessageDigest;
import java.util.Arrays;

public class TServidor extends Thread {
	private int ct;
    protected Socket s;
	static final String CIPHER_MODE = "AES/CTR/NoPadding";
	static final String UNSAFE_PASSWORD = "PASSWORD!!";

    TServidor(Socket s, int c) {
	ct = c;
	this.s=s;
    }

    public void run() {
	try {
		ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
		ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
		
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
		byte[] rawbits = sha256.digest(UNSAFE_PASSWORD.getBytes("UTF-8"));

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