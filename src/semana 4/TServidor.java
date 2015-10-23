import java.net.*;
import java.io.*;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.nio.file.Files;

public class TServidor extends Thread {
	private int ct;
    protected Socket s;
	SecretKey sk;

    TServidor(Socket s, int c, SecretKey sk) {
	ct = c;
	this.s=s;
	this.sk=sk;
    }

    public void run() {
	try {
		ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
		ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
	    String test;
		
        try {
			while (true) {
				
				byte[] dataIn = null;
				dataIn = (byte[]) ois.readObject();
				Cipher e = Cipher.getInstance("RC4");
				e.init(Cipher.DECRYPT_MODE, sk);
				byte[] dataout = null;
				dataout=e.doFinal(dataIn);
				test = new String(dataout);
				System.out.println(ct + " : " + test);
			}
		} catch (EOFException e) {
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