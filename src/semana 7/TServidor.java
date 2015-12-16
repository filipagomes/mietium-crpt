import java.net.*;
import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.MessageDigest;
import java.util.Arrays;
import java.math.BigInteger;
import java.util.*;

public class TServidor extends Thread {
	private int ct;
    protected Socket s;
	static final String CIPHER_MODE = "AES/CTR/NoPadding";

    TServidor(Socket s, int c) {
	ct = c;
	this.s=s;
    }

    public void run() {
	try {
		ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
		ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
		
		BigInteger bg= new BigInteger("44157404837960328768872680677686802650999163226766694797650810379076416463147265401084491113667624054557335394761604876882446924929840681990106974314935015501571333024773172440352475358750668213444607353872754650805031912866692119819377041901642732455911509867728218394542745330014071040326856846990119719675");
		BigInteger bp= new BigInteger("99494096650139337106186933977618513974146274831566768179581759037259788798151499814653951492724365471316253651463342255785311748602922458795201382445323499931625451272600173180136123245441204133515800495917242011863558721723303661523372572477211620144038809673692512025566673746993593384600667047373692203583");
		BigInteger y= new BigInteger(16,1,new Random());
		BigInteger gy = bg.modPow(y,bp);
		
		
		
		BigInteger gx = (BigInteger) ois.readObject();
		System.out.println("gx");
		System.out.println(gx);
		
		System.out.println("gy");
		System.out.println(gy);
		
		oos.writeObject(gy);

		BigInteger K = gx.modPow(y,bp);
		System.out.println("K");
		System.out.println(K);
		
		String PASSWORD = K.toString();
		
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
		byte[] rawbits = sha256.digest(PASSWORD.getBytes("UTF-8"));

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