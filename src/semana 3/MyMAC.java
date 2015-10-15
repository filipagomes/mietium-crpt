
//package mymac;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.security.cert.Certificate;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Filipa
 */
public class MyMAC {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception {

        byte[] dataout;
        byte[] ddataout = null;
        char[] password = "tpratico".toCharArray();


        PasswordProtection pass = new PasswordProtection(password);

        if (args[0].contains("-keygen")) {
			//gera chave
            KeyGenerator kg;
            kg = KeyGenerator.getInstance("AES");
            kg.init(128);
            SecretKey sk = kg.generateKey();
            byte[] bkey = sk.getEncoded();
			//guarda na KeyStore
            KeyStore keyStore = createKeyStore(args[1], "filipa");
            KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(sk);
            keyStore.setEntry("key", skEntry, pass);
            keyStore.store(new FileOutputStream(args[1]), "filipa".toCharArray());
			//apenas para teste
            System.out.println("Found Key 1: " + sk);
        }

        if (args[0].contains("-enc")) {

            //vai buscar chave a keystore
			KeyStore keyStore = createKeyStore(args[1], "filipa");
            KeyStore.Entry entry = keyStore.getEntry("key", pass);
            SecretKey keyFound = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
			//apenas para teste
            System.out.println("Found Key: " + keyFound);
			//inicia mac
            Mac hmacMd5=Mac.getInstance("HMACMD5");
			hmacMd5.init(keyFound);
			//vai buscar IV e ficheiro
            Path pathiv = Paths.get("ivSpec.txt");
            byte[] iv = Files.readAllBytes(pathiv);
			Path path = Paths.get(args[2]);
            byte[] data = Files.readAllBytes(path);
            IvParameterSpec ivSpec=new IvParameterSpec(iv);
            //inicia cifra
            Cipher e = Cipher.getInstance("AES/CBC/PKCS5Padding");
            e.init(Cipher.ENCRYPT_MODE, keyFound, ivSpec);
            dataout = e.doFinal(data);
            ddataout=hmacMd5.doFinal(dataout);
			//junta data e mac
            byte[] datafinal= new byte[dataout.length + hmacMd5.getMacLength()];
            System.arraycopy(dataout, 0, datafinal, 0, dataout.length);
            System.arraycopy(ddataout, 0, datafinal, dataout.length, ddataout.length);
            System.out.println(hmacMd5.getMacLength());
            FileOutputStream out = new FileOutputStream(args[3]);
            out.write(datafinal);
            out.close();
        }

        if (args[0].contains("-dec")) {
            byte[] datamac = null;
            byte[] dataMacIn;
            KeyStore keyStore = createKeyStore(args[1], "filipa");
            KeyStore.Entry entry = keyStore.getEntry("key", pass);
            SecretKey keyFound = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
            Mac hmacMd5=Mac.getInstance("HMACMD5");
            hmacMd5.init(keyFound);
            System.out.println("Found Key: " + keyFound);
            Path pathiv = Paths.get("ivSpec.txt");
            byte[] iv = Files.readAllBytes(pathiv);
            IvParameterSpec ivSpec=new IvParameterSpec(iv);
            Cipher e = Cipher.getInstance("AES/CBC/PKCS5Padding");
            e.init(Cipher.DECRYPT_MODE, keyFound, ivSpec);
            Path path = Paths.get(args[2]);
            byte[] data = Files.readAllBytes(path);
            dataout=hmacMd5.doFinal(data);
            int len = hmacMd5.getMacLength();
            System.out.println(data.length);
            System.out.println(len);
            ddataout = Arrays.copyOfRange(data, 0, 32);
			System.out.println(data.length);
			datamac = Arrays.copyOfRange(data, 32,48);
            dataMacIn=hmacMd5.doFinal(ddataout);
            if(datamac==dataMacIn){
				byte[] datafinal = e.doFinal(ddataout);
				FileOutputStream out1 = new FileOutputStream(args[3]);
				out1.write(datafinal);
				out1.close();}
            else{
                byte[] datafinal = e.doFinal(ddataout);
				FileOutputStream out1 = new FileOutputStream(args[3]);
				out1.write(datafinal);
				out1.close();
                System.out.println("nadaaa");}

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
