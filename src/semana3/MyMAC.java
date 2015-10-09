
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
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
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
        byte[] ddataout;
        char[] password = "tpratico".toCharArray();

        PasswordProtection pass = new PasswordProtection(password);

        if (args[0].contains("-keygen")) {
            KeyGenerator kg;
            kg = KeyGenerator.getInstance("RC4");
            kg.init(128);
            SecretKey sk = kg.generateKey();
            byte[] bkey = sk.getEncoded();
            KeyStore keyStore = createKeyStore(args[1], "filipa");
            KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(sk);
            keyStore.setEntry("key", skEntry, pass);
            //keyStore.store(new FileOutputStream(args[1]), "filipa".toCharArray());
            System.out.println("Found Key 1: " + bkey);
            String filekey = args[1];
            FileOutputStream out = new FileOutputStream(filekey);
            out.write(bkey);
            out.close();
        }

        if (args[0].contains("-enc")) {

            KeyStore keyStore = createKeyStore(args[1], "filipa");
            KeyStore.Entry entry = keyStore.getEntry("key", pass);
            SecretKey keyFound = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
            byte[] ckey = keyFound.getEncoded();
            System.out.println("Found Key: " + ckey);

            Cipher e = Cipher.getInstance("RC4");
            Path path = Paths.get(args[2]);
            byte[] data = Files.readAllBytes(path);
            e.init(Cipher.ENCRYPT_MODE, keyFound);
            dataout = e.doFinal(data);
            FileOutputStream out = new FileOutputStream(args[3]);
            out.write(dataout);
            out.close();
        }
    }

    private static KeyStore createKeyStore(String fileName, String pw) throws Exception {
        File file = new File(fileName);

        final KeyStore keyStore = KeyStore.getInstance("JCEKS");
        if (file.exists()) {
            // .keystore file already exists => load it
            keyStore.load(new FileInputStream(file), pw.toCharArray());
        } else {
            // .keystore file not created yet => create it
            keyStore.load(null, null);
            keyStore.store(new FileOutputStream(fileName), pw.toCharArray());
        }

        return keyStore;
    }

}/*


        
        
       
 if(args[0].contains("-dec")){
            
 Path pathkey = Paths.get(args[1]);
 byte[] chave = Files.readAllBytes(pathkey); 
 SecretKey sk1 = new SecretKeySpec(chave, "RC4");
 Cipher e = Cipher.getInstance("RC4");
 e.init(Cipher.DECRYPT_MODE, sk1);
            
 Path path = Paths.get(args[2]);
 byte[] data = Files.readAllBytes(path);
 dataout=e.doFinal(data);
 FileOutputStream out1 = new FileOutputStream(args[3]);
 out1.write(dataout);
 out1.close();
            
            
            
 }*/
