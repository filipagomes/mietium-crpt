/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package mycipher;

import java.io.FileOutputStream;
import java.io.IOException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;


/**
 *
 * @author Filipa
 */
public class Main {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
         
        byte[] dataout;
        byte[] ddataout;
        
        if(args[1].equals("-keygen")){
           KeyGenerator kg;
           kg = KeyGenerator.getInstance("RC4");
           kg.init(128);
           SecretKey sk = kg.generateKey();
           String alg = sk.getAlgorithm();
           byte[] bkey=sk.getEncoded();
           String filekey = args[2];
           FileOutputStream out = new FileOutputStream(filekey);
            out.write(bkey);
            out.close();}
       
        
        Cipher e = Cipher.getInstance("RC4");
        
        
        Path path = Paths.get("teste.txt");
        byte[] data = Files.readAllBytes(path);
        Path pathkey = Paths.get("chave.txt");
        byte[] chave = Files.readAllBytes(pathkey); 
        SecretKey sk1 = new SecretKeySpec(chave, alg);
        e.init(Cipher.ENCRYPT_MODE,sk);
        dataout = e.doFinal(data);
        
        
        e.init(Cipher.DECRYPT_MODE, sk1);
        ddataout=e.doFinal(dataout);
        FileOutputStream out1 = new FileOutputStream("final.txt");
        out1.write(ddataout);
        out1.close();
        
    }
    
}
