/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
//package mycipher;

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
        
        //String argumento = args[0];
        //System.out.println(argumento);
        if(args[0].contains("-keygen")){
           KeyGenerator kg;
           kg = KeyGenerator.getInstance("RC4");
           kg.init(128);
           SecretKey sk = kg.generateKey();
           byte[] bkey=sk.getEncoded();
           String filekey = args[1];
           FileOutputStream out = new FileOutputStream(filekey);
           out.write(bkey);
           out.close();
        }
        
        if (args[0].contains("-enc")){
            Cipher e = Cipher.getInstance("RC4");
        Path path = Paths.get(args[2]);
        byte[] data = Files.readAllBytes(path);
        Path pathkey = Paths.get(args[1]);
        byte[] chave = Files.readAllBytes(pathkey); 
        SecretKey sk1 = new SecretKeySpec(chave, "RC4");
        e.init(Cipher.ENCRYPT_MODE,sk1);
        dataout = e.doFinal(data);
        FileOutputStream out = new FileOutputStream(args[3]);
        out.write(dataout);
        out.close();            
        }
       
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
            
            
            
        }
        
        
        
        
        
        /*
        
        
        e.init(Cipher.DECRYPT_MODE, sk1);
        ddataout=e.doFinal(dataout);
        FileOutputStream out1 = new FileOutputStream("final.txt");
        out1.write(ddataout);
        out1.close();
        */
    }
    
    
    
}
