import java.net.*;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import javax.crypto.spec.DHParameterSpec;
import java.security.*;
import java.math.BigInteger;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Random;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

public class Servidor {

	static private int tcount;
	
    static public void main(String []args) {
	tcount = 0;
	try {
	    ServerSocket ss = new ServerSocket(4567);
		
		AlgorithmParameterGenerator gerador = AlgorithmParameterGenerator.getInstance("DH");
		gerador.init(1024);
		AlgorithmParameters parametros = gerador.generateParameters();
		DHParameterSpec dhSpec = (DHParameterSpec)parametros.getParameterSpec(DHParameterSpec.class);
		
		
	    while(true) {
		Socket s = ss.accept();
		tcount++;
		TServidor ts = new TServidor(s,tcount,dhSpec);
	        ts.start();
	    }
	}
	catch (Exception e){
	    e.printStackTrace();
	}
    }
	
	
	
}