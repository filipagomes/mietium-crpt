import java.net.*;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import javax.crypto.spec.DHParameterSpec;


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