import java.math.BigInteger;
import java.net.*;
import java.io.*;
import java.util.*;

public class BigA{
	
	
	static public void main(String []args) throws Exception{
		
		BigInteger bg= new BigInteger("44157404837960328768872680677686802650999163226766694797650810379076416463147265401084491113667624054557335394761604876882446924929840681990106974314935015501571333024773172440352475358750668213444607353872754650805031912866692119819377041901642732455911509867728218394542745330014071040326856846990119719675");
		BigInteger bp= new BigInteger("99494096650139337106186933977618513974146274831566768179581759037259788798151499814653951492724365471316253651463342255785311748602922458795201382445323499931625451272600173180136123245441204133515800495917242011863558721723303661523372572477211620144038809673692512025566673746993593384600667047373692203583");
		BigInteger x= new BigInteger(16,1,new Random());
		BigInteger gx = bg.modPow(x,bp); 
		
		Socket s = new Socket("localhost",4567);

	    ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
	    ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
		
		oos.writeObject(gx);
		System.out.println("gx");
		System.out.println(gx);
		ServerSocket ss = new ServerSocket(4566);
		
		Socket sa = ss.accept();
		
		BigInteger gy = (BigInteger) ois.readObject();
		System.out.println("gy");
		System.out.println(gy);
		
		BigInteger K = gy.modPow(x,bp);
		System.out.println("K");
		System.out.println(K);
	}
	
}