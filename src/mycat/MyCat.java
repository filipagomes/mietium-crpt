import java.util.Scanner;

/**
 *
 * @author Filipa
 */
public class Mycat {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
    Scanner ler = new Scanner(System.in);
        String cat;
        do{
        cat = ler.nextLine();
        System.out.println(cat);
    }
        while(cat.length()>0);
    }
    
}
