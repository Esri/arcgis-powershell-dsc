public class FQDN {
    public static void main (String[] arg) {
		try {
            System.out.print(java.net.InetAddress.getLocalHost().getCanonicalHostName());
		} catch(Exception e){	    
		}
    }
}