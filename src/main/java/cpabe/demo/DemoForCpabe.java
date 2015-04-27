package cpabe.demo;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Method;
import java.util.logging.Level;
import java.util.logging.Logger;

import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import cpabe.Cpabe;
import cpabe.policy.PolicyParsing;
import cpabe.policy.Util;

public class DemoForCpabe {
	static File directory					 = new File("examples");
    static File pubfile                      = new File(directory + "/public_key");
    static File mskfile                      = new File(directory + "/secret_master_key");
    static File prvfile                      = new File(directory + "/private_key");

    static File inputfile                    = new File(directory + "/input.txt");
    static File encfile                      = new File(directory + "/input.txt.enc");
    static File decfile                      = new File(directory + "/input.txt.dec");

    static String attribute_test4            = "test = 4";
    static String attribute_test5            = "test = 5";
    static String attribute_test6            = "test = 6";
    static String policy_test                = "test <= 5";

    // location = schwerin oder location = berlin (beides eher grob)
    static String geoHash_policy             = "(location:52.52:13.405:20:1 or location:53.63:11.40:24:1)";
    static String geoHash_attribute_schwerin = "location:53.62511:11.41783";
    static String geoHash_attribute_berlin   = "location:52.51300:13.32020";
    static String geoHash_attribute_hamburg  = "location:53.54373:9.98850";
    
    public static void prepareDirectory() throws IOException {
    	directory.mkdirs();
        inputfile.delete();
        try (PrintWriter out = new PrintWriter(inputfile)) {
        	out.println("some secret data");
        }
    }

    public static void main(String[] args) throws Exception {
        String attributes = geoHash_attribute_schwerin;
        String policy = geoHash_policy;
        prepareDirectory();

        long timeStart = System.currentTimeMillis();
        Cpabe.setup(pubfile, mskfile);
        Cpabe.encrypt(pubfile, policy, inputfile, encfile);
        Cpabe.keygen(prvfile, mskfile, attributes);
        Cpabe.decrypt(prvfile, encfile, decfile);
        long timeEnd = System.currentTimeMillis();
        
        
        System.out.println(String.format("this operation took %d ms.", timeEnd - timeStart));
        System.out.println("wasPbcAvailable? "+PairingFactory.getInstance().isPBCAvailable());
        
        System.out.println( Util.unsignedToBigInteger(-1L));
        System.out.println(Util.unsignedToBigInteger(-1L).testBit(0));
        System.out.println(1L & Long.MIN_VALUE);
        PolicyParsing.parsePolicy("asd > " + Util.unsignedToBigInteger(-2));
        
        double latitude1 = Util.convertLongToLatitude(0);
        double latitude2 = Util.convertLongToLatitude(50000);
        System.out.printf("Difference: %.60f%n", (latitude1 - latitude2));
    }
}
