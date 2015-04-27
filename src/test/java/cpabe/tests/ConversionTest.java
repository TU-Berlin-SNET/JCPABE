package cpabe.tests;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.security.SecureRandom;

import cpabe.policy.Util;
import cpabe.tests.rules.Repeat;
import cpabe.tests.rules.RepeatRule;

import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

public class ConversionTest {
    private static SecureRandom random;
    
    @Rule public RepeatRule repeatRule = new RepeatRule();

    @BeforeClass
    public static void testSetup() {
        random = new SecureRandom();
    }
	
    public static BigInteger MAX_SIGNED_LONG = BigInteger.valueOf(Long.MAX_VALUE);
    @Test
    @Repeat(500)
    public void longToBigIntegerConversion() {
    	BigInteger testNumber = new BigInteger(64, random);
    	long numberAsLong = testNumber.longValue();
    	BigInteger asBigInt = Util.unsignedToBigInteger(numberAsLong);
    	if (testNumber.compareTo(MAX_SIGNED_LONG) > 0) {
    		assertTrue(numberAsLong < 0);
    	} else {
    		assertTrue(numberAsLong >= 0);
    	}
    	assertTrue(testNumber.compareTo(asBigInt) == 0);
    	assertTrue(asBigInt.longValue() == numberAsLong);
    }
    
    
    private final double epsilon = 1E-10;
    @Test
    @Repeat(10000)
    public void latitudeToLongConversion() {
    	double latitude = random.nextDouble() * 90;
    	boolean negative = random.nextBoolean();
    	if (negative) latitude *= -1;
    	long asLong = Util.convertLatitudeToLong(latitude).longValue();
    	double asDouble = Util.convertLongToLatitude(asLong);
    	if (Math.abs(latitude - asDouble) >= epsilon) {
    		System.out.println("diff:" + (latitude - asDouble));
    	}
    	assertTrue(Math.abs(latitude - asDouble) < epsilon);
    }
    
    @Test
    @Repeat(10000)
    public void longitudeToLongConversion() {
    	double longitude = random.nextDouble() * 180;
    	boolean negative = random.nextBoolean();
    	if (negative) longitude *= -1;
    	long asLong = Util.convertLongitudeToLong(longitude).longValue();
    	double asDouble = Util.convertLongToLongitude(asLong);
    	if (Math.abs(longitude - asDouble) >= epsilon) {
    		System.out.println("diff:" + (longitude - asDouble));
    	}
    	assertTrue(Math.abs(longitude - asDouble) < epsilon);
    }
}
