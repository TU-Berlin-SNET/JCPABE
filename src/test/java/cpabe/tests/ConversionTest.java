package cpabe.tests;

import cpabe.policy.Util;
import cpabe.tests.rules.Repeat;
import cpabe.tests.rules.RepeatRule;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import static org.junit.Assert.assertTrue;

public class ConversionTest {
    public static BigInteger MAX_SIGNED_LONG = BigInteger.valueOf(Long.MAX_VALUE);
    private static SecureRandom random;
    private final double epsilon = Util.FLEXINT_MAXBITS == 64 ? 1E-10 : (Util.FLEXINT_MAXBITS == 32 ? 1E-7 : 1E-2); //TODO calculate bound for 16 bits
    @Rule
    public RepeatRule repeatRule = new RepeatRule();

    @BeforeClass
    public static void testSetup() {
        random = new SecureRandom();
    }

    @Test
    @Repeat(500)
    public void longToBigIntegerConversion() {
        BigInteger testNumber = new BigInteger(Util.FLEXINT_MAXBITS, random);
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

    @Test
    @Repeat(10000)
    public void latitudeToLongConversion() {
        double latitude = random.nextDouble() * 90;
        boolean negative = random.nextBoolean();
        if (negative) latitude *= -1;
        long asLong = Util.convertLatitudeToLong(latitude).longValue();
        double asDouble = Util.convertLongToLatitude(asLong);
        if (Math.abs(latitude - asDouble) >= epsilon) {
            System.out.printf("Latitude: %f%n", latitude);
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
            System.out.printf("Longitude: %f%n", longitude);
            System.out.println("diff:" + (longitude - asDouble));
        }
        assertTrue(Math.abs(longitude - asDouble) < epsilon);
    }
}
