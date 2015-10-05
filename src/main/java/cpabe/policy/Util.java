package cpabe.policy;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.MathContext;

public class Util {

    public static final String FLEXINT_TYPE = "flexint";
    public static final int FLEXINT_MAXBITS = 64;

    public static final BigInteger MIN_FLEXINT_VALUE = BigInteger.ZERO;
    public static final BigInteger MAX_FLEXINT_VALUE = BigInteger.ONE.shiftLeft(FLEXINT_MAXBITS).subtract(BigInteger.ONE);
    private static final BigDecimal MAX_FLEXINT_VALUE_DECIMAL = new BigDecimal(MAX_FLEXINT_VALUE);

    public static final BigDecimal NINETY = BigDecimal.valueOf(90);
    public static final BigDecimal ONEHUNDREDEIGHTY = BigDecimal.valueOf(180);
    public static final BigDecimal THREEHUNDRESIXTY = BigDecimal.valueOf(360);

    private static final BigInteger BI_2_64 = BigInteger.ONE.shiftLeft(64); // only use once in long to biginteger conversion
    public static BigInteger unsignedToBigInteger(long l) {
        final BigInteger bi = BigInteger.valueOf(l);
        return l >= 0 ? bi : bi.add(BI_2_64);
    }

    public static String bit_marker_flexint(String attribute, int bit, boolean on) {
        return bit_marker(attribute, FLEXINT_TYPE, FLEXINT_MAXBITS, bit, on);
    }

    private static String bit_marker(String attribute, String type, int maxBits, int bit, boolean on) {
        if (bit >= maxBits) throw new RuntimeException("bit is greater than maxbits");
        StringBuilder result = new StringBuilder(attribute.length() + maxBits + type.length() + 2);
        StringBuilder bitmarks = new StringBuilder(maxBits + 1);
        result.append(attribute).append('_').append(type).append('_');
        for (int i = 0; i < maxBits; i++) {
            bitmarks.append('x');
        }
        bitmarks.setCharAt(maxBits - bit - 1, on ? '1' : '0');
        return result.append(bitmarks).toString();
    }

    public static boolean isLessThanUnsigned(long n1, long n2) {
        boolean comp = (n1 < n2);
        if ((n1 < 0) != (n2 < 0)) {
            comp = !comp;
        }
        return comp;
    }

    public static BigInteger convertLatitudeToLong(double lat) {
        if (Math.abs(lat) > 90) throw new IllegalArgumentException("Latitude can only be between -90 and 90");
        BigDecimal decimal = BigDecimal.valueOf(lat);
        //truncating ok, since number is always positive and would ne to be rounded down anyway
        return decimal.add(NINETY).divide(ONEHUNDREDEIGHTY, MathContext.DECIMAL128).multiply(MAX_FLEXINT_VALUE_DECIMAL).toBigInteger();
    }

    public static double convertLongToLatitude(long lat) { // only used for previewing the resulting value, and unit tests
        BigDecimal latitude = new BigDecimal(unsignedToBigInteger(lat));
        return latitude.divide(MAX_FLEXINT_VALUE_DECIMAL, MathContext.DECIMAL128).multiply(ONEHUNDREDEIGHTY).subtract(NINETY).doubleValue();
    }

    public static BigInteger convertLongitudeToLong(double lng) {
        if (Math.abs(lng) > 180) throw new IllegalArgumentException("Longitude can only be between -180 and 180");
        BigDecimal decimal = BigDecimal.valueOf(lng);
        return decimal.add(ONEHUNDREDEIGHTY).divide(THREEHUNDRESIXTY, MathContext.DECIMAL128).multiply(MAX_FLEXINT_VALUE_DECIMAL).toBigInteger();
    }

    public static double convertLongToLongitude(long lng) {
        BigDecimal latitude = new BigDecimal(unsignedToBigInteger(lng));
        return latitude.divide(MAX_FLEXINT_VALUE_DECIMAL, MathContext.DECIMAL128).multiply(THREEHUNDRESIXTY).subtract(ONEHUNDREDEIGHTY).doubleValue();
    }
}
