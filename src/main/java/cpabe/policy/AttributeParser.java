package cpabe.policy;

import cpabe.policyparser.ParseException;

import java.math.BigInteger;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AttributeParser {

    private final static String name = "([a-zA-Z]\\w*)";
    private final static String numberInt = "(\\d+)";
    // <name><whitespace>*=<whitespace>*<value>
    private final static Pattern NumericalAttributePattern = Pattern.compile(name + "\\s*=\\s*" + numberInt);
    // <name>:<lat>:<lon>
    private final static String numberDouble = "(-?\\d+[\\.]\\d*)"; // needs . as a seperator
    // <name>~<lat>~<lon>
    private final static Pattern AreaAttributePattern = Pattern.compile(name + "~" + numberDouble + "~" + numberDouble);
    private static NumberFormat numberFormat = DecimalFormat.getInstance(Locale.ENGLISH);

    private static StringBuffer getNumericalAttributeResult(String attribute, String number) throws ParseException {
        ArrayList<String> attributes = new ArrayList<String>();
        BigInteger unsignedLong = new BigInteger(number);
        Long value = unsignedLong.longValue();

        if (unsignedLong.compareTo(Util.unsignedToBigInteger(value)) != 0) {
            throw new ParseException("The number for the attribute " + attribute + " is too high (" + number + ")");
        }

        for (int i = 2; i <= Util.FLEXINT_MAXBITS/2; i *= 2) {
            attributes.add(String.format((Util.isLessThanUnsigned(value, (long) 1 << i) ? "%s_lt_2^%02d" : "%s_ge_2^%02d"), attribute, i));
        }

        for (int i = 0; i < Util.FLEXINT_MAXBITS; i++) {
            attributes.add(Util.bit_marker_flexint(attribute, i, (((long) 1 << i) & value) != 0)); // alternatively unsignedLong.testBit(i)
        }

        attributes.add(String.format("%s_%s_%d", attribute, Util.FLEXINT_TYPE, Util.unsignedToBigInteger(value)));

        StringBuffer result = new StringBuffer();
        for (String s : attributes) {
            result.append(s).append(' ');
        }
        return result;
    }

    private static StringBuffer areaLocationToAttributes(String attributeName, String latString, String lonString) throws ParseException {
        double lat;
        double lon;
        try {
            lat = numberFormat.parse(latString).doubleValue();
            lon = numberFormat.parse(lonString).doubleValue();
        } catch (java.text.ParseException e) {
            throw new ParseException("Could not parse double: " + e.getMessage());
        }
        StringBuffer result = new StringBuffer();

        BigInteger convertedLatitude = Util.convertLatitudeToLong(lat);
        BigInteger convertedLongitude = Util.convertLongitudeToLong(lon);

        result.append(getNumericalAttributeResult(attributeName + "_lat", convertedLatitude.toString()));
        result.append(' ');
        result.append(getNumericalAttributeResult(attributeName + "_lng", convertedLongitude.toString()));
        return result;
    }

    public static String parseAttributes(String attributes) throws ParseException {
        attributes = attributes.replace(",", ".");
        // AttributeValue
        Matcher matched = NumericalAttributePattern.matcher(attributes);
        StringBuffer afterNumericalAttribute = new StringBuffer();
        while (matched.find()) {
            matched.appendReplacement(afterNumericalAttribute, getNumericalAttributeResult(matched.group(1), matched.group(2)).toString());
        }
        matched.appendTail(afterNumericalAttribute);

        // Areattribute
        matched = AreaAttributePattern.matcher(afterNumericalAttribute);
        StringBuffer finalResult = new StringBuffer();
        while (matched.find()) {
            matched.appendReplacement(finalResult, areaLocationToAttributes(matched.group(1), matched.group(2), matched.group(3)).toString());
        }
        matched.appendTail(finalResult);

        String finalResultAsString = finalResult.toString().replaceAll("\\s+", " ").trim();
        if (finalResultAsString.contains("=")) {
            throw new ParseException("Error occured while parsing attribute string: " + attributes);
        }
        return finalResultAsString;
    }
}
