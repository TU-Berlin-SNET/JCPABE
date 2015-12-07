package cpabe.policy;

import cpabe.policyparser.*;

import java.math.BigInteger;

public class PolicyParsing {
    private static final BigInteger BI_2_32 = BigInteger.ONE.shiftLeft(32);
    private static final BigInteger BI_2_16 = BigInteger.ONE.shiftLeft(16);
    private static final BigInteger BI_2_08 = BigInteger.ONE.shiftLeft(8);
    private static final BigInteger BI_2_04 = BigInteger.ONE.shiftLeft(4);
    private static final BigInteger BI_2_02 = BigInteger.ONE.shiftLeft(2);

    private static final boolean IS_GREATER = true;
    private static final boolean IS_SMALLER = !IS_GREATER;

    public static String parsePolicy(String input) throws ParseException {
        try {
            ASTStart policy = ParseTree.createParseTree(input);
            return postFix(policy);
        } catch (TokenMgrError e) {
            throw new ParseException(e.getMessage());
        }
    }

    private static String postFix(ASTStart root) throws ParseException {
        return postFix_m(root).toString().trim();
    }

    private static StringBuffer postFix_m(Node current) throws ParseException {
        StringBuffer retVal = new StringBuffer(2000);

        for (int i = 0; i < current.jjtGetNumChildren(); i++) {
            Node child = current.jjtGetChild(i);
            retVal.append(postFix_m(child));
        }

        if (current instanceof ASTExpression) {
            handleExpression((ASTExpression) current, retVal);
        } else if (current instanceof ASTOf) {
            handleOf((ASTOf) current, retVal);
        } else if (current instanceof ASTAttribute) {
            handleAttribute((ASTAttribute) current, retVal);
        } else if (current instanceof ASTNumericalAttribute) {
            handleNumericalAttribute((ASTNumericalAttribute) current, retVal);
        } else if (current instanceof ASTAreaAttribute) {
            handleAreaAttribute((ASTAreaAttribute) current, retVal);
        } else if (!(current instanceof ASTStart)) {
            throw new ParseException("Unknown node found in tree.");
        }

        return retVal.append(' ');
    }

    private static void handleAreaAttribute(ASTAreaAttribute current, StringBuffer retVal) throws ParseException {
        String attributeName = current.getName();
        double minLat = Math.min(current.getLatitude1(), current.getLatitude2());
        double maxLat = Math.max(current.getLatitude1(), current.getLatitude2());
        double minLng = Math.min(current.getLongitude1(), current.getLongitude2());
        double maxLng = Math.max(current.getLongitude1(), current.getLongitude2());

        BigInteger minLngConverted = Util.convertLongitudeToLong(minLng);
        BigInteger maxLngConverted = Util.convertLongitudeToLong(maxLng);
        BigInteger minLatConverted = Util.convertLatitudeToLong(minLat);
        BigInteger maxLatConverted = Util.convertLatitudeToLong(maxLat);

        handleNumericalAttribute(attributeName + "_lng", IS_GREATER, minLngConverted.subtract(BigInteger.ONE), retVal);
        retVal.append(' ');
        handleNumericalAttribute(attributeName + "_lng", IS_SMALLER, maxLngConverted.add(BigInteger.ONE), retVal);
        retVal.append(' ');
        handleNumericalAttribute(attributeName + "_lat", IS_GREATER, minLatConverted.subtract(BigInteger.ONE), retVal);
        retVal.append(' ');
        handleNumericalAttribute(attributeName + "_lat", IS_SMALLER, maxLatConverted.add(BigInteger.ONE), retVal);
        retVal.append(' ');
        retVal.append("4of4");

        // a location is always <name>_lng = number and <name>_lat = number
        // resulting policy shoud be: <name>_lng >= minLng && <name>_lng <= maxLng && <name>_lat >= minLat && <name>_lat <= maxLat
    }

    private static void handleAttribute(ASTAttribute current, StringBuffer retVal) throws ParseException {
        retVal.append(current.getName());
    }

    private static void handleNumericalAttribute(ASTNumericalAttribute current, StringBuffer retVal) throws ParseException {
        BigInteger bigValue = current.getValue();
        if (current.getOp().equals("=")) {
            retVal.append(String.format("%s_%s_%s", current.getName(), Util.FLEXINT_TYPE, bigValue.toString()));
        } else if (current.getOp().equals("<")) {
            handleNumericalAttribute(current.getName(), IS_SMALLER, bigValue, retVal);
        } else if (current.getOp().equals(">")) {
            handleNumericalAttribute(current.getName(), IS_GREATER, bigValue, retVal);
        } else if (current.getOp().equals("<=")) {
            handleNumericalAttribute(current.getName(), IS_SMALLER, bigValue.add(BigInteger.ONE), retVal);
        } else if (current.getOp().equals(">=")) {
            handleNumericalAttribute(current.getName(), IS_GREATER, bigValue.subtract(BigInteger.ONE), retVal);
        } else {
            throw new ParseException("Unknown comparison operator found.");
        }
    }

    private static void handleNumericalAttribute(String name, boolean greaterThan, BigInteger number, StringBuffer retVal) throws ParseException {
        if (number.compareTo(Util.MIN_FLEXINT_VALUE) < 0 || number.compareTo(Util.MAX_FLEXINT_VALUE) >= 0) {
            throw new ParseException("Only non-negative numbers until 2^64 - 1 are supported. Current number: " + number);
        }

        long numberLong = number.longValue();

        // bit_marker_list()
        int bits = (number.compareTo(BI_2_32) >= 0 ? 64 :
                number.compareTo(BI_2_16) >= 0 ? 32 :
                        number.compareTo(BI_2_08) >= 0 ? 16 :
                                number.compareTo(BI_2_04) >= 0 ? 8 :
                                        number.compareTo(BI_2_02) >= 0 ? 4 : 2);
        int i = 0;
        if (greaterThan) {
            while ((1L << i & numberLong) != 0) i++;
        } else {
            while ((1L << i & numberLong) == 0) i++;
        }
        retVal.append(Util.bit_marker_flexint(name, i, greaterThan));
        retVal.append(' ');
        for (i = i + 1; i < bits; i++) {
            int minSatisfy;
            if (greaterThan) {
                minSatisfy = (1L << i & numberLong) != 0 ? 2 : 1;
            } else {
                minSatisfy = (1L << i & numberLong) != 0 ? 1 : 2;
            }
            retVal.append(Util.bit_marker_flexint(name, i, greaterThan));
            retVal.append(' ');
            retVal.append(minSatisfy).append("of2 ");
        }

        // flexint_leader
        int numChildren = 0;
        for (int k = 2; k <= Util.FLEXINT_MAXBITS/2; k *= 2) {
            BigInteger bi_2_k = BigInteger.ONE.shiftLeft(k);
            if (greaterThan && bi_2_k.compareTo(number) > 0) {
                retVal.append(String.format("%s_ge_2^%02d ", name, k));
                numChildren++;
            } else if (!greaterThan && bi_2_k.compareTo(number) >= 0) {
                retVal.append(String.format("%s_lt_2^%02d ", name, k));
                numChildren++;
            }
        }

        int minSatisfyLeader = greaterThan ? 1 : numChildren;
        if (numChildren != 0) {
            // also part of flexint_leader
            if (!(minSatisfyLeader == 1 && numChildren == 1))
                retVal.append(minSatisfyLeader).append("of").append(numChildren).append(' ');

            // p = kof2_policy(gt ? 1 : 2, l, p);
            retVal.append(greaterThan ? 1 : 2).append("of2 ");
        }

        // delete trailing space
        retVal.deleteCharAt(retVal.length() - 1);
    }

    private static void handleOf(ASTOf current, StringBuffer retVal) {
        int numChildren = current.jjtGetNumChildren();
        int minSatisfy = current.getNumber();
        retVal.append(minSatisfy).append("of").append(numChildren);
    }

    private static void handleExpression(ASTExpression current, StringBuffer retVal) {
        int numChildren = current.jjtGetNumChildren();
        int minSatisfy = current.getType().equalsIgnoreCase("and") ? numChildren : 1;
        retVal.append(minSatisfy).append("of").append(numChildren);
    }
}
