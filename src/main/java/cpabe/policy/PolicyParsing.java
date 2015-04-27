package cpabe.policy;

import java.math.BigInteger;
import java.util.List;

import ch.hsr.geohash.BoundingBox;
import ch.hsr.geohash.GeoHash;
import ch.hsr.geohash.WGS84Point;
import cpabe.AbeSettings;
import cpabe.policyparser.*;

public class PolicyParsing {
    private static final BigInteger BI_2_32 = BigInteger.ONE.shiftLeft(32);
    private static final BigInteger BI_2_16 = BigInteger.ONE.shiftLeft(16);
    private static final BigInteger BI_2_08 = BigInteger.ONE.shiftLeft(8);
    private static final BigInteger BI_2_04 = BigInteger.ONE.shiftLeft(4);
    private static final BigInteger BI_2_02 = BigInteger.ONE.shiftLeft(2);

    public static String parsePolicy(String input) throws ParseException {
    	try {
			ASTStart policy = ParseTree.createParseTree(input.replace(",", ".")); //Replacing all "," to fix locale issues
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
        } else if (current instanceof ASTGeoHashAttribute) {
        	ASTGeoHashAttribute currentChild = (ASTGeoHashAttribute) current;
        	if (currentChild.useAdjacentHashes()) {
        		handleGeoHashAttributeWithNeighbours(currentChild, retVal);
        	} else {
        		handleGeoHashAttribute(currentChild, retVal);
        	}
        } else if (current instanceof ASTAreaAttribute) {
        	handleAreaAttribute((ASTAreaAttribute) current, retVal);
        } else if (!(current instanceof ASTStart)) {
            throw new ParseException("Unknown node found in tree.");
        }

        return retVal.append(' ');
    }

	private static void handleAreaAttribute(ASTAreaAttribute current, StringBuffer retVal) throws ParseException {
		WGS84Point corner1 = new WGS84Point(current.getLatitude1(), current.getLongitude1());
		WGS84Point corner2 = new WGS84Point(current.getLatitude2(), current.getLongitude2());
		BoundingBox box = new BoundingBox(corner1, corner2);
		String attributeName = current.getName();
		double minLat = box.getMinLat();
		double maxLat = box.getMaxLat();
		double minLng = box.getMinLon();
		double maxLng = box.getMaxLon();

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

	private static void handleGeoHashAttribute(ASTGeoHashAttribute current, StringBuffer retVal) throws ParseException {
        if (current.getPrecision() > Util.GEOHASH_MAXBITS || current.getPrecision() <= 0) {
            throw new ParseException("(GeoHash precision) Only values between 1 and " + Util.GEOHASH_MAXBITS + " are supported.");
        }
        GeoHash target;
        try {
            target = GeoHash.withBitPrecision(current.getLatitude(), current.getLongitude(), current.getPrecision());
        } catch (IllegalArgumentException e) {
            throw new ParseException(e.getMessage());
        }
        handleGeoHash(target, retVal, current.getName());

        if (AbeSettings.DEBUG) {
            System.out.printf("%f,%f%n", current.getLatitude(), current.getLongitude()); // location that was initially entered
            printBoundingBox(target.getBoundingBox());
        }
    }

    private static void handleGeoHashAttributeWithNeighbours(ASTGeoHashAttribute current, StringBuffer retVal) throws ParseException {
        if (current.getPrecision() > Util.GEOHASH_MAXBITS || current.getPrecision() <= 0) {
            throw new ParseException("(GeoHash precision) Only values between 1 and " + Util.GEOHASH_MAXBITS + " are supported.");
        }
        GeoHash target;
        try {
            target = GeoHash.withBitPrecision(current.getLatitude(), current.getLongitude(), current.getPrecision());
        } catch (IllegalArgumentException e) {
            throw new ParseException(e.getMessage());
        }

        GeoHash[] adjacentFields = target.getAdjacent();

        for (GeoHash cur : adjacentFields) {
            handleGeoHash(cur, retVal, current.getName());
        }
        handleGeoHash(target, retVal, current.getName());
        retVal.append("1of9");

        if (AbeSettings.DEBUG) {
            System.out.printf("%f,%f%n", current.getLatitude(), current.getLongitude()); // location that was initially entered
            printBoundingBox(target.getBoundingBox());
            for (GeoHash cur : adjacentFields) {
                printBoundingBox(cur.getBoundingBox());
            }
        }
    }

    private static void printBoundingBox(BoundingBox box) {
        double latError = box.getLatitudeSize() / 2;
        double lonError = box.getLongitudeSize() / 2;

        double lat = box.getCenterPoint().getLatitude();
        double lon = box.getCenterPoint().getLongitude();
        System.out.printf("%f,%f%n", lat + latError, lon - lonError); // top left
        System.out.printf("%f,%f%n", lat - latError, lon - lonError); // bottom left
        System.out.printf("%f,%f%n", lat - latError, lon + lonError); // bottom right
        System.out.printf("%f,%f%n", lat + latError, lon + lonError); // top right
    }

    private static void handleGeoHash(GeoHash hash, StringBuffer retVal, String attributeName) {
        int precision = hash.significantBits();
        List<String> attributes = AttributeParser.geohashToAttributes(attributeName, hash, precision);
        for (String attribute : attributes) {
            retVal.append(attribute).append(' ');
        }
        retVal.append(precision).append("of").append(precision).append(' ');
    }

    private static void handleAttribute(ASTAttribute current, StringBuffer retVal) throws ParseException {
        retVal.append(current.getName());
    }

    private static final boolean IS_GREATER = true;
    private static final boolean IS_SMALLER = !IS_GREATER;
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
    	if (number.compareTo(Util.MIN_UNSIGNED_LONG) < 0 || number.compareTo(Util.MAX_UNSIGNED_LONG) >= 0) {
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
            retVal.append(minSatisfy + "of2 ");
        }

        // flexint_leader
        int numChildren = 0;
        for (int k = 2; k <= 32; k *= 2) {
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
            retVal.append(minSatisfyLeader + "of" + numChildren);
            retVal.append(' ');

            // p = kof2_policy(gt ? 1 : 2, l, p);
            retVal.append((greaterThan ? 1 : 2) + "of2 ");
        }

        // delete trailing space
        retVal.deleteCharAt(retVal.length() - 1);
    }

    private static void handleOf(ASTOf current, StringBuffer retVal) {
        int numChildren = current.jjtGetNumChildren();
        int minSatisfy = current.getNumber();
        retVal.append(minSatisfy + "of" + numChildren);
    }

    private static void handleExpression(ASTExpression current, StringBuffer retVal) {
        int numChildren = current.jjtGetNumChildren();
        int minSatisfy = current.getType().equalsIgnoreCase("and") ? numChildren : 1;
        retVal.append(minSatisfy + "of" + numChildren);
    }
}
