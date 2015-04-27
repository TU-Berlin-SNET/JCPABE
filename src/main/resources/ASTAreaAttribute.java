package cpabe.policyparser;

import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.Locale;

import cpabe.policyparser.ParseException;

public class ASTAreaAttribute extends SimpleNode {
    private String name;
    private double lon1;
    private double lat1;
    private double lon2;
    private double lat2;
    
    private static NumberFormat numberFormat = DecimalFormat.getInstance(Locale.ENGLISH);
    
    public ASTAreaAttribute(int id) {
        super(id);
    }

    public ASTAreaAttribute(ParseTree p, int id) {
        super(p, id);
    }
    
    public void setValues(String name, String lon1, String lat1, String lon2, String lat2) throws ParseException {
        this.name = name;
        try {
        	this.lon1 = numberFormat.parse(lon1).doubleValue();
        	this.lat1 = numberFormat.parse(lat1).doubleValue();
        	this.lon2 = numberFormat.parse(lon2).doubleValue();
        	this.lat2 = numberFormat.parse(lat2).doubleValue();
        } catch (java.text.ParseException e) {
        	throw new ParseException("Could not parse double: "+ e.getMessage());
        }
    }
    
    
    public String getName() {
        return name;
    }
    
    public double getLatitude1() {
        return lat1;
    }
    
    public double getLongitude1() {
        return lon1;
    }
    
    public double getLatitude2() {
        return lat2;
    }
    
    public double getLongitude2() {
        return lon2;
    }
    
    public String toString() {
        return "AreaAttribute: " + name + " " + lat1 + " " + lon1 + " " + lat2 + " " + lon2;
    }
}