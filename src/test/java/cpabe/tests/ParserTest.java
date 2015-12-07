package cpabe.tests;

import cpabe.policy.AttributeParser;
import cpabe.policy.PolicyParsing;
import cpabe.policyparser.ParseException;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class ParserTest {
    @Test
    public void attributeParserWhitespaceTest() throws ParseException {
        String attributes1 = "att1        att2";
        String attributes2 = "att1\t\n\f\r\t\tatt2";

        String parsed1 = AttributeParser.parseAttributes(attributes1);
        String parsed2 = AttributeParser.parseAttributes(attributes2);

        assertEquals(parsed1, "att1 att2");
        assertEquals(parsed2, "att1 att2");
    }

    @Test
    public void parseLocations() throws ParseException {
        PolicyParsing.parsePolicy("location~12.00~12.00~12.00~12.00");
        PolicyParsing.parsePolicy("location~12,00~12,00~12,00~12,00");
    }

    @Test(expected = ParseException.class)
    public void parseInvalidLocation() throws ParseException {
        PolicyParsing.parsePolicy("location~12.0.0~12.00~12.00~12.00");
    }

    @Test
    public void parseTreshold() throws ParseException {
        PolicyParsing.parsePolicy("2 of (att1, att2, att3)");
    }


    @Test(expected = ParseException.class)
    public void attributeParserInvalidNumberTest() throws ParseException {
        System.out.println("Parsed as: " + AttributeParser.parseAttributes("att1 = -5"));
    }

    @Test(expected = ParseException.class)
    public void attributeParserEqualSignTest() throws ParseException {
        System.out.println("Parsed as: " + AttributeParser.parseAttributes("att1 = test"));
    }

}
