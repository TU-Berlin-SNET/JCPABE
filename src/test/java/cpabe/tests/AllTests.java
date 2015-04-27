package cpabe.tests;

import org.junit.runners.Suite;
import org.junit.runner.RunWith;

@RunWith(Suite.class)
@Suite.SuiteClasses({ Bsw07Test.class, AesTest.class, ParserTest.class, WeberTest.class, ConversionTest.class, AreaAttributeTest.class, SerializationTests.class })
public class AllTests {

}
