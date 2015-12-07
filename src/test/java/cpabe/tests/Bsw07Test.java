package cpabe.tests;

import cpabe.*;
import cpabe.policy.Util;
import cpabe.tests.rules.Repeat;
import cpabe.tests.rules.RepeatRule;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class Bsw07Test {

    private static SecureRandom random;

    @Rule
    public RepeatRule repeatRule = new RepeatRule();

    @BeforeClass
    public static void testSetup() {
        random = new SecureRandom();
    }

    // so we dont need to check for exceptions every time we want to decrypt
    private byte[] decrypt(AbePrivateKey privateKey, AbeEncrypted encryptedData) {
        try {
            return Cpabe.decrypt(privateKey, encryptedData);
        } catch (Exception e) {
            return null;
        }
    }

    private byte[] forceDecrypt(AbeSecretMasterKey secretKey, AbeEncrypted encryptedData) {
        try {
            return CpabeExperimental.forceDecrypt(secretKey, encryptedData);
        } catch (Exception e) {
            return null;
        }
    }

    @Test
    public void delegationTest() throws Exception {
        AbeSecretMasterKey smKey = Cpabe.setup();
        AbePublicKey pubKey = smKey.getPublicKey();

        byte[] data = TUtil.getRandomData();

        String policy1 = "(att1 and att2) or att3";
        String policy2 = "att3 or att4 >= 5";

        AbeEncrypted policy1EncryptedTest = Cpabe.encrypt(pubKey, policy1, data);
        AbeEncrypted policy2EncryptedTest = Cpabe.encrypt(pubKey, policy2, data);

        ByteArrayInputStream baisPolicy1 = TUtil.getReusableStream(policy1EncryptedTest, pubKey);
        ByteArrayInputStream baisPolicy2 = TUtil.getReusableStream(policy2EncryptedTest, pubKey);

        String att1att2Attribute = "att1 att2";
        String att3att4Attribute = "att3 att4 = 42";

        AbePrivateKey att1att2Key = Cpabe.keygen(smKey, att1att2Attribute);
        AbePrivateKey att3att4Key = Cpabe.keygen(smKey, att3att4Attribute);

        assertTrue(Arrays.equals(data, decrypt(att1att2Key, AbeEncrypted.readFromStream(pubKey, baisPolicy1))));
        assertFalse(Arrays.equals(data, decrypt(att1att2Key, AbeEncrypted.readFromStream(pubKey, baisPolicy2))));
        TUtil.resetStreams(baisPolicy1, baisPolicy2);

        assertTrue(Arrays.equals(data, decrypt(att3att4Key, AbeEncrypted.readFromStream(pubKey, baisPolicy1))));
        assertTrue(Arrays.equals(data, decrypt(att3att4Key, AbeEncrypted.readFromStream(pubKey, baisPolicy2))));
        TUtil.resetStreams(baisPolicy1, baisPolicy2);

        AbePrivateKey att1Key = Cpabe.delegate(att1att2Key, "att1");
        AbePrivateKey att2Key = Cpabe.delegate(att1att2Key, "att2");
        AbePrivateKey att3Key = Cpabe.delegate(att3att4Key, "att3");
        AbePrivateKey att4Key = Cpabe.delegate(att3att4Key, "att4 = 42");

        assertFalse(Arrays.equals(data, decrypt(att1Key, AbeEncrypted.readFromStream(pubKey, baisPolicy1))));
        assertFalse(Arrays.equals(data, decrypt(att1Key, AbeEncrypted.readFromStream(pubKey, baisPolicy2))));
        TUtil.resetStreams(baisPolicy1, baisPolicy2);

        assertFalse(Arrays.equals(data, decrypt(att2Key, AbeEncrypted.readFromStream(pubKey, baisPolicy1))));
        assertFalse(Arrays.equals(data, decrypt(att2Key, AbeEncrypted.readFromStream(pubKey, baisPolicy2))));
        TUtil.resetStreams(baisPolicy1, baisPolicy2);

        assertTrue(Arrays.equals(data, decrypt(att3Key, AbeEncrypted.readFromStream(pubKey, baisPolicy1))));
        assertTrue(Arrays.equals(data, decrypt(att3Key, AbeEncrypted.readFromStream(pubKey, baisPolicy2))));
        TUtil.resetStreams(baisPolicy1, baisPolicy2);

        assertFalse(Arrays.equals(data, decrypt(att4Key, AbeEncrypted.readFromStream(pubKey, baisPolicy1))));
        assertTrue(Arrays.equals(data, decrypt(att4Key, AbeEncrypted.readFromStream(pubKey, baisPolicy2))));
        TUtil.resetStreams(baisPolicy1, baisPolicy2);
    }

    @Test
    public void addAttributesTest() throws Exception {
        AbeSecretMasterKey smKey = Cpabe.setup();
        AbePublicKey pubKey = smKey.getPublicKey();

        byte[] data = TUtil.getRandomData();

        String policy1 = "(att1 and att2) or att3";
        String policy2 = "att3 or att4 >= 5";

        AbeEncrypted policy1EncryptedTest1 = Cpabe.encrypt(pubKey, policy1, data);
        AbeEncrypted policy2EncryptedTest1 = Cpabe.encrypt(pubKey, policy2, data);

        AbeEncrypted policy1EncryptedTest2 = Cpabe.encrypt(pubKey, policy1, data);
        AbeEncrypted policy2EncryptedTest2 = Cpabe.encrypt(pubKey, policy2, data);

        AbeEncrypted policy1EncryptedTest3 = Cpabe.encrypt(pubKey, policy1, data);
        AbeEncrypted policy2EncryptedTest3 = Cpabe.encrypt(pubKey, policy2, data);

        AbeEncrypted policy1EncryptedTest4 = Cpabe.encrypt(pubKey, policy1, data);
        AbeEncrypted policy2EncryptedTest4 = Cpabe.encrypt(pubKey, policy2, data);

        AbeEncrypted policy1EncryptedTest5 = Cpabe.encrypt(pubKey, policy1, data);
        AbeEncrypted policy2EncryptedTest5 = Cpabe.encrypt(pubKey, policy2, data);

        String att1att2Attribute = "att1 att2";
        String att1Attribute = "att1";

        AbePrivateKey att1att2Key = Cpabe.keygen(smKey, att1att2Attribute);
        AbePrivateKey att1Key = Cpabe.keygen(smKey, att1Attribute);

        assertTrue(Arrays.equals(data, decrypt(att1att2Key, policy1EncryptedTest1)));
        assertFalse(Arrays.equals(data, decrypt(att1att2Key, policy2EncryptedTest1)));

        assertFalse(Arrays.equals(data, decrypt(att1Key, policy1EncryptedTest2)));
        assertFalse(Arrays.equals(data, decrypt(att1Key, policy2EncryptedTest2)));

        AbePrivateKey att1att2att3Key = CpabeExperimental.keyWithAddedAttributes(att1att2Key, smKey, "att3");
        AbePrivateKey att1att3Key = CpabeExperimental.keyWithAddedAttributes(att1Key, smKey, "att3");
        AbePrivateKey att1att4Key = CpabeExperimental.keyWithAddedAttributes(att1Key, smKey, "att4 = 42");

        assertTrue(Arrays.equals(data, decrypt(att1att2att3Key, policy1EncryptedTest3)));
        assertTrue(Arrays.equals(data, decrypt(att1att2att3Key, policy2EncryptedTest3)));

        assertTrue(Arrays.equals(data, decrypt(att1att3Key, policy1EncryptedTest4)));
        assertTrue(Arrays.equals(data, decrypt(att1att3Key, policy2EncryptedTest4)));

        assertFalse(Arrays.equals(data, decrypt(att1att4Key, policy1EncryptedTest5)));
        assertTrue(Arrays.equals(data, decrypt(att1att4Key, policy2EncryptedTest5)));
    }

    @Test
    public void thresholdTest() throws Exception {
        AbeSecretMasterKey smKey = Cpabe.setup();
        AbePublicKey pubKey = smKey.getPublicKey();

        byte[] data = TUtil.getRandomData();

        String oneOfThreePolicy = "1 of (att1, att2, att3)";
        String twoOfThreePolicy = "2 of (att1, att2, att3)";

        AbeEncrypted oneOfThreeTest = Cpabe.encrypt(pubKey, oneOfThreePolicy, data);
        AbeEncrypted twoOfThreeTest = Cpabe.encrypt(pubKey, twoOfThreePolicy, data);

        ByteArrayInputStream oneOfThree = TUtil.getReusableStream(oneOfThreeTest, pubKey);
        ByteArrayInputStream twoOfThree = TUtil.getReusableStream(twoOfThreeTest, pubKey);

        AbePrivateKey noneOfThreeKey = Cpabe.keygen(smKey, "att9");
        AbePrivateKey oneOfThreeKey = Cpabe.keygen(smKey, "att1");
        AbePrivateKey twoOfThreeKey = Cpabe.keygen(smKey, "att1 att2");
        AbePrivateKey allOfThreeKey = Cpabe.keygen(smKey, "att1 att2 att3");
        AbePrivateKey otherTwoOfThreeKey = Cpabe.keygen(smKey, "att2 att3");

        // noneOfThreeKey
        assertFalse(Arrays.equals(data, decrypt(noneOfThreeKey, AbeEncrypted.readFromStream(pubKey, oneOfThree))));
        assertFalse(Arrays.equals(data, decrypt(noneOfThreeKey, AbeEncrypted.readFromStream(pubKey, twoOfThree))));
        TUtil.resetStreams(oneOfThree, twoOfThree);

        // oneOfThreeKey
        assertTrue(Arrays.equals(data, decrypt(oneOfThreeKey, AbeEncrypted.readFromStream(pubKey, oneOfThree))));
        assertFalse(Arrays.equals(data, decrypt(oneOfThreeKey, AbeEncrypted.readFromStream(pubKey, twoOfThree))));
        TUtil.resetStreams(oneOfThree, twoOfThree);

        // twoOfThreeKey
        assertTrue(Arrays.equals(data, decrypt(twoOfThreeKey, AbeEncrypted.readFromStream(pubKey, oneOfThree))));
        assertTrue(Arrays.equals(data, decrypt(twoOfThreeKey, AbeEncrypted.readFromStream(pubKey, twoOfThree))));
        TUtil.resetStreams(oneOfThree, twoOfThree);

        // otherTwoOfThreeKey
        assertTrue(Arrays.equals(data, decrypt(otherTwoOfThreeKey, AbeEncrypted.readFromStream(pubKey, oneOfThree))));
        assertTrue(Arrays.equals(data, decrypt(otherTwoOfThreeKey, AbeEncrypted.readFromStream(pubKey, twoOfThree))));
        TUtil.resetStreams(oneOfThree, twoOfThree);

        // allOfThreeKey
        assertTrue(Arrays.equals(data, decrypt(allOfThreeKey, AbeEncrypted.readFromStream(pubKey, oneOfThree))));
        assertTrue(Arrays.equals(data, decrypt(allOfThreeKey, AbeEncrypted.readFromStream(pubKey, twoOfThree))));
        TUtil.resetStreams(oneOfThree, twoOfThree);
    }

    @Test
    @Repeat(5)
    public void numberTest() throws Exception {
        long signedNumber = new BigInteger(Util.FLEXINT_MAXBITS, random).longValue();
        BigInteger number = Util.unsignedToBigInteger(signedNumber); // when parsing we dont expect negative values
        System.out.println("Current Number: " + number);
        testComparisonOperations(number);
    }

    @Test
    public void specificNumberTest() throws Exception {
        testComparisonOperations(BigInteger.ONE);
        testComparisonOperations(Util.MAX_FLEXINT_VALUE.subtract(BigInteger.valueOf(2)));
    }

    @Test(expected = AbeEncryptionException.class)
    public void zeroNumberTest() throws Exception {
        testComparisonOperations(Util.MIN_FLEXINT_VALUE); // works for most operators, but fails at >= 0, since that is converted to > -1
    }

    @Test(expected = AbeEncryptionException.class)
    public void maxLongTest() throws Exception {
        testComparisonOperations(Util.MAX_FLEXINT_VALUE);
    }

    @Test(expected = AbeEncryptionException.class)
    public void notQuiteMaxLongTest() throws Exception {
        testComparisonOperations(Util.MAX_FLEXINT_VALUE.subtract(BigInteger.ONE)); // works for most operators, but fails at <= maxValue - 1 since that is converted to < maxValue, which wont work
    }

    public void testComparisonOperations(BigInteger number) throws Exception {
        AbeSecretMasterKey secretKey = Cpabe.setup();
        byte[] data = TUtil.getRandomData();
        AbePublicKey publicKey = secretKey.getPublicKey();

        String greaterPolicy = "someNumber > " + number;
        String greaterEqPolicy = "someNumber >= " + number;
        String smallerPolicy = "someNumber < " + number;
        String smallerEqPolicy = "someNumber <= " + number;
        String equalPolicy = "someNumber = " + number;

        // each AbeEncrypted can only be decrypted once, since we advance the stream to after the AES data.
        AbeEncrypted greaterEncryptedTest = Cpabe.encrypt(publicKey, greaterPolicy, data);
        AbeEncrypted greaterEqEncryptedTest = Cpabe.encrypt(publicKey, greaterEqPolicy, data);
        AbeEncrypted smallerEncryptedTest = Cpabe.encrypt(publicKey, smallerPolicy, data);
        AbeEncrypted smallerEqEncryptedTest = Cpabe.encrypt(publicKey, smallerEqPolicy, data);
        AbeEncrypted equalEncryptedTest = Cpabe.encrypt(publicKey, equalPolicy, data);

        ByteArrayInputStream baisGreater = TUtil.getReusableStream(greaterEncryptedTest, publicKey);
        ByteArrayInputStream baisGreaterEq = TUtil.getReusableStream(greaterEqEncryptedTest, publicKey);
        ByteArrayInputStream baisSmaller = TUtil.getReusableStream(smallerEncryptedTest, publicKey);
        ByteArrayInputStream baisSmallerEq = TUtil.getReusableStream(smallerEqEncryptedTest, publicKey);
        ByteArrayInputStream baisEqual = TUtil.getReusableStream(equalEncryptedTest, publicKey);

        String greaterAttribute = "someNumber = " + number.add(BigInteger.ONE);
        String smallerAttribute = "someNumber = " + number.subtract(BigInteger.ONE);
        String equalAttribute = "someNumber = " + number;

        AbePrivateKey greaterKey = Cpabe.keygen(secretKey, greaterAttribute);
        AbePrivateKey smallerKey = Cpabe.keygen(secretKey, smallerAttribute);
        AbePrivateKey equalKey = Cpabe.keygen(secretKey, equalAttribute);

        // greaterKey
        assertTrue(Arrays.equals(data, decrypt(greaterKey, AbeEncrypted.readFromStream(publicKey, baisGreater))));
        assertTrue(Arrays.equals(data, decrypt(greaterKey, AbeEncrypted.readFromStream(publicKey, baisGreaterEq))));
        assertFalse(Arrays.equals(data, decrypt(greaterKey, AbeEncrypted.readFromStream(publicKey, baisSmaller))));
        assertFalse(Arrays.equals(data, decrypt(greaterKey, AbeEncrypted.readFromStream(publicKey, baisSmallerEq))));
        assertFalse(Arrays.equals(data, decrypt(greaterKey, AbeEncrypted.readFromStream(publicKey, baisEqual))));
        TUtil.resetStreams(baisGreater, baisGreaterEq, baisSmaller, baisSmallerEq, baisEqual);

        // smallerKey
        assertFalse(Arrays.equals(data, decrypt(smallerKey, AbeEncrypted.readFromStream(publicKey, baisGreater))));
        assertFalse(Arrays.equals(data, decrypt(smallerKey, AbeEncrypted.readFromStream(publicKey, baisGreaterEq))));
        assertTrue(Arrays.equals(data, decrypt(smallerKey, AbeEncrypted.readFromStream(publicKey, baisSmaller))));
        assertTrue(Arrays.equals(data, decrypt(smallerKey, AbeEncrypted.readFromStream(publicKey, baisSmallerEq))));
        assertFalse(Arrays.equals(data, decrypt(smallerKey, AbeEncrypted.readFromStream(publicKey, baisEqual))));
        TUtil.resetStreams(baisGreater, baisGreaterEq, baisSmaller, baisSmallerEq, baisEqual);

        // equalKey
        assertFalse(Arrays.equals(data, decrypt(equalKey, AbeEncrypted.readFromStream(publicKey, baisGreater))));
        assertTrue(Arrays.equals(data, decrypt(equalKey, AbeEncrypted.readFromStream(publicKey, baisGreaterEq))));
        assertFalse(Arrays.equals(data, decrypt(equalKey, AbeEncrypted.readFromStream(publicKey, baisSmaller))));
        assertTrue(Arrays.equals(data, decrypt(equalKey, AbeEncrypted.readFromStream(publicKey, baisSmallerEq))));
        assertTrue(Arrays.equals(data, decrypt(equalKey, AbeEncrypted.readFromStream(publicKey, baisEqual))));
        TUtil.resetStreams(baisGreater, baisGreaterEq, baisSmaller, baisSmallerEq, baisEqual);
    }

    @Test
    public void forceDecryptTest() throws Exception {
        AbeSecretMasterKey smKey = Cpabe.setup();
        AbePublicKey pubKey = smKey.getPublicKey();

        byte[] data = TUtil.getRandomData();
        int number = random.nextInt(100) + 20; // 20-119
        String greaterPolicy = "someNumber > " + number;
        String greaterEqPolicy = "someNumber >= " + number;
        String smallerPolicy = "someNumber < " + number;
        String smallerEqPolicy = "someNumber <= " + number;

        AbeEncrypted greaterEncrypted = Cpabe.encrypt(pubKey, greaterPolicy, data);
        AbeEncrypted greaterEqEncrypted = Cpabe.encrypt(pubKey, greaterEqPolicy, data);
        AbeEncrypted smallerEncrypted = Cpabe.encrypt(pubKey, smallerPolicy, data);
        AbeEncrypted smallerEqEncrypted = Cpabe.encrypt(pubKey, smallerEqPolicy, data);

        assertTrue(Arrays.equals(data, forceDecrypt(smKey, greaterEncrypted)));
        assertTrue(Arrays.equals(data, forceDecrypt(smKey, greaterEqEncrypted)));
        assertTrue(Arrays.equals(data, forceDecrypt(smKey, smallerEncrypted)));
        assertTrue(Arrays.equals(data, forceDecrypt(smKey, smallerEqEncrypted)));
    }
}
