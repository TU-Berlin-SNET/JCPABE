package cpabe.tests;

import cpabe.*;
import cpabe.policy.Util;
import cpabe.tests.rules.Repeat;
import cpabe.tests.rules.RepeatRule;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

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

    public byte[] getRandomData() {
        byte[] data = new byte[random.nextInt(100) + 20];
        random.nextBytes(data);
        return data;
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

        byte[] data = getRandomData();

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

        AbeEncrypted policy1EncryptedTest6 = Cpabe.encrypt(pubKey, policy1, data);
        AbeEncrypted policy2EncryptedTest6 = Cpabe.encrypt(pubKey, policy2, data);

        String att1att2Attribute = "att1 att2";
        String att3att4Attribute = "att3 att4 = 42";

        AbePrivateKey att1att2Key = Cpabe.keygen(smKey, att1att2Attribute);
        AbePrivateKey att3att4Key = Cpabe.keygen(smKey, att3att4Attribute);

        assertTrue(Arrays.equals(data, decrypt(att1att2Key, policy1EncryptedTest1)));
        assertFalse(Arrays.equals(data, decrypt(att1att2Key, policy2EncryptedTest1)));

        assertTrue(Arrays.equals(data, decrypt(att3att4Key, policy1EncryptedTest2)));
        assertTrue(Arrays.equals(data, decrypt(att3att4Key, policy2EncryptedTest2)));

        AbePrivateKey att1Key = Cpabe.delegate(att1att2Key, "att1");
        AbePrivateKey att2Key = Cpabe.delegate(att1att2Key, "att2");
        AbePrivateKey att3Key = Cpabe.delegate(att3att4Key, "att3");
        AbePrivateKey att4Key = Cpabe.delegate(att3att4Key, "att4 = 42");

        assertFalse(Arrays.equals(data, decrypt(att1Key, policy1EncryptedTest3)));
        assertFalse(Arrays.equals(data, decrypt(att1Key, policy2EncryptedTest3)));

        assertFalse(Arrays.equals(data, decrypt(att2Key, policy1EncryptedTest4)));
        assertFalse(Arrays.equals(data, decrypt(att2Key, policy2EncryptedTest4)));

        assertTrue(Arrays.equals(data, decrypt(att3Key, policy1EncryptedTest5)));
        assertTrue(Arrays.equals(data, decrypt(att3Key, policy2EncryptedTest5)));

        assertFalse(Arrays.equals(data, decrypt(att4Key, policy1EncryptedTest6)));
        assertTrue(Arrays.equals(data, decrypt(att4Key, policy2EncryptedTest6)));
    }

    @Test
    public void addAttributesTest() throws Exception {
        AbeSecretMasterKey smKey = Cpabe.setup();
        AbePublicKey pubKey = smKey.getPublicKey();

        byte[] data = getRandomData();

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
        byte[] data = getRandomData();
        AbePublicKey publicKey = secretKey.getPublicKey();

        String greaterPolicy = "someNumber > " + number;
        String greaterEqPolicy = "someNumber >= " + number;
        String smallerPolicy = "someNumber < " + number;
        String smallerEqPolicy = "someNumber <= " + number;
        String equalPolicy = "someNumber = " + number;

        // each AbeEncrypted can only be decrypted once, since we advance the stream to after the AES data.
        AbeEncrypted greaterEncryptedTest1 = Cpabe.encrypt(publicKey, greaterPolicy, data);
        AbeEncrypted greaterEqEncryptedTest1 = Cpabe.encrypt(publicKey, greaterEqPolicy, data);
        AbeEncrypted smallerEncryptedTest1 = Cpabe.encrypt(publicKey, smallerPolicy, data);
        AbeEncrypted smallerEqEncryptedTest1 = Cpabe.encrypt(publicKey, smallerEqPolicy, data);
        AbeEncrypted equalEncryptedTest1 = Cpabe.encrypt(publicKey, equalPolicy, data);

        AbeEncrypted greaterEncryptedTest2 = Cpabe.encrypt(publicKey, greaterPolicy, data);
        AbeEncrypted greaterEqEncryptedTest2 = Cpabe.encrypt(publicKey, greaterEqPolicy, data);
        AbeEncrypted smallerEncryptedTest2 = Cpabe.encrypt(publicKey, smallerPolicy, data);
        AbeEncrypted smallerEqEncryptedTest2 = Cpabe.encrypt(publicKey, smallerEqPolicy, data);
        AbeEncrypted equalEncryptedTest2 = Cpabe.encrypt(publicKey, equalPolicy, data);

        AbeEncrypted greaterEncryptedTest3 = Cpabe.encrypt(publicKey, greaterPolicy, data);
        AbeEncrypted greaterEqEncryptedTest3 = Cpabe.encrypt(publicKey, greaterEqPolicy, data);
        AbeEncrypted smallerEncryptedTest3 = Cpabe.encrypt(publicKey, smallerPolicy, data);
        AbeEncrypted smallerEqEncryptedTest3 = Cpabe.encrypt(publicKey, smallerEqPolicy, data);
        AbeEncrypted equalEncryptedTest3 = Cpabe.encrypt(publicKey, equalPolicy, data);

        String greaterAttribute = "someNumber = " + number.add(BigInteger.ONE);
        String smallerAttribute = "someNumber = " + number.subtract(BigInteger.ONE);
        String equalAttribute = "someNumber = " + number;

        AbePrivateKey greaterKey = Cpabe.keygen(secretKey, greaterAttribute);
        AbePrivateKey smallerKey = Cpabe.keygen(secretKey, smallerAttribute);
        AbePrivateKey equalKey = Cpabe.keygen(secretKey, equalAttribute);

        // greaterKey
        assertTrue(Arrays.equals(data, decrypt(greaterKey, greaterEncryptedTest1)));
        assertTrue(Arrays.equals(data, decrypt(greaterKey, greaterEqEncryptedTest1)));
        assertFalse(Arrays.equals(data, decrypt(greaterKey, smallerEncryptedTest1)));
        assertFalse(Arrays.equals(data, decrypt(greaterKey, smallerEqEncryptedTest1)));
        assertFalse(Arrays.equals(data, decrypt(greaterKey, equalEncryptedTest1)));

        // smallerKey
        assertFalse(Arrays.equals(data, decrypt(smallerKey, greaterEncryptedTest2)));
        assertFalse(Arrays.equals(data, decrypt(smallerKey, greaterEqEncryptedTest2)));
        assertTrue(Arrays.equals(data, decrypt(smallerKey, smallerEncryptedTest2)));
        assertTrue(Arrays.equals(data, decrypt(smallerKey, smallerEqEncryptedTest2)));
        assertFalse(Arrays.equals(data, decrypt(smallerKey, equalEncryptedTest2)));

        // equalKey
        assertFalse(Arrays.equals(data, decrypt(equalKey, greaterEncryptedTest3)));
        assertTrue(Arrays.equals(data, decrypt(equalKey, greaterEqEncryptedTest3)));
        assertFalse(Arrays.equals(data, decrypt(equalKey, smallerEncryptedTest3)));
        assertTrue(Arrays.equals(data, decrypt(equalKey, smallerEqEncryptedTest3)));
        assertTrue(Arrays.equals(data, decrypt(equalKey, equalEncryptedTest3)));
    }

    @Test
    public void forceDecryptTest() throws Exception {
        AbeSecretMasterKey smKey = Cpabe.setup();
        AbePublicKey pubKey = smKey.getPublicKey();

        byte[] data = getRandomData();
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
