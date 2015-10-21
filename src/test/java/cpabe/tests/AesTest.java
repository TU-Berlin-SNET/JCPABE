package cpabe.tests;

import cpabe.*;
import cpabe.aes.AesEncryption;
import cpabe.aes.InputStreamStopper;
import cpabe.tests.rules.Repeat;
import cpabe.tests.rules.RepeatRule;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.Assert.assertTrue;

public class AesTest {

    private static SecureRandom random;

    @Rule
    public RepeatRule repeatRule = new RepeatRule();

    @BeforeClass
    public static void testSetup() {
        random = new SecureRandom();
    }

    @Test
    @Repeat(100)
    public void testStreamingAES() throws AbeEncryptionException, IOException, AbeDecryptionException {
        int plainTextLength = random.nextInt(100) + 1;
        byte[] plaintext = new byte[plainTextLength];
        byte[] cpabeKey = new byte[1000];
        byte[] iv = new byte[16];

        random.nextBytes(plaintext);
        random.nextBytes(cpabeKey);
        random.nextBytes(iv);

        ByteArrayInputStream encInput = new ByteArrayInputStream(plaintext);
        ByteArrayOutputStream encOutput = new ByteArrayOutputStream();

        AesEncryption.encrypt(cpabeKey, null, iv, encInput, encOutput);
        byte[] ciphertext = encOutput.toByteArray();

        ByteArrayInputStream decInput = new ByteArrayInputStream(ciphertext);
        ByteArrayOutputStream decOutput = new ByteArrayOutputStream();
        AesEncryption.decrypt(cpabeKey, null, iv, decInput, decOutput);

        byte[] decryptedtext = decOutput.toByteArray();
        assertTrue(Arrays.equals(plaintext, decryptedtext));
    }

    @Test
    public void readAfterABEFileTest() throws Exception {
        AbeSecretMasterKey smKey = Cpabe.setup();
        AbePublicKey pubKey = smKey.getPublicKey();

        int plainTextLength = random.nextInt(100) + 1;
        byte[] plaintext = new byte[plainTextLength];
        random.nextBytes(plaintext);

        String policy = "someAttribute1 and someAttribute2";

        AbeEncrypted encrypted = Cpabe.encrypt(pubKey, policy, plaintext);
        AbePrivateKey key = Cpabe.keygen(smKey, "someAttribute1 someAttribute2");

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        encrypted.writeEncryptedData(baos, pubKey);

        byte[] encryptedData = baos.toByteArray();
        byte[] encryptedDataPlusBytes = Arrays.copyOf(encryptedData, encryptedData.length + 3);

        encryptedDataPlusBytes[encryptedDataPlusBytes.length - 3] = 5;
        encryptedDataPlusBytes[encryptedDataPlusBytes.length - 2] = 10;
        encryptedDataPlusBytes[encryptedDataPlusBytes.length - 1] = 15;

        ByteArrayInputStream input = new ByteArrayInputStream(encryptedDataPlusBytes);
        InputStream limitedInput = new InputStreamStopper(input, encryptedData.length);
        ByteArrayOutputStream decryptedStream = new ByteArrayOutputStream();
        Cpabe.decrypt(key, limitedInput, decryptedStream);

        byte[] decryptedData = decryptedStream.toByteArray();
        assertTrue(Arrays.equals(plaintext, decryptedData));
        assertTrue(input.read() == 5);
        assertTrue(input.read() == 10);
        assertTrue(input.read() == 15);
        assertTrue(input.read() == -1);
    }
}
