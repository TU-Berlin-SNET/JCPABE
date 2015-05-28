package cpabe.tests;

import cpabe.Cpabe;
import cpabe.tests.rules.RepeatRule;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

import java.io.*;
import java.security.SecureRandom;

import static org.junit.Assert.assertArrayEquals;

public class SerializationTests {
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


    @Test
    public void testSerialization() throws Exception {
        File inputFile = new File("a.txt");
        File encryptedFile = new File("a.enc");
        File decryptedFile = new File("a.dec");
        File publicKey = new File("a.pkey");
        File secretKey = new File("a.mkey");
        File privateKey = new File("user.private");

        inputFile.delete();
        encryptedFile.delete();
        decryptedFile.delete();
        publicKey.delete();
        secretKey.delete();
        privateKey.delete();

        byte[] rawData = getRandomData();
        byte[] decryptedData = new byte[rawData.length];
        try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(inputFile))) {
            bos.write(rawData);
        }

        Cpabe.setup(publicKey, secretKey);
        Cpabe.encrypt(publicKey, "a and b", inputFile, encryptedFile);
        Cpabe.keygen(privateKey, secretKey, "a b c");
        Cpabe.decrypt(privateKey, encryptedFile, decryptedFile);

        try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(decryptedFile))) {
            int read = 0;
            while (read < rawData.length) {
                read += bis.read(decryptedData, read, rawData.length - read);
            }
        }
        assertArrayEquals(rawData, decryptedData);

        inputFile.delete();
        encryptedFile.delete();
        decryptedFile.delete();
        publicKey.delete();
        secretKey.delete();
        privateKey.delete();
    }

}
