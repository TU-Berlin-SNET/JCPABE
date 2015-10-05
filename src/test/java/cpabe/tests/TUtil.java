package cpabe.tests;

import cpabe.AbeEncrypted;
import cpabe.AbePublicKey;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.security.SecureRandom;

public class TUtil {
    static final SecureRandom random = new SecureRandom();

    public static byte[] getRandomData() {
        byte[] data = new byte[random.nextInt(100) + 20];
        random.nextBytes(data);
        return data;
    }

    public static File getExampleSecretKey(String keyName) {
        return new File("examples" + File.separator + keyName);
    }

    public static void resetStreams(ByteArrayInputStream... streams) {
        for (ByteArrayInputStream stream : streams) {
            stream.reset();
        }
    }

    public static ByteArrayInputStream getReusableStream(AbeEncrypted encrypted, AbePublicKey publicKey) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        encrypted.writeEncryptedData(baos, publicKey);
        byte[] encryptedBytes = baos.toByteArray();
        return new ByteArrayInputStream(encryptedBytes);
    }
}
