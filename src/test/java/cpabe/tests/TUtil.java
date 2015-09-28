package cpabe.tests;

import cpabe.AbeEncrypted;
import cpabe.AbePublicKey;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

public class TUtil {
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
