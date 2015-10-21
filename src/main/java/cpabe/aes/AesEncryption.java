package cpabe.aes;

import cpabe.AbeDecryptionException;
import cpabe.AbeEncryptionException;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

//import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class AesEncryption {
    private final static String KEY_ALGORITHM = "AES";
    private final static String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding"; //"AES/GCM/NoPadding" not working on android
    private final static String HASHING_ALGORITHM = "SHA-256";
    private static final int BUFFERSIZE = 1024;
    // We use AES128 per schneier, so we need to reduce the keysize
    private static final int AES_KEY_LENGTH = 16;

    static {
        //Security.addProvider(new BouncyCastleProvider());
    }



    private static byte[] hash(byte[] cpabeData) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance(HASHING_ALGORITHM);
            return Arrays.copyOf(sha256.digest(cpabeData), AES_KEY_LENGTH);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Hashing Alogrithm not available: " + HASHING_ALGORITHM, e);
        }
    }

    private static byte[] combine(byte[] cpabeData, byte[] lbeKey) {
        byte[] hashedCpabeSecret = hash(cpabeData);
        if (lbeKey != null) {
            if (hashedCpabeSecret.length != lbeKey.length) {
                throw new RuntimeException("wrong key size for lbeKey, " + hashedCpabeSecret.length + " bytes required");
            }
            for (int i = 0; i < lbeKey.length; i++) {
                hashedCpabeSecret[i] = (byte) (hashedCpabeSecret[i] ^ lbeKey[i]);
            }
        }
        return hashedCpabeSecret;
    }

    public static void encrypt(byte[] cpabeKey, byte[] lbeKey, byte[] iv, InputStream input, OutputStream output) throws IOException, AbeEncryptionException {
        try {
            CipherInputStream cis = encrypt(cpabeKey, lbeKey, iv, input);
            int read;
            byte[] buffer = new byte[BUFFERSIZE];
            while ((read = cis.read(buffer)) >= 0) {
                output.write(buffer, 0, read);
            }
            output.close();
            cis.close();
        } catch (GeneralSecurityException e) {
            throw new AbeEncryptionException(e.getMessage(), e);
        }
    }

    public static CipherInputStream encrypt(byte[] cpabeKey, byte[] lbeKey, byte[] iv, InputStream input) throws AbeEncryptionException {
        try {
            SecretKeySpec skeySpec = new SecretKeySpec(combine(cpabeKey, lbeKey), KEY_ALGORITHM);
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, new IvParameterSpec(iv));
            CipherInputStream cis = new CipherInputStream(input, cipher);
            return cis;
        } catch (GeneralSecurityException e) {
            throw new AbeEncryptionException(e.getMessage(), e);
        }
    }

    public static CipherInputStream decrypt(byte[] cpabeKey, byte[] lbeKey, byte[] iv, InputStream input) throws AbeDecryptionException {
        try {
            SecretKeySpec skeySpec = new SecretKeySpec(combine(cpabeKey, lbeKey), KEY_ALGORITHM);
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, new IvParameterSpec(iv));
            return new CipherInputStream(input, cipher);
        } catch (GeneralSecurityException e) {
            throw new AbeDecryptionException(e.getMessage(), e);
        }
    }

    public static void decrypt(byte[] cpabeKey, byte[] lbeKey, byte[] iv, InputStream input, OutputStream output) throws IOException, AbeDecryptionException {
        try {
            InputStream cis = decrypt(cpabeKey, lbeKey, iv, input);
            int read;
            byte[] buffer = new byte[BUFFERSIZE];
            while ((read = cis.read(buffer)) >= 0) {
                output.write(buffer, 0, read);
            }
            output.flush();
        } catch (GeneralSecurityException e) {
            throw new AbeDecryptionException(e.getMessage(), e);
        }
    }
}