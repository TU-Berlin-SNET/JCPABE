package cpabe;

import cpabe.aes.AesEncryption;
import cpabe.bsw07.Bsw07;
import cpabe.bsw07.Bsw07Cipher;
import it.unisa.dia.gas.jpbc.Element;

import java.io.*;

public class AbeEncrypted implements AutoCloseable {
    Bsw07Cipher cipher;
    byte[] iv;
    InputStream dataStream; // the encrypted data

    AbeEncrypted(byte[] iv, Bsw07Cipher cipher, InputStream dataStream) {
        this.iv = iv;
        this.cipher = cipher;
        this.dataStream = dataStream;
    }

    public static AbeEncrypted readFromFile(AbePublicKey publicKey, File file) throws IOException {
        return AbeEncrypted.readFromStream(publicKey, new BufferedInputStream(new FileInputStream(file)));
    }

    public static AbeEncrypted readFromStream(AbePublicKey publicKey, InputStream input) throws IOException {
        AbeInputStream stream = new AbeInputStream(input, publicKey);
        Version.readAndVerify(stream);
        Bsw07Cipher cipher = Bsw07Cipher.readFromStream(stream);
        int ivLength = stream.readInt();
        byte[] iv = new byte[ivLength];
        stream.readFully(iv);
        return new AbeEncrypted(iv, cipher, input);
    }

    public static AbeEncrypted createDuringEncryption(byte[] iv, Bsw07Cipher cipher, InputStream input, Element plainSecret) throws AbeEncryptionException, IOException {
        return new AbeEncrypted(iv, cipher, AesEncryption.encrypt(plainSecret.toBytes(), null, iv, input));
    }

    public static AbeEncrypted createDuringEncryption(byte[] iv, byte[] lbeKey, Bsw07Cipher cipher, InputStream input, Element plainSecret) throws AbeEncryptionException, IOException {
        return new AbeEncrypted(iv, cipher, AesEncryption.encrypt(plainSecret.toBytes(), lbeKey, iv, input));
    }

    public Bsw07Cipher getCipher() {
        return cipher;
    }

    public void writeEncryptedData(OutputStream out, AbePublicKey publicKey) throws IOException {
        AbeOutputStream abeOut = new AbeOutputStream(out, publicKey);
        Version.writeToStream(abeOut);
        cipher.writeToStream(abeOut);
        abeOut.writeInt(iv.length);
        abeOut.write(iv);
        byte[] buffer = new byte[1024];
        int len;
        while ((len = dataStream.read(buffer)) != -1) {
            abeOut.write(buffer, 0, len);
        }
    }

    /**
     * Advances the stream to after the AES block.
     *
     * @param privateKey
     * @param output
     * @throws AbeDecryptionException
     * @throws IOException
     */
    public void writeDecryptedData(AbePrivateKey privateKey, OutputStream output) throws AbeDecryptionException, IOException {
        Element secret = Bsw07.decrypt(privateKey, cipher);
        byte[] cpabeKey = secret.toBytes();
        AesEncryption.decrypt(cpabeKey, null, iv, dataStream, output);
    }

    public void writeDecryptedData(AbePrivateKey privateKey, byte[] lbeKey, OutputStream output) throws AbeDecryptionException, IOException {
        Element secret = Bsw07.decrypt(privateKey, cipher);
        byte[] cpabeKey = secret.toBytes();
        AesEncryption.decrypt(cpabeKey, lbeKey, iv, dataStream, output);
    }

    @Override
    public void close() throws Exception {
        dataStream.close();
    }
}
