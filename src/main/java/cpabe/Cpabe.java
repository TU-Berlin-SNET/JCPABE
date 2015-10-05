package cpabe;

import cpabe.bsw07.Bsw07;
import cpabe.bsw07.Bsw07Cipher;
import cpabe.bsw07.Bsw07CipherAndKey;
import cpabe.policy.AttributeParser;
import cpabe.policy.PolicyParsing;
import cpabe.policyparser.ParseException;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.*;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Cpabe {
    static {
        try {
            System.loadLibrary("jpbc-pbc");
        } catch (UnsatisfiedLinkError e) {
            Logger.getLogger(Cpabe.class.toString()).log(Level.SEVERE, "Could not load library jpbc-pbc. JCPABE will be extremely slow.", e);
            // can't salvage this
        }
        PairingFactory.getInstance().setUsePBCWhenPossible(true);
        if (!PairingFactory.getInstance().isPBCAvailable()) {
            PairingFactory.getInstance().isPBCAvailable();
            Logger.getLogger(Cpabe.class.toString()).log(Level.SEVERE, "The jpbc-pbc library was loaded, but can not be used. JCPABE will be extremely slow.");
        }
    }

    public static AbeSecretMasterKey setup() {
        return Bsw07.setup();
    }

    public static void setup(File publicKeyFile, File secretMasterFile) throws IOException {
        AbeSecretMasterKey masterKey = setup();
        masterKey.writeToFile(secretMasterFile);
        masterKey.getPublicKey().writeToFile(publicKeyFile);
    }

    public static AbePrivateKey keygen(AbeSecretMasterKey secretMaster, String attributes) throws ParseException {
        String parsedAttributes = AttributeParser.parseAttributes(attributes);
        String[] splitAttributes = parsedAttributes.split(" ");
        return Bsw07.keygen(secretMaster, splitAttributes);
    }

    public static void keygen(File privateFile, File secretMasterFile, String attributes) throws IOException, ParseException {
        AbeSecretMasterKey secretKey = AbeSecretMasterKey.readFromFile(secretMasterFile);
        AbePrivateKey prv = keygen(secretKey, attributes);
        prv.writeToFile(privateFile);
    }

    public static AbePrivateKey delegate(AbePrivateKey oldPrivateKey, String attributeSubset) throws ParseException {
        String parsedAttributeSubset = AttributeParser.parseAttributes(attributeSubset);
        String[] splitAttributeSubset = parsedAttributeSubset.split(" ");
        return Bsw07.delegate(oldPrivateKey, splitAttributeSubset);
    }

    public static void delegate(File oldPrivateKeyFile, String attributeSubset, File newPrivateKeyFile) throws IOException, ParseException {
        AbePrivateKey oldPrivateKey = AbePrivateKey.readFromFile(oldPrivateKeyFile);
        AbePrivateKey newPrivateKey = delegate(oldPrivateKey, attributeSubset);
        newPrivateKey.writeToFile(newPrivateKeyFile);
    }

    /**
     * Decrypts ABE encrypted data from the inputstream and writes that data to the outputstream. Neither stream will be closed.
     *
     * @param privateKey the private key to use for the decryption
     * @param input
     * @param output
     */
    public static void decrypt(AbePrivateKey privateKey, InputStream input, OutputStream output) throws IOException, AbeDecryptionException {
        AbeEncrypted encrypted = AbeEncrypted.readFromStream(privateKey.getPublicKey(), input);
        encrypted.writeDecryptedData(privateKey, output);
    }

    /**
     * Decrypts ABE encrypted data. The stream in the given AbeEncrypted instance will not be closed.
     *
     * @param privateKey
     * @param encryptedData
     * @return the decrypted data
     */
    public static byte[] decrypt(AbePrivateKey privateKey, AbeEncrypted encryptedData) throws AbeDecryptionException, IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        encryptedData.writeDecryptedData(privateKey, out);
        return out.toByteArray();
    }

    public static void decrypt(File privateKeyFile, File encryptedFile, File decryptedFile) throws IOException, AbeDecryptionException {
        AbePrivateKey privateKey = AbePrivateKey.readFromFile(privateKeyFile);
        try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(encryptedFile));
             BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(decryptedFile))) {
            decrypt(privateKey, in, out);
        }
    }

    /**
     * Encrypts the data of the inputstream with the given policy and writes the result to the outputstream.
     * Neither stream will be closed after this.
     *
     * @param publicKey
     * @param policy
     * @param input
     * @param output
     */
    public static void encrypt(AbePublicKey publicKey, String policy, InputStream input, OutputStream output) throws AbeEncryptionException, IOException {
        AbeEncrypted encrypted = encrypt(publicKey, policy, input);
        encrypted.writeEncryptedData(output, publicKey);
    }

    /**
     * Encrypts the data of the inputstream with the given policy. The inputstream will not be closed. To get the encrypted data use the returned AbeEncrypted instance.
     *
     * @param publicKey
     * @param policy
     * @param input
     * @return
     */
    public static AbeEncrypted encrypt(AbePublicKey publicKey, String policy, InputStream input) throws AbeEncryptionException, IOException {
        try {
            String parsedPolicy = PolicyParsing.parsePolicy(policy);
            Bsw07CipherAndKey cipherAndKey = Bsw07.encrypt(publicKey, parsedPolicy);
            Bsw07Cipher abeEncryptedSecret = cipherAndKey.getCipher();
            Element plainSecret = cipherAndKey.getKey();

            if (abeEncryptedSecret == null) {
                throw new AbeEncryptionException("ABE Encryption failed");
            }

            byte[] iv = new byte[16];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            return AbeEncrypted.createDuringEncryption(iv, abeEncryptedSecret, input, plainSecret);
        } catch (ParseException e) {
            throw new AbeEncryptionException("error while parsing policy", e);
        }
    }

    public static AbeEncrypted encrypt(AbePublicKey publicKey, String policy, byte[] data) throws AbeEncryptionException, IOException {
        try (ByteArrayInputStream byteIn = new ByteArrayInputStream(data)) {
            return encrypt(publicKey, policy, byteIn);
        }
    }

    public static void encrypt(File publicKeyFile, String policy, File inputFile, File outputFile) throws IOException, AbeEncryptionException {
        AbePublicKey publicKey = AbePublicKey.readFromFile(publicKeyFile);
        try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(inputFile));
             BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(outputFile))) {
            encrypt(publicKey, policy, in, out);
        }
    }


    /**
     * Returns true if the given privateKey is able to decrypt the cipher of the given File, false otherwise.
     *
     * @param privateKey
     * @param encryptedFile     the encrypted file to test
     * @return true if the privatekey is able to decrypt the cipher
     * @throws IOException
     */
    public static boolean canDecrypt(AbePrivateKey privateKey, File encryptedFile) throws IOException {
        try (FileInputStream fis = new FileInputStream(encryptedFile)) {
            AbeEncrypted encrypted = AbeEncrypted.readFromStream(privateKey.getPublicKey(), fis);
            return Bsw07.canDecrypt(privateKey, encrypted.getCipher());
        }
    }
}
