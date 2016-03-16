package cpabe;

import cpabe.bsw07.Bsw07;
import cpabe.bsw07.Bsw07Cipher;
import cpabe.bsw07.Bsw07CipherAndKey;
import cpabe.bsw07.Bsw07PrivateKeyComponent;
import cpabe.bsw07.policy.Bsw07PolicyAbstractNode;
import cpabe.policy.AttributeParser;
import cpabe.policyparser.ParseException;
import it.unisa.dia.gas.jpbc.Element;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.ArrayList;

public class CpabeExperimental {

    /**
     * This is an experimental feature. It is recommended to not use it.
     *
     * @throws ParseException
     */
    public static ArrayList<Bsw07PrivateKeyComponent> generateAdditionalAttributes(AbeSecretMasterKey msk, Element prv_d, String attributes) throws ParseException {
        String parsedAttributeSet = AttributeParser.parseAttributes(attributes);
        String[] splitAttributeSet = parsedAttributeSet.split(" ");
        return Bsw07.generateAdditionalAttributes(msk, prv_d, splitAttributeSet);
    }

    /**
     * This is an experimental feature. It is recommended to not use it.
     *
     * @throws ParseException
     */
    public static AbePrivateKey keyWithAddedAttributes(AbePrivateKey oldKey, AbeSecretMasterKey msk, String newAttributes) throws ParseException {
        ArrayList<Bsw07PrivateKeyComponent> newComponents = generateAdditionalAttributes(msk, oldKey.getD(), newAttributes);
        return oldKey.newKeyWithAddedAttributes(newComponents);
    }

    public static AbeEncrypted encryptWithExistingPolicyTree(AbePublicKey publicKey, Bsw07PolicyAbstractNode policyTree, byte[] data) throws IOException, AbeEncryptionException {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(data)) {
            return encryptWithExistingPolicyTree(publicKey, policyTree, bais);
        }
    }

    /**
     * The policyTree will not be modified. The resulting policytree in the cipher is a copy of the given one.
     *
     * @throws IOException
     * @throws AbeEncryptionException
     */
    public static AbeEncrypted encryptWithExistingPolicyTree(AbePublicKey publicKey, Bsw07PolicyAbstractNode policyTree, InputStream input) throws IOException, AbeEncryptionException {
        Bsw07PolicyAbstractNode policyTreeCopy = policyTree.getCopy(publicKey);
        Bsw07CipherAndKey cipherAndKey = Bsw07.encrypt(publicKey, policyTreeCopy);
        Bsw07Cipher abeEncryptedSecret = cipherAndKey.getCipher();
        Element plainSecret = cipherAndKey.getKey();

        if (abeEncryptedSecret == null) {
            throw new AbeEncryptionException("ABE Encryption failed");
        }

        byte[] iv = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        return AbeEncrypted.createDuringEncryption(iv, abeEncryptedSecret, input, plainSecret);
    }

    public static AbePrivateKey generatePrivateKeyFromEncrypted(AbeSecretMasterKey secretKey, AbeEncrypted encrypted) {
        return Bsw07.keygen(secretKey, encrypted.getCipher());
    }

    public static byte[] forceDecrypt(AbeSecretMasterKey secretKey, AbeEncrypted encrypted) throws AbeDecryptionException, IOException {
        return Cpabe.decrypt(generatePrivateKeyFromEncrypted(secretKey, encrypted), encrypted);
    }

}
