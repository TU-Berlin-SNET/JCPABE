package cpabe.bsw07;

import cpabe.AbePublicKey;
import cpabe.AbeSettings;
import it.unisa.dia.gas.jpbc.Element;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Bsw07Util {
    public static Element elementG2FromString(String s, AbePublicKey publicKey) {
        try {
            MessageDigest sha1 = MessageDigest.getInstance(AbeSettings.ELEMENT_HASHING_ALGORITHM);
            byte[] digest = sha1.digest(s.getBytes());
            return publicKey.getPairing().getG2().newElementFromHash(digest, 0, digest.length);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Hashing Alogrithm not available: " + AbeSettings.ELEMENT_HASHING_ALGORITHM, e);
        }
    }
}
