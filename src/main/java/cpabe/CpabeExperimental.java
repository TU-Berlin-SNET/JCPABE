package cpabe;

import it.unisa.dia.gas.jpbc.Element;

import java.io.IOException;
import java.util.ArrayList;

import cpabe.bsw07.Bsw07;
import cpabe.bsw07.Bsw07PrivateKeyComponent;
import cpabe.policy.AttributeParser;
import cpabe.policyparser.ParseException;

public class CpabeExperimental {

    /**
     * This is an experimental feature. It is recommended to not use it.
     * @throws ParseException 
     */
    public static ArrayList<Bsw07PrivateKeyComponent> generateAdditionalAttributes(AbeSecretMasterKey msk, Element prv_d, String attributes) throws ParseException {
        String parsedAttributeSet = AttributeParser.parseAttributes(attributes);
        String[] splitAttributeSet = parsedAttributeSet.split(" ");
        return Bsw07.generateAdditionalAttributes(msk, prv_d, splitAttributeSet);
    }

    /**
     * This is an experimental feature. It is recommended to not use it.
     * @throws ParseException 
     */
    public static AbePrivateKey keyWithAddedAttributes(AbePrivateKey oldKey, AbeSecretMasterKey msk, String newAttributes) throws ParseException {
        ArrayList<Bsw07PrivateKeyComponent> newComponents = generateAdditionalAttributes(msk, oldKey.getD(), newAttributes);
        return oldKey.newKeyWithAddedAttributes(newComponents);
    }
    
    public static AbePrivateKey generatePrivateKeyFromEncrypted(AbeSecretMasterKey secretKey, AbeEncrypted encrypted) {
    	return Bsw07.keygen(secretKey, encrypted.getCipher());
    }
    
    public static byte[] forceDecrypt(AbeSecretMasterKey secretKey, AbeEncrypted encrypted) throws AbeDecryptionException, IOException {
    	return Cpabe.decrypt(generatePrivateKeyFromEncrypted(secretKey, encrypted), encrypted);
    }

}
