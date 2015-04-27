package cpabe.tests;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

import java.security.SecureRandom;
import java.util.Arrays;

import org.junit.BeforeClass;
import org.junit.Test;

import cpabe.AbeEncrypted;
import cpabe.AbePrivateKey;
import cpabe.AbePublicKey;
import cpabe.AbeSecretMasterKey;
import cpabe.Cpabe;

public class AreaAttributeTest {
	
    private static SecureRandom random;
    
    @BeforeClass
    public static void testSetup() {
        random = new SecureRandom();
    }
	
    public byte[] getRandomData() {
        byte[] data = new byte[random.nextInt(100) + 20];
        random.nextBytes(data);
        return data;
    }

    // so we dont need to check for exceptions every time we want to decrypt
    private byte[] decrypt(AbePrivateKey privateKey, AbeEncrypted encryptedData) {
        try {
            return Cpabe.decrypt(privateKey, encryptedData);
        } catch (Exception e) {
            return null;
        }
    }
	
    @Test
    public void areaAttributes() throws Exception {
		AbeSecretMasterKey secretMasterkey = Cpabe.setup();
		AbePublicKey pubKey = secretMasterkey.getPublicKey();
		
		byte[] data = getRandomData();
		String policyBerlin = "location~52.288323~13.059998~52.609719~13.785095";
		String policySchwerin = "location~53.609618~11.362267~53.652778~11.438484";
		
		AbeEncrypted policyBerlinEncryptedTest1 = Cpabe.encrypt(pubKey, policyBerlin, data);
		AbeEncrypted policySchwerinEncryptedTest1 = Cpabe.encrypt(pubKey, policySchwerin, data);
		
		AbeEncrypted policyBerlinEncryptedTest2 = Cpabe.encrypt(pubKey, policyBerlin, data);
		AbeEncrypted policySchwerinEncryptedTest2 = Cpabe.encrypt(pubKey, policySchwerin, data);
		
		AbeEncrypted policyBerlinEncryptedTest3 = Cpabe.encrypt(pubKey, policyBerlin, data);
		AbeEncrypted policySchwerinEncryptedTest3 = Cpabe.encrypt(pubKey, policySchwerin, data);
		
		AbeEncrypted policyBerlinEncryptedTest4 = Cpabe.encrypt(pubKey, policyBerlin, data);
		AbeEncrypted policySchwerinEncryptedTest4 = Cpabe.encrypt(pubKey, policySchwerin, data);
		
		String inBerlin = "location~52.527919~13.403320";
		String outsideBerlin = "location~51.337476~12.403564";
		String inSchwerin = "location~53.636903~11.405182";
		String outsideSchwerin = "location~53.876821~11.458740";
		
		AbePrivateKey inBerlinKey = Cpabe.keygen(secretMasterkey, inBerlin);
		AbePrivateKey outsideBerlinKey = Cpabe.keygen(secretMasterkey, outsideBerlin);
		AbePrivateKey inSchwerinKey = Cpabe.keygen(secretMasterkey, inSchwerin);
		AbePrivateKey outsideSchwerinKey = Cpabe.keygen(secretMasterkey, outsideSchwerin);
		
		//Berlin Policy
		assertTrue(Arrays.equals(data, decrypt(inBerlinKey, policyBerlinEncryptedTest1)));
		assertFalse(Arrays.equals(data, decrypt(outsideBerlinKey, policyBerlinEncryptedTest2)));
		assertFalse(Arrays.equals(data, decrypt(inSchwerinKey, policyBerlinEncryptedTest3)));
		assertFalse(Arrays.equals(data, decrypt(outsideSchwerinKey, policyBerlinEncryptedTest4)));
		
		//Schwerin Policy
		assertFalse(Arrays.equals(data, decrypt(inBerlinKey, policySchwerinEncryptedTest1)));
		assertFalse(Arrays.equals(data, decrypt(outsideBerlinKey, policySchwerinEncryptedTest2)));
		assertTrue(Arrays.equals(data, decrypt(inSchwerinKey, policySchwerinEncryptedTest3)));
		assertFalse(Arrays.equals(data, decrypt(outsideSchwerinKey, policySchwerinEncryptedTest4)));
    }
    

}
