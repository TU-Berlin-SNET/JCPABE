package cpabe.tests;

import cpabe.*;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

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

        AbeEncrypted policyBerlinEncryptedTest = Cpabe.encrypt(pubKey, policyBerlin, data);
        AbeEncrypted policySchwerinEncryptedTest = Cpabe.encrypt(pubKey, policySchwerin, data);

        ByteArrayInputStream baisBerlin = TUtil.getReusableStream(policyBerlinEncryptedTest, pubKey);
        ByteArrayInputStream baisSchwerin = TUtil.getReusableStream(policySchwerinEncryptedTest, pubKey);

        String inBerlin = "location~52.527919~13.403320";
        String outsideBerlin = "location~51.337476~12.403564";
        String inSchwerin = "location~53.636903~11.405182";
        String outsideSchwerin = "location~53.876821~11.458740";

        AbePrivateKey inBerlinKey = Cpabe.keygen(secretMasterkey, inBerlin);
        AbePrivateKey outsideBerlinKey = Cpabe.keygen(secretMasterkey, outsideBerlin);
        AbePrivateKey inSchwerinKey = Cpabe.keygen(secretMasterkey, inSchwerin);
        AbePrivateKey outsideSchwerinKey = Cpabe.keygen(secretMasterkey, outsideSchwerin);

        //Berlin Policy
        assertTrue(Arrays.equals(data, decrypt(inBerlinKey, AbeEncrypted.readFromStream(pubKey, baisBerlin))));
        baisBerlin.reset();
        assertFalse(Arrays.equals(data, decrypt(outsideBerlinKey, AbeEncrypted.readFromStream(pubKey, baisBerlin))));
        baisBerlin.reset();
        assertFalse(Arrays.equals(data, decrypt(inSchwerinKey, AbeEncrypted.readFromStream(pubKey, baisBerlin))));
        baisBerlin.reset();
        assertFalse(Arrays.equals(data, decrypt(outsideSchwerinKey, AbeEncrypted.readFromStream(pubKey, baisBerlin))));

        //Schwerin Policy
        assertFalse(Arrays.equals(data, decrypt(inBerlinKey, AbeEncrypted.readFromStream(pubKey, baisSchwerin))));
        baisSchwerin.reset();
        assertFalse(Arrays.equals(data, decrypt(outsideBerlinKey, AbeEncrypted.readFromStream(pubKey, baisSchwerin))));
        baisSchwerin.reset();
        assertTrue(Arrays.equals(data, decrypt(inSchwerinKey, AbeEncrypted.readFromStream(pubKey, baisSchwerin))));
        baisSchwerin.reset();
        assertFalse(Arrays.equals(data, decrypt(outsideSchwerinKey, AbeEncrypted.readFromStream(pubKey, baisSchwerin))));
    }
}
