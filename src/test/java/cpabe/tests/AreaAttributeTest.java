package cpabe.tests;

import cpabe.*;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import static org.junit.Assert.*;

public class AreaAttributeTest {
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

        byte[] data = TUtil.getRandomData();
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


    private static NumberFormat numberFormat = DecimalFormat.getInstance(Locale.ENGLISH);

    @Test
    public void longPolicy() throws Exception {
        String doctorLocations = "52.507641, 13.394413\n" +
                "52.46112, 13.3853\n" +
                "52.48095, 13.435\n" +
                "52.539303, 13.410184\n" +
                "52.436916, 13.346267\n" +
                "52.545377, 13.360405\n" +
                "52.518217, 13.45404\n" +
                "52.503458, 13.342893\n" +
                "52.538116, 13.419351\n" +
                "52.508383, 13.393924\n" +
                "52.51486, 13.47773\n" +
                "52.48619, 13.332499\n" +
                "52.50134, 13.3154\n" +
                "52.50059, 13.31946\n" +
                "52.500711, 13.330393\n" +
                "52.44236, 13.29757\n" +
                "52.4806, 13.47875\n" +
                "52.44036, 13.38769\n" +
                "52.549622, 13.416334\n" +
                "52.45617, 13.32419\n" +
                "52.476471, 13.280622\n" +
                "52.427626, 13.303971\n" +
                "52.510223, 13.373336\n" +
                "52.48152, 13.3284\n" +
                "52.468403, 13.386001\n" +
                "52.499757, 13.392047\n" +
                "52.52161, 13.38598\n" +
                "52.498802, 13.324886\n" +
                "52.551567, 13.383447\n" +
                "52.46592, 13.30742\n" +
                "52.47997, 13.28437\n" +
                "52.468168, 13.33208\n" +
                "52.524058, 13.408792\n" +
                "52.53708, 13.26779\n" +
                "52.51876, 13.38686\n" +
                "52.452044, 13.270681\n" +
                "52.504864, 13.448288\n" +
                "52.569815, 13.403895\n" +
                "52.49314, 13.38845\n" +
                "52.515981, 13.300466\n" +
                "52.55383, 13.45115\n" +
                "52.492098, 13.457623\n" +
                "52.45809, 13.32312\n" +
                "52.47665, 13.289234\n" +
                "52.512204, 13.312374\n" +
                "52.53687, 13.20462\n" +
                "52.4897, 13.38861\n" +
                "52.514423, 13.4653\n" +
                "52.54961, 13.45769\n" +
                "52.55031, 13.35293\n" +
                "52.484153, 13.434597\n" +
                "52.49519, 13.339709\n" +
                "52.512929, 13.495973\n" +
                "52.506477, 13.560219\n" +
                "52.51039, 13.37365\n" +
                "52.514036, 13.47411\n" +
                "52.511957, 13.385488\n" +
                "52.464243, 13.328107\n" +
                "52.511187, 13.39006\n" +
                "52.456, 13.57608\n" +
                "52.546028, 13.445259\n" +
                "52.55344, 13.45062\n" +
                "52.53072, 13.435744\n" +
                "52.565245, 13.322593\n" +
                "52.526532, 13.340196\n" +
                "52.55205, 13.415345\n" +
                "52.473461, 13.314134\n" +
                "52.55451, 13.410166\n" +
                "52.516351, 13.445223\n" +
                "52.521634, 13.163865\n" +
                "52.433423, 13.259889\n" +
                "52.582009, 13.404328\n" +
                "52.47487, 13.29317\n" +
                "52.503458, 13.342893\n" +
                "52.50038, 13.30767\n" +
                "52.427934, 13.328393\n" +
                "52.48621, 13.35545\n" +
                "52.46836, 13.385017\n" +
                "52.502821, 13.324688\n" +
                "52.49533, 13.4304\n" +
                "52.583905, 13.288525\n" +
                "52.501284, 13.344611\n" +
                "52.50065, 13.33009\n" +
                "52.47175, 13.43981\n" +
                "52.488694, 13.338995\n" +
                "52.468445, 13.431569\n" +
                "52.552595, 13.431979\n" +
                "52.53512, 13.43615\n" +
                "52.58807, 13.286989\n" +
                "52.549105, 13.413268\n" +
                "52.52664, 13.34105\n" +
                "52.46608, 13.46963\n" +
                "52.544248, 13.237079\n" +
                "52.50717, 13.29865\n" +
                "52.446289, 13.316684\n" +
                "52.51028, 13.28126\n" +
                "52.426946, 13.216531\n" +
                "52.4897, 13.38861\n" +
                "52.507543, 13.301815\n" +
                "52.487623, 13.427239\n" +
                "52.440981, 13.458474\n" +
                "52.549977, 13.422918\n" +
                "52.541148, 13.394368\n" +
                "52.50696, 13.32342\n" +
                "52.513495, 13.405446\n" +
                "52.536576, 13.603575\n" +
                "52.50244, 13.34233\n" +
                "52.510894, 13.614498\n" +
                "52.511004, 13.293388\n" +
                "52.527313, 13.479228\n" +
                "52.43664, 13.4499\n" +
                "52.598842, 13.354496\n" +
                "52.51069, 13.27096\n" +
                "52.50175, 13.31377\n" +
                "52.46023, 13.38529\n" +
                "52.51922, 13.19747\n" +
                "52.507419, 13.591931\n" +
                "52.513679, 13.396781\n" +
                "52.452714, 13.509701\n" +
                "52.497555, 13.290522\n" +
                "52.52798, 13.46729\n" +
                "52.587594, 13.286027\n" +
                "52.551132, 13.414406\n" +
                "52.587732, 13.285298\n" +
                "52.52513, 13.343379\n" +
                "52.566871, 13.415698\n" +
                "52.5163, 13.47887\n" +
                "52.423573, 13.435416\n" +
                "52.431961, 13.537387\n" +
                "52.52798, 13.46729\n" +
                "52.510051, 13.373478\n" +
                "52.512187, 13.455249\n" +
                "52.57092, 13.41079\n" +
                "52.555455, 13.561319\n" +
                "52.505, 13.44828\n" +
                "52.5865, 13.37346\n" +
                "52.517742, 13.3889\n" +
                "52.498194, 13.295522\n" +
                "52.54263, 13.54484\n" +
                "52.464879, 13.698563\n" +
                "52.54756, 13.17709\n" +
                "52.428651, 13.328495\n" +
                "52.512929, 13.495973\n" +
                "52.51503, 13.66812\n" +
                "52.567861, 13.572334\n" +
                "52.53222, 13.19827\n" +
                "52.54573, 13.59174\n" +
                "52.54152, 13.61492\n" +
                "52.505476, 13.514923\n" +
                "52.5404, 13.48705\n" +
                "52.53734, 13.37265\n" +
                "52.55442, 13.34576\n" +
                "52.43453, 13.35932\n" +
                "52.458419, 13.323952\n" +
                "52.548576, 13.354921\n" +
                "52.45739, 13.32193\n" +
                "52.44718, 13.57584\n" +
                "52.436665, 13.26109\n" +
                "52.514248, 13.567692\n" +
                "52.526798, 13.414204\n" +
                "52.569446, 13.402262\n" +
                "52.4868, 13.32145\n" +
                "52.500628, 13.330602\n" +
                "52.48424, 13.38376\n" +
                "52.542414, 13.348643\n" +
                "52.44471, 13.57527\n" +
                "52.589602, 13.283312\n" +
                "52.468135, 13.332084\n" +
                "52.446115, 13.385911\n" +
                "52.46271, 13.51542\n" +
                "52.48266, 13.52468\n" +
                "52.55276, 13.34731\n" +
                "52.460753, 13.324702\n" +
                "52.525945, 13.386937\n" +
                "52.466911, 13.32747\n" +
                "52.56097, 13.368682\n" +
                "52.512929, 13.495973\n" +
                "52.43914, 13.45843\n" +
                "52.52744, 13.541491\n" +
                "52.45809, 13.32312\n" +
                "52.429743, 13.457388\n" +
                "52.51195, 13.386834\n" +
                "52.51861, 13.27976\n" +
                "52.516903, 13.389893\n" +
                "52.518514, 13.388343\n" +
                "52.547626, 13.201751\n" +
                "52.488002, 13.340696\n" +
                "52.54469, 13.367369\n" +
                "52.502059, 13.33624\n" +
                "52.505, 13.44828\n" +
                "52.53948, 13.39465\n" +
                "52.461093, 13.385185\n" +
                "52.50175, 13.31377\n" +
                "52.50134, 13.3154\n" +
                "52.43185, 13.537278\n" +
                "52.484084, 13.383828\n" +
                "52.526728, 13.413845\n" +
                "52.52196, 13.38064\n" +
                "52.526728, 13.413845\n" +
                "52.51039, 13.37365";

        String[] splitLocations = doctorLocations.split("\n");
        List<Location> actualLocations = new ArrayList<>(splitLocations.length);
        for (String singleLocation : splitLocations) {
            String[] singleLocationSplit = singleLocation.split(", ");
            if (singleLocationSplit.length != 2) {
                System.err.println("singleLocation wrong: "+ singleLocation);
                fail("Test setup wrong");
            }
            double lat = numberFormat.parse(singleLocationSplit[0]).doubleValue();
            double lon = numberFormat.parse(singleLocationSplit[1]).doubleValue();
            actualLocations.add(new Location(lat, lon));
        }

        StringBuilder policyBuilder = new StringBuilder();
        String attributeName = "location";
        for (Location location : actualLocations) {
            policyBuilder.append(location.getPolicyString(attributeName));
            policyBuilder.append(" or ");
        }
        String policy = policyBuilder.substring(0, policyBuilder.length() - " or ".length());
        System.out.println("Policy: " + policy);

        AbeSecretMasterKey secretKey = AbeSecretMasterKey.readFromFile(TUtil.getExampleSecretKey("lz_secret_key"));
        AbePublicKey pubkey = secretKey.getPublicKey();

        System.out.println("Start keygen: " + AbeSettings.getCurrentTime());
        long keygenStart = System.nanoTime();
        AbePrivateKey pk1   = Cpabe.keygen(secretKey, "location~52.507641~13.394413");
        AbePrivateKey pk50  = Cpabe.keygen(secretKey, "location~52.55031~13.35293");
        AbePrivateKey pk100 = Cpabe.keygen(secretKey, "location~52.487623~13.427239");
        AbePrivateKey pk150 = Cpabe.keygen(secretKey, "location~52.5404~13.48705");
        AbePrivateKey pk200 = Cpabe.keygen(secretKey, "location~52.51039~13.37365");
        long keygenEnd = System.nanoTime();
        System.out.println("Stop keygen: " + AbeSettings.getCurrentTime());
        System.out.println(String.format("this operation took %fs.", (keygenEnd - keygenStart) / 1E9d));

        byte[] data = TUtil.getRandomData();

        System.out.println("Start encryption: " + AbeSettings.getCurrentTime());
        long decryptionStart = System.nanoTime();
        AbeEncrypted encrypted = Cpabe.encrypt(pubkey, policy, data);
        long decryptionEnd = System.nanoTime();
        System.out.println("Stop encryption: " + AbeSettings.getCurrentTime());
        System.out.println(String.format("this operation took %fs.", (decryptionEnd - decryptionStart) / 1E9d));
        ByteArrayInputStream baisEncrypted = TUtil.getReusableStream(encrypted, pubkey);

        assertTrue(Arrays.equals(data, decrypt(pk1, AbeEncrypted.readFromStream(pubkey, baisEncrypted))));
        baisEncrypted.reset();
        assertTrue(Arrays.equals(data, decrypt(pk50, AbeEncrypted.readFromStream(pubkey, baisEncrypted))));
        baisEncrypted.reset();
        assertTrue(Arrays.equals(data, decrypt(pk100, AbeEncrypted.readFromStream(pubkey, baisEncrypted))));
        baisEncrypted.reset();
        assertTrue(Arrays.equals(data, decrypt(pk150, AbeEncrypted.readFromStream(pubkey, baisEncrypted))));
        baisEncrypted.reset();
        assertTrue(Arrays.equals(data, decrypt(pk200, AbeEncrypted.readFromStream(pubkey, baisEncrypted))));
        baisEncrypted.reset();
    }

    private static class Location {
        double lat;
        double lon;

        public Location(double lat, double lon) {
            this.lat = lat;
            this.lon = lon;
        }

        public String getPolicyString(String attributeName) {
            double lonDiff = 0.001;
            double latDiff = lonDiff/2;

            double minLon = lon - lonDiff;
            double maxLon = lon + lonDiff;
            double minLat = lat - latDiff;
            double maxLat = lat + latDiff;

            return attributeName + "~" + minLat + "~" + minLon + "~" + maxLat + "~" + maxLon;
        }
    }
}
