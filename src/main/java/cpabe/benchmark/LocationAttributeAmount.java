package cpabe.benchmark;

import cpabe.*;
import sun.rmi.runtime.Log;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Measures the time to decrypt a file that has been encrypted with 2^iteration location attributes (combined with or)
 */
public class LocationAttributeAmount extends Benchmark {
    private AbeSecretMasterKey msk;
    private AbePrivateKey privateKey;
    private byte[] data;
    private byte[] encryptedData;


    @Override
    public void initializeIteration(int iteration) {
        if (iteration == Benchmark.WARMUP) iteration = 2;
        int numPolicyNodes = (int) Math.pow(2, iteration);
        List<String> policyNodes = new ArrayList<String>(numPolicyNodes);
        for (int i = 1; i < numPolicyNodes; i++) {
            String policyNode = ""; //filler
            policyNodes.add(policyNode);
        }
        policyNodes.add(""); // this is the one the attributes fulfill
        StringBuilder concatNodes = new StringBuilder();
        boolean first = true;
        for (String policyNode : policyNodes) {
            if (!first) concatNodes.append(" OR ");
            else first = false;
            concatNodes.append(policyNode);
        }
        try {
            AbeEncrypted encrypted = Cpabe.encrypt(msk.getPublicKey(), concatNodes.toString(), data);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            encrypted.writeEncryptedData(baos, msk.getPublicKey());
            encryptedData = baos.toByteArray();
        } catch (Exception e) {
            Logger.getLogger(LocationAttributeAmount.class.toString()).log(Level.SEVERE, "Exiting benchmark because encryption failed", e);
            System.exit(0);
        }
        // encrypt
    }

    @Override
    public void singleRun(int iteration) {

        try {
            ByteArrayInputStream bais = new ByteArrayInputStream(encryptedData);
            AbeEncrypted encrypted = AbeEncrypted.readFromStream(msk.getPublicKey(), bais); // ideally this wouldnt be part of the run
            Cpabe.decrypt(privateKey, encrypted);
        } catch (Exception e) {
            Logger.getLogger(LocationAttributeAmount.class.toString()).log(Level.SEVERE, "Exiting benchmark because decryption failed", e);
            System.exit(0);
        }
    }

    @Override
    public void initializeBenchmark() {
        try {
            msk = AbeSecretMasterKey.readFromFile(new File("res/bench.msk"));
            privateKey = Cpabe.keygen(msk, "location:lat:lon"); //TODO
        } catch (Exception e) {
            throw new RuntimeException("exception thrown during initialization");
        }
        data = new byte[255]; // not actually relevant, since we dont really encrypt this
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i % 256);
        }
    }

    @Override
    public int numWarmupRuns() {
        return 2;
    }

    @Override
    public int numIterations() {
        return 11;
    } // 0 - 10 -> 2^0 - 2^10 == 1 - 1024

    @Override
    public int numRunsPerIteration() {
        return 2;
    }

}

