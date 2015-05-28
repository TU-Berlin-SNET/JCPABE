package cpabe.benchmark;

import cpabe.AbeEncrypted;
import cpabe.AbePrivateKey;
import cpabe.AbeSecretMasterKey;
import cpabe.Cpabe;
import cpabe.bsw07.Bsw07;

import java.io.File;
import java.io.IOException;
import java.util.UUID;

public class CpabeDecryptionOrAttributeNumberTest extends Benchmark {

    private byte[] data;

    private AbeSecretMasterKey msk;
    private AbePrivateKey privateKey;
    private AbeEncrypted encrypted;


    @Override
    public void initializeIteration(int iteration) {
        if (iteration == Benchmark.WARMUP) iteration = 2;
        String[] splitAttributes = new String[iteration + 1]; // at least one

        for (int i = 0; i < splitAttributes.length; i++) {
            splitAttributes[i] = "a" + UUID.randomUUID().toString().replace('-', '0'); // policy attribute have to begin with a letter
        }

        String policy = splitAttributes[0];
        String attributes = splitAttributes[0];
        for (int i = 1; i < splitAttributes.length; i++) {
            attributes += " " + splitAttributes[i];
            policy += " or " + splitAttributes[i];
        }

        try {
            encrypted = Cpabe.encrypt(msk.getPublicKey(), policy, data);
            privateKey = Cpabe.keygen(msk, attributes);
        } catch (Exception e) {
            throw new RuntimeException("exception thrown iteration initialization", e);
        }
    }

    @Override
    public void singleRun(int iteration) {
        try {
            Bsw07.decrypt(privateKey, encrypted.getCipher());
        } catch (Exception e) {
            throw new RuntimeException("exception thrown during test", e);
        }
    }

    @Override
    public void initializeBenchmark() {
        try {
            msk = AbeSecretMasterKey.readFromFile(new File("res/bench.msk"));
        } catch (IOException e) {
            throw new RuntimeException("exception thrown during initialization");
        }
        data = new byte[255]; // not actually relevant, since we dont really encrypt this
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i % 256);
        }
    }

    @Override
    public int numWarmupRuns() {
        return 5;
    }

    @Override
    public int numIterations() {
        return 20;
    }

    @Override
    public int numRunsPerIteration() {
        return 5;
    }

}
