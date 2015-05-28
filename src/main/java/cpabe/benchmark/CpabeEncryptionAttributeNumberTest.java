package cpabe.benchmark;

import cpabe.AbeSecretMasterKey;
import cpabe.Cpabe;

import java.io.File;
import java.io.IOException;

public class CpabeEncryptionAttributeNumberTest extends Benchmark {

    private byte[] data;

    private AbeSecretMasterKey msk;
    private String policy = "";


    @Override
    public void initializeIteration(int iteration) {
        if (iteration == Benchmark.WARMUP) iteration = 2;
        policy = "a";
        for (int i = 0; i < iteration; i++) {
            policy += " and a";
        }
    }

    @Override
    public void singleRun(int iteration) {
        try {
            Cpabe.encrypt(msk.getPublicKey(), policy, data); // hope this doesnt get optimized away
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
