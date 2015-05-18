package cpabe.benchmark;

import java.io.File;
import java.io.IOException;
import java.util.UUID;

import cpabe.AbeSecretMasterKey;
import cpabe.Cpabe;

public class CpabeKeygenAttributeNumberTest extends Benchmark {
	private AbeSecretMasterKey msk;
	private String attributes = "";
	
	
	@Override
	public void initializeIteration(int iteration) {
		if (iteration == Benchmark.WARMUP) iteration = 2;
		attributes = UUID.randomUUID().toString();
		for (int i = 0; i < iteration; i++) {
			attributes += " " + UUID.randomUUID();
		}
	}
	
	@Override
	public void singleRun(int iteration) {
		try {
			Cpabe.keygen(msk, attributes);
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
