package cpabe.benchmark;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;

public class BenchmarkRunner {
	public static BenchmarkResult runBenchmark(Benchmark benchmark) {
		if (!verifyOptions(benchmark)) return null;

		benchmark.initializeBenchmark();
		int warmupRuns = benchmark.numWarmupRuns();
		benchmark.initializeIteration(Benchmark.WARMUP);
		for (int i = 0; i < warmupRuns; i++) {
			benchmark.singleRun(Benchmark.WARMUP);
		}
		benchmark.destroyIteration(Benchmark.WARMUP);
		
		int testRuns = benchmark.numIterations();
		int runsPerRun = benchmark.numRunsPerIteration();
		BenchmarkResult result = new BenchmarkResult(testRuns);
		
		for (int iteration = 0; iteration < testRuns; iteration++) {
			benchmark.initializeIteration(iteration);
			long start = System.nanoTime();
			for (int i = 0; i < runsPerRun; i++) {
				benchmark.singleRun(iteration);
			}
			long end = System.nanoTime();
			double average = (end - start) / (double) runsPerRun;
			benchmark.destroyIteration(iteration);
			result.addResult(average);
		}
		benchmark.destroyBenchmark();
		return result;
	}
	
	public static BenchmarkResult runBenchmark(Benchmark benchmark, File output) throws IOException {
		BenchmarkResult result = runBenchmark(benchmark);
		PrintWriter writer = new PrintWriter(new BufferedWriter(new FileWriter(output)));
		writer.write(result.toString());
		writer.close();
		return result;
	}
	
	
	private static boolean verifyOptions(Benchmark benchmark) {
		if (benchmark.numRunsPerIteration() <= 0) throw new IllegalArgumentException("numRunsPerRun can't be 0 or lower");
		if (benchmark.numWarmupRuns() < 0) throw new IllegalArgumentException("numWarmupRuns can't be lower than 0");
		if (benchmark.numIterations() <= 0) throw new IllegalArgumentException("numTestRuns can't be 0 or lower");
		return true;
	}
}
