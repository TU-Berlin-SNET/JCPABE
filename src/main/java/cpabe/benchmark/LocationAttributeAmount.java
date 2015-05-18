package cpabe.benchmark;

/**
 * Created by iwolapubuntu on 18.05.15.
 */
public class LocationAttributeAmount extends Benchmark {
    @Override
    public void singleRun(int iteration) {

    }

    @Override
    public int numWarmupRuns() {
        return 5;
    }

    @Override
    public int numIterations() {
        return 1;
    }

    @Override
    public int numRunsPerIteration() {
        return 2;
    }
}
