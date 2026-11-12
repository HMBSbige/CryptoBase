using System.Runtime;

namespace CryptoBase.SpeedTest.Measuring;

/// <param name="WarmupSeconds">The least warm-up time of each row, or of each operation of an operation row; 0 skips the warm-up.</param>
internal sealed record MeasurementSettings(double Seconds, double WarmupSeconds, int Threads)
{
	public const int SampleCount = 10;

	/// <summary>
	/// The fewest samples of an operation slower than a sample, each of which is then one iteration.
	/// </summary>
	public const int MinimumSlowSampleCount = 3;
}

/// <param name="TicksPerIteration">The time per iteration of each runner in its last batch, in <see cref="Stopwatch" /> ticks, or <see cref="double.NaN" /> if it has not run.</param>
/// <param name="Summary">How long the warm-up took, or <see langword="null" /> if it was skipped.</param>
internal sealed record WarmupResult(double[] TicksPerIteration, WarmupSummary? Summary);

internal sealed class Measurer(MeasurementSettings settings)
{
	/// <summary>
	/// The target length of a warm-up batch.
	/// </summary>
	/// <remarks>
	/// Tiered compilation promotes a method in two steps, to instrumented code and then to Tier1 with PGO, each after about 30 calls and a delay
	/// that restarts whenever a method is compiled for the first time. <see cref="Workload.Run" /> is itself a loop that is called once per batch,
	/// so short batches call it thousands of times during the warm-up, and it reaches Tier1 along with the methods it calls.
	/// </remarks>
	private static readonly long WarmupBatchTicks = Math.Max(1, Stopwatch.Frequency / 4000);

	/// <summary>
	/// How long the JIT must have compiled nothing for a warm-up to end.
	/// </summary>
	/// <remarks>
	/// Between two steps of tiered compilation the count of compiled methods stands still while the runtime waits out its call-counting delay,
	/// 100 ms by default, which methods called for the first time extend. Measured on every row, such a pause lasts about 200 to 230 ms, and rarely
	/// up to 300 ms, so a shorter quiet time could end the warm-up before the code it runs reaches Tier1.
	/// </remarks>
	private static readonly long JitQuietTicks = 3 * Stopwatch.Frequency / 10;

	/// <summary>
	/// How far past the warm-up time a warm-up can run while the JIT is still compiling, so that it ends even if the JIT never settles.
	/// </summary>
	private static readonly long MaximumWarmupExtensionTicks = 5 * Stopwatch.Frequency;

	private readonly long _sampleTicks = Math.Max(1, (long)(settings.Seconds * Stopwatch.Frequency / MeasurementSettings.SampleCount));

	private bool AwaitsJit { get; init; } = true;

	/// <summary>
	/// Runs the measuring code once on a workload that does nothing, so that its first compilation does not happen in the middle of the first row
	/// and restart the delay of tiered compilation there.
	/// </summary>
	public static void PrimeHarness(int threads)
	{
		using IBatchRunner runner = threads > 1 ? new MultiThreadBatchRunner([new IdleWorkload(), new IdleWorkload()]) : new SingleThreadBatchRunner(new IdleWorkload());
		Measurer measurer = new(new MeasurementSettings(1e-4, 1e-4, threads)) { AwaitsJit = false };
		measurer.Measure(runner, 1, measurer.Warmup([runner]).TicksPerIteration[0]);
		measurer.Measure(runner, 1, double.NaN);
	}

	/// <summary>
	/// Runs short batches of every runner in turn for at least the warm-up time and until the JIT has compiled nothing for <see cref="JitQuietTicks" />,
	/// but no longer than <see cref="MaximumWarmupExtensionTicks" /> past the warm-up time.
	/// </summary>
	/// <remarks>
	/// The count of compiled methods includes the recompilations that tiered compilation makes on its background thread, so it stops changing
	/// once the code that the runners call has reached its final tier. Native AOT compiles nothing at run time, so its warm-up takes the warm-up time.
	/// </remarks>
	public WarmupResult Warmup(IReadOnlyList<IBatchRunner> runners)
	{
		double[] ticksPerIteration = new double[runners.Count];
		ticksPerIteration.AsSpan().Fill(double.NaN);

		if (settings.WarmupSeconds <= 0 || runners.Count is 0)
		{
			return new WarmupResult(ticksPerIteration, null);
		}

		long[] iterations = new long[runners.Count];
		iterations.AsSpan().Fill(1);
		long start = Stopwatch.GetTimestamp();
		long minimumEnd = start + (long)(settings.WarmupSeconds * Stopwatch.Frequency);
		long maximumEnd = minimumEnd + MaximumWarmupExtensionTicks;
		long compiledMethods = JitInfo.GetCompiledMethodCount();
		long lastCompilation = start;
		long now;

		while (true)
		{
			for (int i = 0; i < runners.Count; ++i)
			{
				long ticks = runners[i].RunBatch(iterations[i]);

				// A batch shorter than a tick of the clock says nothing of the time per iteration.
				if (ticks > 0)
				{
					ticksPerIteration[i] = (double)ticks / iterations[i];
				}

				if (ticks < WarmupBatchTicks / 2 && iterations[i] <= long.MaxValue / 2)
				{
					iterations[i] *= 2;
				}
			}

			now = Stopwatch.GetTimestamp();
			long count = JitInfo.GetCompiledMethodCount();

			if (count != compiledMethods)
			{
				compiledMethods = count;
				lastCompilation = now;
			}

			if (now >= minimumEnd && (!AwaitsJit || now - lastCompilation >= JitQuietTicks) || now >= maximumEnd)
			{
				break;
			}
		}

		return new WarmupResult(ticksPerIteration, new WarmupSummary(Stopwatch.GetElapsedTime(start, now), now - lastCompilation >= JitQuietTicks));
	}

	/// <param name="unitsPerIteration">The bytes or operations of one iteration of one worker.</param>
	/// <param name="ticksPerIteration">The time per iteration from the warm-up, or <see cref="double.NaN" />.</param>
	public SampleStatistics Measure(IBatchRunner runner, double unitsPerIteration, double ticksPerIteration)
	{
		if (double.IsNaN(ticksPerIteration) || ticksPerIteration < _sampleTicks)
		{
			ticksPerIteration = Calibrate(runner, ticksPerIteration);
		}

		// Dividing by zero below would ask for a batch that never ends.
		if (!(ticksPerIteration > 0))
		{
			throw new InvalidOperationException("The workload takes no measurable time.");
		}

		return ticksPerIteration >= _sampleTicks
			? SampleSlow(runner, unitsPerIteration)
			: Sample(runner, unitsPerIteration, Math.Max(1, (long)Math.Round(_sampleTicks / ticksPerIteration)));
	}

	/// <summary>
	/// Times a batch of about an eighth of a sample, which also runs this input size again after the others of its row.
	/// </summary>
	private double Calibrate(IBatchRunner runner, double ticksPerIteration)
	{
		long target = Math.Max(1, _sampleTicks / 8);
		long iterations = ticksPerIteration > 0 ? Math.Max(1, (long)(target / ticksPerIteration)) : 1;

		while (true)
		{
			long ticks = runner.RunBatch(iterations);

			if (ticks >= target || iterations > long.MaxValue / 8)
			{
				return (double)ticks / iterations;
			}

			iterations *= ticks * 8 < target ? 8 : 2;
		}
	}

	private static SampleStatistics Sample(IBatchRunner runner, double unitsPerIteration, long iterations)
	{
		Span<double> rates = stackalloc double[MeasurementSettings.SampleCount];
		double units = iterations * runner.WorkerCount * unitsPerIteration * Stopwatch.Frequency;

		for (int i = 0; i < rates.Length; ++i)
		{
			rates[i] = units / Math.Max(1, runner.RunBatch(iterations));
		}

		return SampleStatistics.FromRates(rates, iterations);
	}

	/// <summary>
	/// Times one iteration per sample, until the cell's time has passed, but at least <see cref="MeasurementSettings.MinimumSlowSampleCount" /> times.
	/// </summary>
	private SampleStatistics SampleSlow(IBatchRunner runner, double unitsPerIteration)
	{
		Span<double> rates = stackalloc double[MeasurementSettings.SampleCount];
		double units = runner.WorkerCount * unitsPerIteration * Stopwatch.Frequency;
		long totalTicks = 0;
		int count = 0;

		while (count < rates.Length && (count < MeasurementSettings.MinimumSlowSampleCount || totalTicks < _sampleTicks * MeasurementSettings.SampleCount))
		{
			long ticks = Math.Max(1, runner.RunBatch(1));
			totalTicks += ticks;
			rates[count++] = units / ticks;
		}

		return SampleStatistics.FromRates(rates.Slice(0, count), 1);
	}
}

file sealed class IdleWorkload : Workload
{
	private long _count;

	public override void Verify()
	{
	}

	public override void Run(long iterations)
	{
		// A volatile write per iteration keeps the JIT from folding the loop into one addition, which would take no measurable time.
		for (long i = 0; i < iterations; ++i)
		{
			Volatile.Write(ref _count, _count + 1);
		}
	}
}
