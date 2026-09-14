namespace CryptoBase.SpeedTest;

internal sealed class CryptoTest(int bufferSize, double seconds)
{
	public static ReadOnlySpan<byte> Key =>
	[
		0, 1, 2, 3, 4, 5, 6, 7, 8,
		9, 10, 11, 12, 13, 14, 15,
		16, 17, 18, 19, 20, 21, 22, 23,
		24, 25, 26, 27, 28, 29, 30, 31
	];

	public static ReadOnlySpan<byte> IV =>
	[
		0, 1, 2, 3, 4, 5, 6, 7, 8,
		9, 10, 11, 12, 13, 14, 15,
		16, 17, 18, 19, 20, 21, 22, 23,
		24, 25, 26, 27, 28, 29, 30, 31
	];

	private const double TargetBatchSeconds = 0.02;

	private const int SampleCount = 10;

	internal const double MinimumSeconds = SampleCount * TargetBatchSeconds;

	public void TestStream<T>(T crypto) where T : IStreamCipher
	{
		byte[] input = RandomNumberGenerator.GetBytes(bufferSize);
		byte[] output = new byte[bufferSize];

		Measure(() => crypto.Xor(input, output));
	}

	public void TestAead<T>(T crypto) where T : IAeadCipher<T>
	{
		byte[] input = RandomNumberGenerator.GetBytes(bufferSize);
		byte[] output = new byte[input.Length];
		byte[] nonce = [.. IV.Slice(0, T.NonceSize)];
		byte[] tag = new byte[T.TagSize];

		Measure(() => crypto.Encrypt(nonce, input, output, tag));
	}

	public void TestDataUnit<T>(T crypto) where T : IDataUnitCipher<T>
	{
		byte[] input = RandomNumberGenerator.GetBytes(bufferSize);
		byte[] output = new byte[bufferSize];
		byte[] iv = [.. IV.Slice(0, T.TweakSize)];

		Measure(() => crypto.Encrypt(iv, input, output));
	}

	private void Measure(Action operation)
	{
		long opsPerBatch = WarmupAndCalibrate(operation);
		long sampleTicks = (long)(seconds / SampleCount * Stopwatch.Frequency);
		Span<double> throughputs = stackalloc double[SampleCount];

		for (int i = 0; i < SampleCount; ++i)
		{
			long ops = 0;
			long elapsed = 0;

			do
			{
				long start = Stopwatch.GetTimestamp();

				for (long j = 0; j < opsPerBatch; ++j)
				{
					operation();
				}

				elapsed += Stopwatch.GetTimestamp() - start;
				ops += opsPerBatch;
			} while (elapsed < sampleTicks);

			throughputs[i] = ops * (double)bufferSize * Stopwatch.Frequency / elapsed;
		}

		throughputs.Sort();
		double median = (throughputs[(SampleCount - 1) / 2] + throughputs[SampleCount / 2]) / 2.0;

		Console.WriteLine($@"{median / 1024.0 / 1024.0:F2} MiB/s (CV {CoefficientOfVariation(throughputs):P1})");
	}

	private long WarmupAndCalibrate(Action operation)
	{
		double warmupSeconds = Math.Clamp(seconds / 3.0, 0.2, 1.0);
		long warmupTicks = (long)(warmupSeconds * Stopwatch.Frequency);
		long targetBatchTicks = (long)(TargetBatchSeconds * Stopwatch.Frequency);
		long opsPerBatch = 1;
		long warmupElapsed = 0;
		bool batchCalibrated;

		do
		{
			long start = Stopwatch.GetTimestamp();

			for (long i = 0; i < opsPerBatch; ++i)
			{
				operation();
			}

			long batchTicks = Stopwatch.GetTimestamp() - start;
			warmupElapsed += batchTicks;
			batchCalibrated = batchTicks >= targetBatchTicks || opsPerBatch > long.MaxValue / 2;

			if (!batchCalibrated)
			{
				opsPerBatch *= 2;
			}
		} while (warmupElapsed < warmupTicks || !batchCalibrated);

		return opsPerBatch;
	}

	private static double CoefficientOfVariation(ReadOnlySpan<double> samples)
	{
		double mean = 0.0;

		foreach (double sample in samples)
		{
			mean += sample;
		}

		mean /= samples.Length;

		double variance = 0.0;

		foreach (double sample in samples)
		{
			variance += (sample - mean) * (sample - mean);
		}

		variance /= samples.Length - 1;

		return Math.Sqrt(variance) / mean;
	}
}
