namespace CryptoBase.SpeedTest.Measuring;

/// <summary>
/// Checks every workload of the selected algorithms without timing them,.
/// </summary>
internal static class SelfTest
{
	/// <returns>The number of workloads that failed.</returns>
	public static int Run(ImmutableArray<AlgorithmEntry> algorithms, ImmutableArray<int> inputSizes, TextWriter writer)
	{
		long start = Stopwatch.GetTimestamp();
		int count = 0;
		int failed = 0;

		foreach (AlgorithmEntry algorithm in algorithms)
		{
			foreach (string operation in algorithm.Operations)
			{
				switch (algorithm.Metric)
				{
					case Metric.Throughput:
					{
						foreach (int inputSize in inputSizes)
						{
							if (algorithm.SupportsInputSize(inputSize))
							{
								Check(algorithm, operation, inputSize);
							}
						}

						break;
					}
					case Metric.Operations:
					{
						Check(algorithm, operation, null);
						break;
					}
					default:
					{
						throw new UnreachableException();
					}
				}
			}
		}

		TimeSpan elapsed = Stopwatch.GetElapsedTime(start);
		writer.WriteLine(FormattableString.Invariant($"Tested {count} workload(s) of {algorithms.Length} algorithm(s) in {ReportFormat.FormatDuration(elapsed)}: {(failed is 0 ? "all passed" : $"{failed} failed")}."));
		return failed;

		void Check(AlgorithmEntry algorithm, string operation, int? inputSize)
		{
			++count;

			try
			{
				using Workload workload = algorithm.CreateWorkload(operation, inputSize ?? 0);
				workload.Verify();
				workload.Run(1);
			}
			catch (Exception ex)
			{
				++failed;
				string where = inputSize is { } size ? FormattableString.Invariant($"{operation} {size} bytes") : operation;
				writer.WriteLine($"error: {algorithm.Name} {where}: {ex.GetType().Name}: {ex.Message}");
			}
		}
	}
}
