namespace CryptoBase.SpeedTest.Measuring;

/// <summary>
/// Summarizes the rates of the samples of one cell, in units (bytes or operations) per second.
/// </summary>
/// <param name="CoefficientOfVariation">The sample standard deviation divided by the mean, or 0 for a single sample.</param>
/// <param name="IterationsPerSample">The number of iterations that each worker ran in each sample.</param>
internal sealed record SampleStatistics(double Median, double Min, double Max, double CoefficientOfVariation, int SampleCount, long IterationsPerSample)
{
	public static SampleStatistics FromRates(Span<double> rates, long iterationsPerSample)
	{
		rates.Sort();
		int count = rates.Length;
		double median = (rates[(count - 1) / 2] + rates[count / 2]) / 2;

		double mean = 0;

		foreach (double rate in rates)
		{
			mean += rate;
		}

		mean /= count;

		double variance = 0;

		foreach (double rate in rates)
		{
			variance += (rate - mean) * (rate - mean);
		}

		double cv = count > 1 ? Math.Sqrt(variance / (count - 1)) / mean : 0;

		return new SampleStatistics(median, rates[0], rates[^1], cv, count, iterationsPerSample);
	}
}
