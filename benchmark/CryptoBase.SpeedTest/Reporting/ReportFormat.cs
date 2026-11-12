namespace CryptoBase.SpeedTest.Reporting;

internal static class ReportFormat
{
	/// <summary>
	/// The coefficient of variation above which a cell is flagged as noisy.
	/// </summary>
	public const double NoisyCoefficientOfVariation = 0.05;

	private const double BytesPerMebibyte = 1024 * 1024;

	public static string NoisyNote { get; } = FormattableString.Invariant($"The samples of the cell vary by more than {NoisyCoefficientOfVariation * 100:0}% (coefficient of variation); rerun it, or raise --seconds.");

	public static bool IsNoisy(SampleStatistics statistics)
	{
		return statistics.CoefficientOfVariation > NoisyCoefficientOfVariation;
	}

	public static string GetUnit(Metric metric)
	{
		return metric switch
		{
			Metric.Throughput => "MiB/s",
			Metric.Operations => "ops/s",
			_ => throw new UnreachableException()
		};
	}

	/// <summary>
	/// Converts a rate in bytes or operations per second to the unit of <see cref="GetUnit" />.
	/// </summary>
	public static double ToUnit(double rate, Metric metric)
	{
		return metric switch
		{
			Metric.Throughput => rate / BytesPerMebibyte,
			Metric.Operations => rate,
			_ => throw new UnreachableException()
		};
	}

	public static string FormatRate(double rate, Metric metric)
	{
		return ToUnit(rate, metric).ToString("0.0", CultureInfo.InvariantCulture);
	}

	public static string GetGroupTitle(AlgorithmGroup group)
	{
		return $"{group.Name} ({GetUnit(group.Metric)})";
	}

	public static string FormatDuration(TimeSpan duration)
	{
		return duration.TotalSeconds < 60
			? FormattableString.Invariant($"{duration.TotalSeconds:0.0} s")
			: FormattableString.Invariant($"{(int)duration.TotalMinutes} min {duration.Seconds} s");
	}

	public static string DescribeSettings(RunInfo run)
	{
		MeasurementSettings settings = run.Settings;
		string warmup = settings.WarmupSeconds switch
		{
			<= 0 => "no warm-up",
			_ when RuntimeFeature.IsDynamicCodeCompiled => FormattableString.Invariant($"warm-up per row of at least {settings.WarmupSeconds:0.###} s and until the JIT settles"),
			_ => FormattableString.Invariant($"warm-up of {settings.WarmupSeconds:0.###} s per row")
		};
		string threads = settings.Threads is 1 ? "1 thread" : FormattableString.Invariant($"{settings.Threads} threads");

		return FormattableString.Invariant($"{settings.Seconds:0.###} s per cell, {warmup}, {threads}{(run.Decrypt ? ", decryption" : "")}; at least {FormatDuration(run.EstimatedDuration)} in all");
	}

	public static string DescribeCell(CellResult cell)
	{
		return cell.InputSize is { } size ? FormattableString.Invariant($"{cell.Algorithm} {cell.Operation} {size} bytes") : $"{cell.Algorithm} {cell.Operation}";
	}

	/// <summary>
	/// Keeps the commit of a version such as 1.2.3+0123456789abcdef… to nine hexadecimal digits.
	/// </summary>
	public static string ShortenVersion(string version)
	{
		int plus = version.IndexOf('+', StringComparison.Ordinal);
		return plus >= 0 && version.Length > plus + 10 ? version.Substring(0, plus + 10) : version;
	}
}
