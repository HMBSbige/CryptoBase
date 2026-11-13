namespace CryptoBase.SpeedTest.Reporting;

/// <summary>
/// Receives the results of a run as they are measured, in this order: <see cref="BeginRun" />, then for each group <see cref="BeginGroup" />,
/// for each row <see cref="BeginRow" />, one <see cref="ReportCell" /> per column and <see cref="EndRow" />, then <see cref="EndGroup" />, and last <see cref="EndRun" />.
/// </summary>
internal interface IReporter
{
	void BeginRun(RunInfo run);

	void BeginGroup(GroupLayout group);

	void BeginRow(AlgorithmEntry algorithm);

	void ReportCell(CellResult cell);

	void EndRow();

	void EndGroup();

	void EndRun(RunSummary summary);
}

/// <param name="EstimatedDuration">The least duration of the run: warm-ups take longer while the JIT compiles, and slow operations can exceed their cells.</param>
internal sealed record RunInfo(EnvironmentSummary Environment, MeasurementSettings Settings, ImmutableArray<int> InputSizes, bool Decrypt, ImmutableArray<GroupLayout> Groups, TimeSpan EstimatedDuration);

/// <param name="Columns">The columns: the input sizes in bytes of a throughput group, or the operation names of an operation group.</param>
internal sealed record GroupLayout(AlgorithmGroup Group, ImmutableArray<AlgorithmEntry> Algorithms, ImmutableArray<string> Columns);

/// <param name="InputSize">The input size in bytes of a throughput cell, or <see langword="null" /> for an operation cell.</param>
/// <param name="Metric">What the rates of <paramref name="Outcome" /> count: bytes or operations per second.</param>
/// <param name="Outcome">The measurement, or why there is none.</param>
/// <param name="Warmup">The warm-up before the cell, shared by the cells of a throughput row, or <see langword="null" /> if there was none.</param>
internal sealed record CellResult(string Group, string Algorithm, string Operation, int? InputSize, Metric Metric, CellOutcome Outcome, WarmupSummary? Warmup);

/// <param name="JitSettled">Whether the compilation count stayed unchanged for the quiet window before the warm-up ended; always true when no JIT wait is needed.</param>
internal sealed record WarmupSummary(TimeSpan Elapsed, bool JitSettled);

internal closed class CellOutcome
{
	public sealed class Measured(SampleStatistics statistics) : CellOutcome
	{
		public SampleStatistics Statistics { get; } = statistics;
	}

	public sealed class NotApplicable : CellOutcome
	{
		public static NotApplicable Instance { get; } = new();

		private NotApplicable()
		{
		}
	}

	public sealed class Failed(string message) : CellOutcome
	{
		public string Message { get; } = message;
	}
}

internal sealed record RunSummary(TimeSpan Elapsed, int FailedCellCount);
