namespace CryptoBase.SpeedTest.Reporting;

/// <summary>
/// Writes plain-text tables, one cell at a time, so that the output is final as soon as it appears.
/// </summary>
internal sealed class TextReporter(TextWriter writer) : IReporter
{
	// Up to 99999.9 MiB/s and 9999999.9 ops/s keep their columns aligned.
	private const int MinimumThroughputColumnWidth = 7;
	private const int MinimumOperationsColumnWidth = 9;

	private readonly List<string> _failures = [];
	private int _nameWidth;
	private int[] _columnWidths = [];
	private int _column;
	private bool _pendingSpace;
	private bool _anyNoisy;

	public void BeginRun(RunInfo run)
	{
		EnvironmentSummary environment = run.Environment;

		writer.WriteLine($"CryptoBase {ReportFormat.ShortenVersion(environment.CryptoBaseVersion)} | {environment.Runtime} ({environment.CodeGeneration}) | {environment.OperatingSystem} {environment.Architecture}");
		writer.WriteLine(FormattableString.Invariant($"CPU: {environment.Cpu ?? "unknown"} ({environment.LogicalProcessorCount} logical processors)"));
		writer.WriteLine($"ISA: {string.Join(' ', environment.InstructionSets)}");
		writer.WriteLine(ReportFormat.DescribeSettings(run));

		_nameWidth = 0;

		foreach (GroupLayout group in run.Groups)
		{
			_nameWidth = Math.Max(_nameWidth, ReportFormat.GetGroupTitle(group.Group).Length);

			foreach (AlgorithmEntry algorithm in group.Algorithms)
			{
				_nameWidth = Math.Max(_nameWidth, algorithm.Name.Length);
			}
		}
	}

	public void BeginGroup(GroupLayout group)
	{
		_failures.Clear();
		int minimumWidth = group.Group.Metric is Metric.Operations ? MinimumOperationsColumnWidth : MinimumThroughputColumnWidth;
		_columnWidths = [.. group.Columns.Select(column => Math.Max(minimumWidth, column.Length))];

		writer.WriteLine();
		writer.Write(ReportFormat.GetGroupTitle(group.Group).PadRight(_nameWidth));

		for (int i = 0; i < group.Columns.Length; ++i)
		{
			// Every column but the last is followed by the slot of its noise marker.
			writer.Write(i > 0 ? "  " : " ");
			writer.Write(group.Columns[i].PadLeft(_columnWidths[i]));
		}

		writer.WriteLine();
	}

	public void BeginRow(AlgorithmEntry algorithm)
	{
		writer.Write(algorithm.Name.PadRight(_nameWidth));
		_column = 0;
		_pendingSpace = false;
	}

	public void ReportCell(CellResult cell)
	{
		(string text, bool noisy) = cell.Outcome switch
		{
			CellOutcome.Measured { Statistics: var statistics } => (ReportFormat.FormatRate(statistics.Median, cell.Metric), ReportFormat.IsNoisy(statistics)),
			CellOutcome.NotApplicable => ("-", false),
			CellOutcome.Failed { Message: var message } => (AddFailure(cell, message), false)
		};

		// A marker follows its number, so the space that stands in for a missing marker is only written before the next cell.
		if (_pendingSpace)
		{
			writer.Write(' ');
		}

		writer.Write(' ');
		writer.Write(text.PadLeft(_columnWidths[_column]));

		if (noisy)
		{
			writer.Write('*');
			_anyNoisy = true;
		}

		_pendingSpace = !noisy;
		++_column;
	}

	public void EndRow()
	{
		writer.WriteLine();
	}

	public void EndGroup()
	{
		foreach (string failure in _failures)
		{
			writer.WriteLine(failure);
		}

		_failures.Clear();
	}

	public void EndRun(RunSummary summary)
	{
		writer.WriteLine();

		if (_anyNoisy)
		{
			writer.WriteLine($"* {ReportFormat.NoisyNote}");
		}

		if (summary.FailedCellCount > 0)
		{
			writer.WriteLine(FormattableString.Invariant($"{summary.FailedCellCount} cell(s) failed."));
		}

		writer.WriteLine($"Finished in {ReportFormat.FormatDuration(summary.Elapsed)}.");
	}

	private string AddFailure(CellResult cell, string message)
	{
		_failures.Add($"  error: {ReportFormat.DescribeCell(cell)}: {message}");
		return "error";
	}
}
