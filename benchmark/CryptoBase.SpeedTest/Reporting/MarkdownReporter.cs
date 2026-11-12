using System.Text;

namespace CryptoBase.SpeedTest.Reporting;

/// <summary>
/// Writes GitHub-flavored Markdown tables, one cell at a time, so that the output is final as soon as it appears.
/// </summary>
internal sealed class MarkdownReporter(TextWriter writer) : IReporter
{
	private const string NoisyMarker = @"\*";
	private const string AlgorithmTitle = "algorithm";
	// Up to 9999999.9 and a noise marker keep their columns aligned in the source.
	private const int MinimumColumnWidth = 9 + 2;

	private readonly List<string> _failures = [];
	private int _nameWidth;
	private int[] _columnWidths = [];
	private int _column;
	private bool _anyNoisy;

	public void BeginRun(RunInfo run)
	{
		EnvironmentSummary environment = run.Environment;

		writer.WriteLine("| | |");
		writer.WriteLine("| :-- | :-- |");
		WriteFact("CryptoBase", ReportFormat.ShortenVersion(environment.CryptoBaseVersion));
		WriteFact("Runtime", $"{environment.Runtime} ({environment.CodeGeneration})");
		WriteFact("OS", $"{environment.OperatingSystem} {environment.Architecture}");
		WriteFact("CPU", FormattableString.Invariant($"{environment.Cpu ?? "unknown"} ({environment.LogicalProcessorCount} logical processors)"));
		WriteFact("ISA", string.Join(' ', environment.InstructionSets));
		WriteFact("Settings", ReportFormat.DescribeSettings(run));

		_nameWidth = AlgorithmTitle.Length;

		foreach (GroupLayout group in run.Groups)
		{
			foreach (AlgorithmEntry algorithm in group.Algorithms)
			{
				_nameWidth = Math.Max(_nameWidth, Escape(algorithm.Name).Length);
			}
		}
	}

	public void BeginGroup(GroupLayout group)
	{
		_failures.Clear();
		_columnWidths = [.. group.Columns.Select(static column => Math.Max(MinimumColumnWidth, column.Length))];

		writer.WriteLine();
		writer.WriteLine($"### {Escape(ReportFormat.GetGroupTitle(group.Group))}");
		writer.WriteLine();

		StringBuilder header = new();
		StringBuilder separator = new();
		header.Append($"| {AlgorithmTitle.PadRight(_nameWidth)} |");
		separator.Append($"| :{new string('-', _nameWidth - 1)} |");

		for (int i = 0; i < group.Columns.Length; ++i)
		{
			header.Append($" {group.Columns[i].PadLeft(_columnWidths[i])} |");
			separator.Append($" {new string('-', _columnWidths[i] - 1)}: |");
		}

		writer.WriteLine(header);
		writer.WriteLine(separator);
	}

	public void BeginRow(AlgorithmEntry algorithm)
	{
		writer.Write($"| {Escape(algorithm.Name).PadRight(_nameWidth)} |");
		_column = 0;
	}

	public void ReportCell(CellResult cell)
	{
		string text = cell.Outcome switch
		{
			CellOutcome.Measured { Statistics: var statistics } when ReportFormat.IsNoisy(statistics) => ReportFormat.FormatRate(statistics.Median, cell.Metric) + NoisyMarker,
			CellOutcome.Measured { Statistics: var statistics } => ReportFormat.FormatRate(statistics.Median, cell.Metric),
			CellOutcome.NotApplicable => "-",
			CellOutcome.Failed { Message: var message } => AddFailure(cell, message)
		};

		_anyNoisy |= text.EndsWith(NoisyMarker, StringComparison.Ordinal);
		writer.Write($" {text.PadLeft(_columnWidths[_column])} |");
		++_column;
	}

	public void EndRow()
	{
		writer.WriteLine();
	}

	public void EndGroup()
	{
		if (_failures.Count is 0)
		{
			return;
		}

		// A blank line ends the table before the list.
		writer.WriteLine();

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
			writer.WriteLine($"{NoisyMarker} {Escape(ReportFormat.NoisyNote)}");
			writer.WriteLine();
		}

		if (summary.FailedCellCount > 0)
		{
			writer.WriteLine(FormattableString.Invariant($"{summary.FailedCellCount} cell(s) failed."));
			writer.WriteLine();
		}

		writer.WriteLine($"Finished in {ReportFormat.FormatDuration(summary.Elapsed)}.");
	}

	private static string Escape(string text)
	{
		StringBuilder builder = new(text.Length);

		foreach (char c in text)
		{
			if (c is '\\' or '`' or '*' or '_' or '|' or '<' or '>' or '[' or ']' or '#')
			{
				builder.Append('\\');
			}

			builder.Append(c is '\r' or '\n' ? ' ' : c);
		}

		return builder.ToString();
	}

	private void WriteFact(string name, string value)
	{
		writer.WriteLine($"| {name} | {Escape(value)} |");
	}

	private string AddFailure(CellResult cell, string message)
	{
		_failures.Add($"- error: {Escape(ReportFormat.DescribeCell(cell))}: {Escape(message)}");
		return "error";
	}
}
