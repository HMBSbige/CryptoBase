using System.Text.Encodings.Web;
using System.Text.Json;

namespace CryptoBase.SpeedTest.Reporting;

/// <summary>
/// Writes the whole run as one JSON document when it ends, and a line of progress per row to <paramref name="progress" /> meanwhile.
/// </summary>
/// <remarks>
/// Rates are in the units of the tables: MiB/s for throughput and ops/s for operations.
/// </remarks>
internal sealed class JsonReporter(Stream output, TextWriter progress) : IReporter
{
	private readonly List<(GroupLayout Layout, List<(AlgorithmEntry Algorithm, List<CellResult> Cells)> Rows)> _groups = [];
	private RunInfo? _run;
	private int _rowCount;
	private int _finishedRowCount;

	public void BeginRun(RunInfo run)
	{
		_run = run;
		_rowCount = run.Groups.Sum(static group => group.Algorithms.Length);
		progress.WriteLine(FormattableString.Invariant($"Measuring {_rowCount} algorithm(s): {ReportFormat.DescribeSettings(run)}."));
	}

	public void BeginGroup(GroupLayout group)
	{
		_groups.Add((group, []));
	}

	public void BeginRow(AlgorithmEntry algorithm)
	{
		_groups[^1].Rows.Add((algorithm, []));
	}

	public void ReportCell(CellResult cell)
	{
		_groups[^1].Rows[^1].Cells.Add(cell);
	}

	public void EndRow()
	{
		(AlgorithmEntry algorithm, List<CellResult> cells) = _groups[^1].Rows[^1];
		int failed = cells.Count(static cell => cell.Outcome is CellOutcome.Failed);
		progress.WriteLine(FormattableString.Invariant($"[{++_finishedRowCount}/{_rowCount}] {algorithm.Name}{(failed > 0 ? $": {failed} cell(s) failed" : "")}"));
	}

	public void EndGroup()
	{
	}

	public void EndRun(RunSummary summary)
	{
		RunInfo run = _run ?? throw new InvalidOperationException("The run has not begun.");

		using (Utf8JsonWriter json = new(output, new JsonWriterOptions { Indented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }))
		{
			json.WriteStartObject();
			WriteEnvironment(json, run.Environment);
			WriteSettings(json, run);
			json.WriteNumber("elapsedSeconds", Math.Round(summary.Elapsed.TotalSeconds, 3));
			json.WriteNumber("failedCellCount", summary.FailedCellCount);
			json.WriteStartArray("groups");

			foreach ((GroupLayout layout, List<(AlgorithmEntry Algorithm, List<CellResult> Cells)> rows) in _groups)
			{
				json.WriteStartObject();
				json.WriteString("name", layout.Group.Name);
				json.WriteString("description", layout.Group.Description);
				json.WriteString("metric", layout.Group.Metric switch
				{
					Metric.Throughput => "throughput",
					Metric.Operations => "operations",
					_ => throw new UnreachableException()
				});
				json.WriteString("unit", ReportFormat.GetUnit(layout.Group.Metric));
				json.WriteStartArray("algorithms");

				foreach ((AlgorithmEntry algorithm, List<CellResult> cells) in rows)
				{
					json.WriteStartObject();
					json.WriteString("name", algorithm.Name);
					json.WriteStartArray("cells");

					foreach (CellResult cell in cells)
					{
						WriteCell(json, cell);
					}

					json.WriteEndArray();
					json.WriteEndObject();
				}

				json.WriteEndArray();
				json.WriteEndObject();
			}

			json.WriteEndArray();
			json.WriteEndObject();
		}

		output.Write("\n"u8);
		output.Flush();
	}

	private static void WriteEnvironment(Utf8JsonWriter json, EnvironmentSummary environment)
	{
		json.WriteStartObject("environment");
		json.WriteString("cryptoBaseVersion", environment.CryptoBaseVersion);
		json.WriteString("runtime", environment.Runtime);
		json.WriteString("codeGeneration", environment.CodeGeneration);
		json.WriteString("operatingSystem", environment.OperatingSystem);
		json.WriteString("architecture", environment.Architecture.ToString());
		json.WriteString("cpu", environment.Cpu);
		json.WriteNumber("logicalProcessorCount", environment.LogicalProcessorCount);
		json.WriteStartArray("instructionSets");

		foreach (string instructionSet in environment.InstructionSets)
		{
			json.WriteStringValue(instructionSet);
		}

		json.WriteEndArray();
		json.WriteEndObject();
	}

	private static void WriteSettings(Utf8JsonWriter json, RunInfo run)
	{
		json.WriteStartObject("settings");
		json.WriteNumber("secondsPerCell", run.Settings.Seconds);
		json.WriteNumber("minimumWarmupSeconds", run.Settings.WarmupSeconds);
		json.WriteNumber("threads", run.Settings.Threads);
		json.WriteBoolean("decrypt", run.Decrypt);
		json.WriteNumber("samplesPerCell", MeasurementSettings.SampleCount);
		json.WriteStartArray("inputSizes");

		foreach (int size in run.InputSizes)
		{
			json.WriteNumberValue(size);
		}

		json.WriteEndArray();
		json.WriteEndObject();
	}

	private static void WriteCell(Utf8JsonWriter json, CellResult cell)
	{
		json.WriteStartObject();
		json.WriteString("operation", cell.Operation);

		if (cell.InputSize is { } size)
		{
			json.WriteNumber("inputSize", size);
		}
		else
		{
			json.WriteNull("inputSize");
		}

		switch (cell.Outcome)
		{
			case CellOutcome.Measured { Statistics: var statistics }:
			{
				json.WriteString("status", "measured");
				json.WriteString("unit", ReportFormat.GetUnit(cell.Metric));
				WriteRate(json, "median", statistics.Median, cell.Metric);
				WriteRate(json, "min", statistics.Min, cell.Metric);
				WriteRate(json, "max", statistics.Max, cell.Metric);
				WriteFinite(json, "cv", statistics.CoefficientOfVariation);
				json.WriteNumber("sampleCount", statistics.SampleCount);
				json.WriteNumber("iterationsPerSample", statistics.IterationsPerSample);
				break;
			}
			case CellOutcome.NotApplicable:
			{
				json.WriteString("status", "notApplicable");
				break;
			}
			case CellOutcome.Failed { Message: var message }:
			{
				json.WriteString("status", "failed");
				json.WriteString("error", message);
				break;
			}
			default:
			{
				throw new UnreachableException();
			}
		}

		if (cell.Warmup is { } warmup)
		{
			json.WriteStartObject("warmup");
			json.WriteNumber("seconds", Math.Round(warmup.Elapsed.TotalSeconds, 3));
			json.WriteBoolean("jitSettled", warmup.JitSettled);
			json.WriteEndObject();
		}

		json.WriteEndObject();
	}

	private static void WriteRate(Utf8JsonWriter json, string name, double rate, Metric metric)
	{
		WriteFinite(json, name, ReportFormat.ToUnit(rate, metric));
	}

	/// <summary>
	/// Writes a number, or <see langword="null" /> for a value that JSON cannot hold.
	/// </summary>
	private static void WriteFinite(Utf8JsonWriter json, string name, double value)
	{
		if (double.IsFinite(value))
		{
			json.WriteNumber(name, value);
		}
		else
		{
			json.WriteNull(name);
		}
	}
}
