namespace CryptoBase.SpeedTest.Measuring;

internal sealed class BenchmarkSession(MeasurementSettings settings, ImmutableArray<int> inputSizes, bool decrypt, IReporter reporter)
{
	private readonly Measurer _measurer = new(settings);
	private int _failedCellCount;

	/// <returns>The number of cells that failed.</returns>
	public int Run(ImmutableArray<AlgorithmEntry> algorithms)
	{
		long start = Stopwatch.GetTimestamp();
		ImmutableArray<GroupLayout> groups = Plan(algorithms, inputSizes);
		Measurer.PrimeHarness(settings.Threads);

		reporter.BeginRun(new RunInfo(EnvironmentSummary.Capture(), settings, inputSizes, decrypt, groups, Estimate(groups)));

		foreach (GroupLayout group in groups)
		{
			reporter.BeginGroup(group);

			foreach (AlgorithmEntry algorithm in group.Algorithms)
			{
				CollectGarbage();
				reporter.BeginRow(algorithm);

				switch (algorithm.Metric)
				{
					case Metric.Throughput:
					{
						RunThroughputRow(algorithm);
						break;
					}
					case Metric.Operations:
					{
						RunOperationRow(algorithm, group.Columns);
						break;
					}
					default:
					{
						throw new UnreachableException();
					}
				}

				reporter.EndRow();
			}

			reporter.EndGroup();
		}

		reporter.EndRun(new RunSummary(Stopwatch.GetElapsedTime(start), _failedCellCount));
		return _failedCellCount;
	}

	/// <summary>
	/// Lays out a table per group that has a selected algorithm. The columns of a throughput group are the input sizes; those of an operation group
	/// are the operations that its selected algorithms have, in the order of <see cref="AlgorithmGroup.Operations" />.
	/// </summary>
	public static ImmutableArray<GroupLayout> Plan(ImmutableArray<AlgorithmEntry> algorithms, ImmutableArray<int> inputSizes)
	{
		ImmutableArray<GroupLayout>.Builder groups = ImmutableArray.CreateBuilder<GroupLayout>();
		ImmutableArray<string> sizeColumns = [.. inputSizes.Select(static size => size.ToString(CultureInfo.InvariantCulture))];

		foreach (AlgorithmGroup group in AlgorithmGroups.All)
		{
			ImmutableArray<AlgorithmEntry> rows = [.. algorithms.Where(algorithm => algorithm.Group == group)];

			if (rows.IsEmpty)
			{
				continue;
			}

			ImmutableArray<string> columns = group.Metric switch
			{
				Metric.Throughput => sizeColumns,
				Metric.Operations => [.. group.Operations.Where(operation => rows.Any(row => row.Operations.Contains(operation)))],
				_ => throw new UnreachableException()
			};

			groups.Add(new GroupLayout(group, rows, columns));
		}

		return groups.DrainToImmutable();
	}

	/// <summary>
	/// Estimates the least duration of the run from its warm-ups and cells, leaving out set-up, calibration, and the time that warm-ups wait for the JIT.
	/// </summary>
	private TimeSpan Estimate(ImmutableArray<GroupLayout> groups)
	{
		double seconds = 0;

		foreach (GroupLayout group in groups)
		{
			foreach (AlgorithmEntry algorithm in group.Algorithms)
			{
				seconds += algorithm.Metric switch
				{
					Metric.Throughput => settings.WarmupSeconds + inputSizes.Count(algorithm.SupportsInputSize) * settings.Seconds,
					Metric.Operations => algorithm.Operations.Length * (settings.WarmupSeconds + settings.Seconds),
					_ => throw new UnreachableException()
				};
			}
		}

		return TimeSpan.FromSeconds(seconds);
	}

	/// <summary>
	/// Measures one operation at every input size, after warming them up together.
	/// </summary>
	private void RunThroughputRow(AlgorithmEntry algorithm)
	{
		string operation = algorithm.GetThroughputOperation(decrypt);
		CellOutcome?[] outcomes = new CellOutcome?[inputSizes.Length];
		List<(int Column, IBatchRunner Runner)> runners = [];

		try
		{
			for (int i = 0; i < inputSizes.Length; ++i)
			{
				if (!algorithm.SupportsInputSize(inputSizes[i]))
				{
					outcomes[i] = CellOutcome.NotApplicable.Instance;
				}
				else if (TryCreateRunner(algorithm, operation, inputSizes[i], out IBatchRunner? runner, out CellOutcome? failure))
				{
					runners.Add((i, runner));
				}
				else
				{
					outcomes[i] = failure;
				}
			}

			WarmupResult? warmup = null;

			try
			{
				warmup = _measurer.Warmup([.. runners.Select(static item => item.Runner)]);
			}
			catch (Exception ex)
			{
				foreach ((int column, _) in runners)
				{
					outcomes[column] = new CellOutcome.Failed(ex.Message);
				}
			}

			// The runners are in column order, and only the columns without an outcome yet have one; those all have one if the warm-up failed.
			for (int i = 0, next = 0; i < inputSizes.Length; ++i)
			{
				CellOutcome? outcome = outcomes[i];

				if (outcome is null && warmup is not null)
				{
					outcome = Measure(runners[next].Runner, inputSizes[i], warmup.TicksPerIteration[next]);
					++next;
				}

				outcome ??= new CellOutcome.Failed("The cell has no runner.");
				Report(algorithm, operation, inputSizes[i], outcome, outcome is CellOutcome.NotApplicable ? null : warmup?.Summary);
			}

		}
		finally
		{
			foreach ((_, IBatchRunner runner) in runners)
			{
				runner.Dispose();
			}
		}
	}

	/// <summary>
	/// Measures each operation of the group that the algorithm has, warming each one up before it.
	/// </summary>
	private void RunOperationRow(AlgorithmEntry algorithm, ImmutableArray<string> operations)
	{
		foreach (string operation in operations)
		{
			if (!algorithm.Operations.Contains(operation))
			{
				Report(algorithm, operation, null, CellOutcome.NotApplicable.Instance, null);
				continue;
			}

			if (!TryCreateRunner(algorithm, operation, 0, out IBatchRunner? runner, out CellOutcome? failure))
			{
				Report(algorithm, operation, null, failure, null);
				continue;
			}

			using (runner)
			{
				WarmupResult warmup;

				try
				{
					warmup = _measurer.Warmup([runner]);
				}
				catch (Exception ex)
				{
					Report(algorithm, operation, null, new CellOutcome.Failed(ex.Message), null);
					continue;
				}

				Report(algorithm, operation, null, Measure(runner, 1, warmup.TicksPerIteration[0]), warmup.Summary);
			}
		}
	}

	private bool TryCreateRunner(AlgorithmEntry algorithm, string operation, int inputSize, [NotNullWhen(true)] out IBatchRunner? runner, [NotNullWhen(false)] out CellOutcome? failure)
	{
		List<Workload> workloads = new(settings.Threads);

		try
		{
			for (int i = 0; i < settings.Threads; ++i)
			{
				Workload workload = algorithm.CreateWorkload(operation, inputSize);
				workloads.Add(workload);
				workload.Verify();
			}

			runner = workloads.Count is 1 ? new SingleThreadBatchRunner(workloads[0]) : new MultiThreadBatchRunner([.. workloads]);
			failure = null;
			return true;
		}
		catch (Exception ex)
		{
			foreach (Workload workload in workloads)
			{
				workload.Dispose();
			}

			runner = null;
			failure = new CellOutcome.Failed(ex.Message);
			return false;
		}
	}

	private CellOutcome Measure(IBatchRunner runner, double unitsPerIteration, double ticksPerIteration)
	{
		try
		{
			return new CellOutcome.Measured(_measurer.Measure(runner, unitsPerIteration, ticksPerIteration));
		}
		catch (Exception ex)
		{
			return new CellOutcome.Failed(ex.Message);
		}
	}

	private void Report(AlgorithmEntry algorithm, string operation, int? inputSize, CellOutcome outcome, WarmupSummary? warmup)
	{
		if (outcome is CellOutcome.Failed)
		{
			++_failedCellCount;
		}

		reporter.ReportCell(new CellResult(algorithm.Group.Name, algorithm.Name, operation, inputSize, algorithm.Metric, outcome, warmup));
	}

	private static void CollectGarbage()
	{
		GC.Collect();
		GC.WaitForPendingFinalizers();
		GC.Collect();
	}
}
