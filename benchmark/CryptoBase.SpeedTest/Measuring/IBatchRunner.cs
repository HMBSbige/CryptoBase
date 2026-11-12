namespace CryptoBase.SpeedTest.Measuring;

/// <summary>
/// Runs timed batches of a workload.
/// </summary>
/// <remarks>
/// A runner that spreads a batch over several threads, each with its own workload, reports the wall-clock time of the whole batch and its <see cref="WorkerCount" />.
/// </remarks>
internal interface IBatchRunner : IDisposable
{
	/// <summary>
	/// Gets the number of workloads that each run <see cref="RunBatch" />'s iterations.
	/// </summary>
	int WorkerCount { get; }

	/// <summary>
	/// Runs <paramref name="iterations" /> iterations on every worker and returns the elapsed time in <see cref="Stopwatch" /> ticks.
	/// </summary>
	long RunBatch(long iterations);
}

internal sealed class SingleThreadBatchRunner(Workload workload) : IBatchRunner
{
	public int WorkerCount => 1;

	public long RunBatch(long iterations)
	{
		long start = Stopwatch.GetTimestamp();
		workload.Run(iterations);
		return Stopwatch.GetTimestamp() - start;
	}

	public void Dispose()
	{
		workload.Dispose();
	}
}

/// <summary>
/// Runs each batch on one dedicated thread per workload, all started together.
/// </summary>
/// <remarks>
/// A batch wakes the threads first and starts the clock only once every thread spins, ready to go, so that waking them is not timed.
/// Each thread stops its own clock, and the batch takes from the start to the last of them.
/// Between batches the threads block, so that idle runners leave the processors to the busy ones.
/// </remarks>
internal sealed class MultiThreadBatchRunner : IBatchRunner
{
	private readonly Workload[] _workloads;
	private readonly Thread[] _threads;
	private readonly SemaphoreSlim _wake = new(0);
	private readonly ManualResetEventSlim _finished = new();
	private readonly long[] _endTimestamps;
	private readonly Exception?[] _exceptions;
	private long _iterations;
	private int _ready;
	private int _running;
	private int _generation;
	private bool _stopping;

	/// <param name="workloads">The workloads, one per thread, which the runner then owns.</param>
	public MultiThreadBatchRunner(Workload[] workloads)
	{
		_workloads = workloads;
		_endTimestamps = new long[workloads.Length];
		_exceptions = new Exception?[workloads.Length];
		_threads = new Thread[workloads.Length];

		for (int i = 0; i < _threads.Length; ++i)
		{
			int worker = i;
			_threads[i] = new Thread(() => Work(worker)) { IsBackground = true, Name = $"SpeedTest worker {worker}" };
			_threads[i].Start();
		}
	}

	public int WorkerCount => _workloads.Length;

	public long RunBatch(long iterations)
	{
		_iterations = iterations;
		_exceptions.AsSpan().Clear();
		Volatile.Write(ref _ready, 0);
		Volatile.Write(ref _running, _workloads.Length);
		_finished.Reset();
		_wake.Release(_workloads.Length);

		SpinWait spinner = new();

		while (Volatile.Read(ref _ready) < _workloads.Length)
		{
			spinner.SpinOnce(sleep1Threshold: -1);
		}

		long start = Stopwatch.GetTimestamp();
		Interlocked.Increment(ref _generation);
		_finished.Wait();

		for (int i = 0; i < _exceptions.Length; ++i)
		{
			if (_exceptions[i] is { } exception)
			{
				throw new InvalidOperationException($"Worker {i}: {exception.Message}", exception);
			}
		}

		long end = start;

		foreach (long timestamp in _endTimestamps)
		{
			end = Math.Max(end, timestamp);
		}

		return end - start;
	}

	public void Dispose()
	{
		Volatile.Write(ref _stopping, true);
		_wake.Release(_workloads.Length);

		foreach (Thread thread in _threads)
		{
			thread.Join();
		}

		foreach (Workload workload in _workloads)
		{
			workload.Dispose();
		}

		_wake.Dispose();
		_finished.Dispose();
	}

	private void Work(int worker)
	{
		Workload workload = _workloads[worker];
		int generation = 0;

		while (true)
		{
			_wake.Wait();

			if (Volatile.Read(ref _stopping))
			{
				return;
			}

			Interlocked.Increment(ref _ready);

			// The batch starts within a fraction of a microsecond, so spin without yielding.
			while (Volatile.Read(ref _generation) == generation)
			{
				Thread.SpinWait(1);
			}

			++generation;

			try
			{
				workload.Run(_iterations);
			}
			catch (Exception ex)
			{
				_exceptions[worker] = ex;
			}

			_endTimestamps[worker] = Stopwatch.GetTimestamp();

			if (Interlocked.Decrement(ref _running) is 0)
			{
				_finished.Set();
			}
		}
	}
}
