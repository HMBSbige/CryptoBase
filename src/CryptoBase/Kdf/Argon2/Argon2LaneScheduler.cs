using static CryptoBase.Internal.ThreadInterrupts;

namespace CryptoBase.Kdf.Argon2;

// With several lanes, pool threads queued once claim lanes alongside the calling thread and wait between phases, which costs far less than handing every slice to Parallel.For.
// The calling thread processes every lane nobody has claimed, so progress never depends on a helper starting.
internal abstract class Argon2LaneScheduler(int lanes, int maxDegreeOfParallelism) : ThreadPoolHelper
{
	// Threads waiting between phases spin for about 500 µs before blocking: long enough to cover the usual stagger between lanes of a phase, short enough not to hold a core while other derivations need it.
	private static readonly long SpinTicks = Stopwatch.Frequency / 2000;

	private readonly int _helpers = HelperCount(lanes, maxDegreeOfParallelism);
	private readonly object _gate = new();

	private int _pass;
	private int _slice;

	// Phase generation in the high 32 bits and next unclaimed lane in the low 32 bits, so that one CAS only claims a lane of the expected phase.
	private long _work;
	private int _pendingLanes;
	private int _runningHelpers;
	private int _blockedThreads;
	private int _finished;

	protected int Lanes { get; } = lanes;

	private uint PublishedGeneration => (uint)(Volatile.Read(ref _work) >> 32);

	internal static int HelperCount(int lanes, int maxDegreeOfParallelism)
	{
		Debug.Assert(lanes > 0);
		Debug.Assert(maxDegreeOfParallelism is -1 or > 0);

		int threads = maxDegreeOfParallelism is -1 ? Environment.ProcessorCount : maxDegreeOfParallelism;
		return Math.Min(lanes, threads) - 1;
	}

	protected abstract void ProcessLane(int pass, int slice, int lane);

	protected void StartHelpers()
	{
		QueueHelpers(_helpers);
	}

	// Once this returns, no helper processes a lane, so the caller can release the memory; an interrupt therefore cannot cut it short.
	// A helper that has not started yet will see _finished before claiming anything.
	// If a phase was cut short, helpers may still be processing its lanes, possibly whole segments, so this waits for them to leave, sleeping rather than holding a core.
	protected void StopHelpers()
	{
		Interlocked.Exchange(ref _finished, 1);
		WakeBlockedThreads();

		// With no lane pending, every lane of the last phase has been claimed and processed, so no helper is processing one or can claim one.
		if (Volatile.Read(ref _pendingLanes) is not 0)
		{
			SpinUntilZero(ref _runningHelpers);
		}
	}

	protected void RunPhase(int pass, int slice)
	{
		if (_helpers is 0)
		{
			for (int lane = 0; lane < Lanes; ++lane)
			{
				ProcessLane(pass, slice, lane);
			}

			return;
		}

		uint generation = PublishedGeneration + 1;
		_pass = pass;
		_slice = slice;
		Volatile.Write(ref _pendingLanes, Lanes);
		Interlocked.Exchange(ref _work, (long)generation << 32);
		WakeBlockedThreads();

		ProcessClaimedLanes(generation);
		WaitWhile(static (scheduler, _) => Volatile.Read(ref scheduler._pendingLanes) is not 0, 0);
	}

	// A pool thread may carry an interrupt meant for other work, and an exception escaping a work item ends the process, so the waits of a helper retry after an interrupt, which is raised again afterwards.
	internal override void Help()
	{
		Interlocked.Increment(ref _runningHelpers);
		bool interrupted = false;

		try
		{
			uint seenGeneration = 0;

			while (TryWaitForGeneration(seenGeneration, ref interrupted, out uint generation))
			{
				seenGeneration = generation;
				ProcessClaimedLanes(generation);
			}
		}
		finally
		{
			Interlocked.Decrement(ref _runningHelpers);
		}

		RestoreInterrupt(interrupted);
	}

	private bool TryWaitForGeneration(uint seenGeneration, ref bool interrupted, out uint generation)
	{
		Uninterruptibly
		(
			static state => state.Scheduler.WaitWhile(static (scheduler, seen) => Volatile.Read(ref scheduler._finished) is 0 && scheduler.PublishedGeneration == seen, state.SeenGeneration),
			(Scheduler: this, SeenGeneration: seenGeneration),
			ref interrupted
		);
		generation = PublishedGeneration;
		return Volatile.Read(ref _finished) is 0;
	}

	// Counting the thread as blocked is a full fence that pairs with the one publishing each awaited change before WakeBlockedThreads: either the publisher sees the thread blocked, or the thread sees the change.
	private void WaitWhile(Func<Argon2LaneScheduler, uint, bool> keepWaiting, uint state)
	{
		long spinDeadline = Stopwatch.GetTimestamp() + SpinTicks;
		SpinWait spinner = default;

		while (keepWaiting(this, state))
		{
			if (Stopwatch.GetTimestamp() < spinDeadline)
			{
				spinner.SpinOnce(-1);
				continue;
			}

			lock (_gate)
			{
				Interlocked.Increment(ref _blockedThreads);

				try
				{
					while (keepWaiting(this, state))
					{
						Monitor.Wait(_gate);
					}
				}
				finally
				{
					Interlocked.Decrement(ref _blockedThreads);
				}
			}
		}
	}

	// The thread completing a phase may be the only one left to wake the threads waiting for it, so an interrupt cannot stop the wake-up.
	private void WakeBlockedThreads()
	{
		if (Volatile.Read(ref _blockedThreads) is 0)
		{
			return;
		}

		bool interrupted = false;
		Uninterruptibly
		(
			static gate =>
			{
				lock (gate)
				{
					Monitor.PulseAll(gate);
				}
			}, _gate, ref interrupted
		);
		RestoreInterrupt(interrupted);
	}

	// _pass and _slice are written before the generation is published and cannot change until every lane of it is processed, so a stale read only happens when claiming would fail anyway.
	private void ProcessClaimedLanes(uint generation)
	{
		int pass = _pass;
		int slice = _slice;

		while (TryClaimLane(generation, out int lane))
		{
			ProcessLane(pass, slice, lane);

			if (Interlocked.Decrement(ref _pendingLanes) is 0)
			{
				WakeBlockedThreads();
			}
		}
	}

	private bool TryClaimLane(uint generation, out int lane)
	{
		long work = Volatile.Read(ref _work);

		while ((uint)(work >> 32) == generation && (int)work < Lanes)
		{
			long observed = Interlocked.CompareExchange(ref _work, work + 1, work);

			if (observed == work)
			{
				lane = (int)work;
				return true;
			}

			work = observed;
		}

		lane = default;
		return false;
	}
}
