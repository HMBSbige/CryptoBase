using CryptoBase.Kdf.Argon2;
using System.Diagnostics;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Kdf.Argon2;

// Helpers, and a calling thread that gets interrupted, run on dedicated threads rather than on the pool: helpers are sure to take part, and no interrupt reaches other work.
public class Argon2LaneSchedulerTest
{
	private const int LaneCount = 4;
	private const int HelperThreadCount = LaneCount - 1;
	private const int PhaseCount = 8;
	private const int TimeoutMilliseconds = 10_000;

	[Test]
	[Arguments(false)]
	[Arguments(true)]
	public async Task EachPhaseProcessesEveryLaneOnceBeforeTheNextStarts(bool interruptHelpers)
	{
		RecordingScheduler scheduler = new(interruptHelpers);
		scheduler.Run();
		bool helpersLeft = scheduler.JoinHelperThreads();

		using (Assert.Multiple())
		{
			await Assert.That(scheduler.Counts).All(static count => count is 1);
			await Assert.That(scheduler.StartedEarly).IsFalse();
			await Assert.That(scheduler.HelpersTookPart).IsTrue();
			await Assert.That(helpersLeft).IsTrue();
			await Assert.That(scheduler.HelperFailures).All(static failure => failure is null);
			await Assert.That(scheduler.HelperInterruptsPending).All(pending => pending == interruptHelpers);
		}
	}

	[Test]
	[Arguments(false)]
	[Arguments(true)]
	public async Task FailureWaitsForHelpersToLeaveTheirLanes(bool interrupt)
	{
		using FailingScheduler scheduler = new(interrupt);
		Exception? failure = null;
		int activeLanes = -1;
		bool interruptPending = false;

		Thread thread = new
		(() =>
			{
				try
				{
					scheduler.Run();
				}
				catch (Exception e)
				{
					activeLanes = scheduler.ActiveLanes;
					failure = e;
				}

				interruptPending = ConsumePendingInterrupt();
			}
		)
		{ IsBackground = true };

		thread.Start();
		bool waitedForHelpers;
		int lanesWhileWaiting;
		bool callerLeft;
		bool helpersLeft;

		try
		{
			bool waitingOrStopped = SpinWait.SpinUntil(() => !thread.IsAlive || scheduler.Stopping && thread.ThreadState.HasFlag(System.Threading.ThreadState.WaitSleepJoin), TimeoutMilliseconds);
			waitedForHelpers = waitingOrStopped && thread.IsAlive;
			lanesWhileWaiting = scheduler.ActiveLanes;
		}
		finally
		{
			scheduler.ReleaseHelpers();
			callerLeft = thread.Join(TimeoutMilliseconds);
			helpersLeft = scheduler.JoinHelperThreads();
		}

		using (Assert.Multiple())
		{
			await Assert.That(waitedForHelpers).IsTrue();
			await Assert.That(lanesWhileWaiting).IsEqualTo(HelperThreadCount);
			await Assert.That(callerLeft).IsTrue();
			await Assert.That(failure).IsTypeOf<InvalidOperationException>();
			await Assert.That(activeLanes).IsEqualTo(0);
			await Assert.That(interruptPending).IsEqualTo(interrupt);
			await Assert.That(scheduler.HelpersTookPart).IsTrue();
			await Assert.That(helpersLeft).IsTrue();
			await Assert.That(scheduler.HelperFailures).All(static error => error is null);
		}
	}

	private abstract class TestScheduler(bool interruptHelpers) : Argon2LaneScheduler(LaneCount, LaneCount)
	{
		private readonly Thread[] _helperThreads = new Thread[HelperThreadCount];

		public Exception?[] HelperFailures { get; } = new Exception?[HelperThreadCount];

		public bool[] HelperInterruptsPending { get; } = new bool[HelperThreadCount];

		public bool HelpersTookPart { get; protected set; } = true;

		protected int CallingThread { get; private set; }

		public bool JoinHelperThreads()
		{
			return _helperThreads.All(static thread => thread.Join(TimeoutMilliseconds));
		}

		protected void StartHelperThreads()
		{
			CallingThread = Environment.CurrentManagedThreadId;

			for (int i = 0; i < HelperThreadCount; ++i)
			{
				int helper = i;
				_helperThreads[i] = new Thread(() => RunHelper(helper)) { IsBackground = true };
				_helperThreads[i].Start();
			}
		}

		protected void InterruptHelpers()
		{
			if (!interruptHelpers)
			{
				return;
			}

			foreach (Thread thread in _helperThreads)
			{
				thread.Interrupt();
			}
		}

		private void RunHelper(int helper)
		{
			if (interruptHelpers)
			{
				Thread.CurrentThread.Interrupt();
			}

			try
			{
				((IThreadPoolWorkItem)this).Execute();
			}
			catch (Exception e)
			{
				HelperFailures[helper] = e;
			}

			HelperInterruptsPending[helper] = ConsumePendingInterrupt();
		}
	}

	private sealed class RecordingScheduler(bool interruptHelpers) : TestScheduler(interruptHelpers)
	{
		private readonly int[] _entered = new int[PhaseCount];
		private int _startedEarly;

		public int[] Counts { get; } = new int[PhaseCount * LaneCount];

		public bool StartedEarly => Volatile.Read(ref _startedEarly) is not 0;

		public void Run()
		{
			StartHelperThreads();

			try
			{
				for (int phase = 0; phase < PhaseCount; ++phase)
				{
					RunPhase(phase, 0);
				}
			}
			finally
			{
				StopHelpers();
			}
		}

		protected override void ProcessLane(int pass, int slice, int lane)
		{
			Interlocked.Increment(ref _entered[pass]);

			for (int other = 0; pass > 0 && other < LaneCount; ++other)
			{
				if (Volatile.Read(ref Counts[(pass - 1) * LaneCount + other]) is 0)
				{
					Volatile.Write(ref _startedEarly, 1);
				}
			}

			if (Environment.CurrentManagedThreadId == CallingThread)
			{
				InterruptHelpers();

				if (HelpersTookPart && !SpinWait.SpinUntil(() => Volatile.Read(ref _entered[pass]) == LaneCount, TimeoutMilliseconds))
				{
					HelpersTookPart = false;
				}
			}
			else
			{
				// Busy rather than asleep, so that an interrupt pending on a helper can only surface in the waits of the scheduler, and longer than the scheduler spins, so that the threads waiting for the phase block.
				long end = Stopwatch.GetTimestamp() + (lane + 1) * Stopwatch.Frequency / 1000;

				while (Stopwatch.GetTimestamp() < end)
				{
					Thread.SpinWait(1);
				}
			}

			Interlocked.Increment(ref Counts[pass * LaneCount + lane]);
		}
	}

	private sealed class FailingScheduler(bool interrupt) : TestScheduler(false), IDisposable
	{
		private readonly CountdownEvent _helpersEntered = new(HelperThreadCount);
		private readonly ManualResetEventSlim _releaseHelpers = new();
		private int _activeLanes;
		private int _stopping;

		public int ActiveLanes => Volatile.Read(ref _activeLanes);

		public bool Stopping => Volatile.Read(ref _stopping) is not 0;

		public void Run()
		{
			StartHelperThreads();

			try
			{
				RunPhase(0, 0);
			}
			finally
			{
				// The exception has already been thrown; no test synchronization may consume the interrupt before StopHelpers.
				if (interrupt)
				{
					Thread.CurrentThread.Interrupt();
				}

				Volatile.Write(ref _stopping, 1);
				StopHelpers();
			}
		}

		public void ReleaseHelpers()
		{
			_releaseHelpers.Set();
		}

		public void Dispose()
		{
			_helpersEntered.Dispose();
			_releaseHelpers.Dispose();
		}

		protected override void ProcessLane(int pass, int slice, int lane)
		{
			Interlocked.Increment(ref _activeLanes);

			try
			{
				if (Environment.CurrentManagedThreadId != CallingThread)
				{
					_helpersEntered.Signal();

					if (!_releaseHelpers.Wait(TimeoutMilliseconds))
					{
						throw new TimeoutException("The test did not release the helper lanes.");
					}

					return;
				}

				HelpersTookPart = _helpersEntered.Wait(TimeoutMilliseconds);

				if (!HelpersTookPart)
				{
					throw new TimeoutException("The helper lanes did not start.");
				}

				throw new InvalidOperationException();
			}
			finally
			{
				Interlocked.Decrement(ref _activeLanes);
			}
		}
	}
}
