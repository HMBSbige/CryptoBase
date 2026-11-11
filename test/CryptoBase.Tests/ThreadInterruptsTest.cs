using CryptoBase.Internal;

namespace CryptoBase.Tests;

public class ThreadInterruptsTest
{
	private const int TimeoutMilliseconds = 10_000;
	private const int StepMilliseconds = 100;

	// The interrupting thread holds the lock, so the waiting thread has to block to take it back. A pulsed thread is interrupted while it does, unless it is slow to block: it then takes the lock and returns.
	[Test]
	[Arguments(false)]
	[Arguments(true)]
	public async Task InterruptedWaitThrowsHoldingTheLock(bool pulsed)
	{
		object gate = new();
		bool waiting = false;
		bool? heldWhenThrown = null;
		Exception? failure = null;

		Thread thread = new
		(() =>
			{
				try
				{
					lock (gate)
					{
						Volatile.Write(ref waiting, true);

						try
						{
							ThreadInterrupts.WaitHoldingLock(gate);
						}
						catch (ThreadInterruptedException)
						{
							heldWhenThrown = Monitor.IsEntered(gate);
						}
					}
				}
				catch (Exception e)
				{
					failure = e;
				}
			}
		)
		{ IsBackground = true };

		thread.Start();
		bool waited = SpinWait.SpinUntil(() => Volatile.Read(ref waiting), TimeoutMilliseconds);

		lock (gate)
		{
			if (pulsed)
			{
				Monitor.Pulse(gate);
				Thread.Sleep(StepMilliseconds);
			}

			thread.Interrupt();
			Thread.Sleep(StepMilliseconds);
		}

		bool left = thread.Join(TimeoutMilliseconds);
		bool released = Monitor.TryEnter(gate);

		if (released)
		{
			Monitor.Exit(gate);
		}

		using (Assert.Multiple())
		{
			await Assert.That(waited).IsTrue();
			await Assert.That(left).IsTrue();
			await Assert.That(heldWhenThrown ?? pulsed).IsTrue();
			await Assert.That(failure).IsNull();
			await Assert.That(released).IsTrue();
		}
	}

	// A wait that loses the lock leaves the thread queued as a waiter, ahead of the wait it starts next, where a single pulse would wake the stale waiter alone.
	[Test]
	public async Task PulseReachesTheThreadAfterAnInterruptedWait()
	{
		object gate = new();
		bool done = false;
		int waits = 0;

		Thread thread = new
		(() =>
			{
				while (true)
				{
					try
					{
						lock (gate)
						{
							while (!Volatile.Read(ref done))
							{
								Interlocked.Increment(ref waits);
								ThreadInterrupts.WaitHoldingLock(gate);
							}
						}

						return;
					}
					catch (ThreadInterruptedException)
					{
					}
				}
			}
		)
		{ IsBackground = true };

		thread.Start();
		bool waited = SpinWait.SpinUntil(() => Volatile.Read(ref waits) >= 1, TimeoutMilliseconds);

		lock (gate)
		{
			thread.Interrupt();
			Thread.Sleep(StepMilliseconds);
			thread.Interrupt();
			Thread.Sleep(StepMilliseconds);
		}

		bool waitedAgain = SpinWait.SpinUntil(() => Volatile.Read(ref waits) >= 2, TimeoutMilliseconds);

		// Entered once the thread has released the gate inside its wait.
		lock (gate)
		{
			Volatile.Write(ref done, true);
			Monitor.Pulse(gate);
		}

		bool left = thread.Join(TimeoutMilliseconds);

		using (Assert.Multiple())
		{
			await Assert.That(waited).IsTrue();
			await Assert.That(waitedAgain).IsTrue();
			await Assert.That(left).IsTrue();
		}
	}
}
