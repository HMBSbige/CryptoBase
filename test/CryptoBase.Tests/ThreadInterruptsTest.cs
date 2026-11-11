using CryptoBase.Internal;

namespace CryptoBase.Tests;

public class ThreadInterruptsTest
{
	private const int TimeoutMilliseconds = 10_000;
	private const int StepMilliseconds = 100;

	// The interrupting thread holds the lock, so the waiting thread blocks to take it back. Once pulsed, it is doing so when the interrupt arrives.
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
			await Assert.That(heldWhenThrown).IsTrue();
			await Assert.That(failure).IsNull();
			await Assert.That(released).IsTrue();
		}
	}
}
