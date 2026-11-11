namespace CryptoBase.Internal;

internal static class ThreadInterrupts
{
	internal static void Uninterruptibly<TState>(Action<TState> operation, TState state, ref bool interrupted)
	{
		while (true)
		{
			try
			{
				operation(state);
				return;
			}
			catch (ThreadInterruptedException)
			{
				interrupted = true;
			}
		}
	}

	// Monitor.Wait for a thread that has entered gate once and waits in a loop on its condition. Some runtimes let it throw ThreadInterruptedException without the lock and still queued as a waiter; the lock is taken back here first, and every waiter woken to empty the queue: https://github.com/dotnet/runtime/issues/137329
	// The check is in the catch block, since an exception filter would run before Monitor.Wait has tried to take the lock back.
	internal static void WaitHoldingLock(object gate)
	{
		try
		{
			Monitor.Wait(gate);
		}
		catch (ThreadInterruptedException)
		{
			if (!Monitor.IsEntered(gate))
			{
				bool interrupted = false;
				Uninterruptibly(static gate => Monitor.Enter(gate), gate, ref interrupted);
				Monitor.PulseAll(gate);
				RestoreInterrupt(interrupted);
			}

			throw;
		}
	}

	// Spinning, yielding and then sleeping, the wait needs nothing that may fail, and sleeping lets threads of any priority run on the processor.
	internal static void SpinUntilZero(ref int value)
	{
		bool interrupted = false;
		SpinWait spinner = default;

		while (Volatile.Read(ref value) is not 0)
		{
			try
			{
				spinner.SpinOnce();
			}
			catch (ThreadInterruptedException)
			{
				interrupted = true;
			}
		}

		RestoreInterrupt(interrupted);
	}

	internal static void RestoreInterrupt(bool interrupted)
	{
		if (interrupted)
		{
			Thread.CurrentThread.Interrupt();
		}
	}
}
