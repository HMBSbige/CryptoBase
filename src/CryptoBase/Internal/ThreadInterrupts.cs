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
