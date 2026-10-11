namespace CryptoBase.Kdf.Argon2;

internal static class Argon2Interrupts
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

	internal static void RestoreInterrupt(bool interrupted)
	{
		if (interrupted)
		{
			Thread.CurrentThread.Interrupt();
		}
	}
}
