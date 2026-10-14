namespace CryptoBase.Internal;

internal abstract class ThreadPoolHelper(ThreadPoolHelperBudget budget) : IThreadPoolWorkItem
{
	private int _shares;

	protected ThreadPoolHelper() : this(ThreadPoolHelperBudget.Shared)
	{
	}

	protected int QueueHelpers(int count)
	{
		int reserved = budget.Reserve(count);

		for (int queued = 0; queued < reserved; ++queued)
		{
			Interlocked.Increment(ref _shares);

			try
			{
				budget.Enqueue(this);
			}
			catch
			{
				// The failed enqueue may still have queued the helper, so its share is returned through the same path as a started one.
				ReturnShare();
				budget.Release(reserved - queued - 1);
				throw;
			}
		}

		return reserved;
	}

	internal abstract void Help();

	void IThreadPoolWorkItem.Execute()
	{
		ReturnShare();
		Help();
	}

	private void ReturnShare()
	{
		if (Interlocked.Decrement(ref _shares) >= 0)
		{
			budget.Release(1);
		}
	}
}
