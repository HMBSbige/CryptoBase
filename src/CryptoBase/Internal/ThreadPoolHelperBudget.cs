namespace CryptoBase.Internal;

// Bounds helpers queued but not yet started, so a saturated pool cannot collect idle helpers without bound.
internal sealed class ThreadPoolHelperBudget(int capacity, Action<IThreadPoolWorkItem> enqueue)
{
	internal static ThreadPoolHelperBudget Shared { get; } = new(Environment.ProcessorCount, static helper => ThreadPool.UnsafeQueueUserWorkItem(helper, false));

	private int _queued;

	internal int Queued => Volatile.Read(ref _queued);

	internal void Enqueue(IThreadPoolWorkItem helper)
	{
		enqueue(helper);
	}

	internal int Reserve(int count)
	{
		int queued = Volatile.Read(ref _queued);

		while (true)
		{
			int granted = Math.Min(count, capacity - queued);

			if (granted <= 0)
			{
				return 0;
			}

			int observed = Interlocked.CompareExchange(ref _queued, queued + granted, queued);

			if (observed == queued)
			{
				return granted;
			}

			queued = observed;
		}
	}

	internal void Release(int count)
	{
		if (count is not 0)
		{
			Interlocked.Add(ref _queued, -count);
		}
	}
}
