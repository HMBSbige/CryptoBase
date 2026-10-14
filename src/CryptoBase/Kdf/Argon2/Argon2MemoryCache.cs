using System.Diagnostics.CodeAnalysis;
using static CryptoBase.Internal.ThreadInterrupts;
using Region = (nint Address, nuint Length, long ReturnedAt);

namespace CryptoBase.Kdf.Argon2;

// Keeps recently released working memory for reuse: touching fresh memory costs a page fault per page, about as much as a whole pass.
// Freeing a region of tens of MiB takes milliseconds, so it happens outside the lock.
internal sealed unsafe class Argon2MemoryCache(nuint maxCachedBytes, int trimPeriodMilliseconds)
{
	internal const nuint Alignment = 64;

	private readonly Lock _gate = new();
	private readonly List<Region> _regions = [];
	private nuint _cachedBytes;
	private Timer? _trimTimer;

	internal static Argon2MemoryCache Shared { get; } = new(256 << 20, 2000);

	internal nuint CachedBytes
	{
		get
		{
			lock (_gate)
			{
				return _cachedBytes;
			}
		}
	}

	internal nint Rent(nuint length)
	{
		lock (_gate)
		{
			for (int i = _regions.Count - 1; i >= 0; --i)
			{
				Region region = _regions[i];

				if (region.Length == length)
				{
					_regions.RemoveAt(i);
					_cachedBytes -= length;
					return region.Address;
				}
			}
		}

		return (nint)NativeMemory.AlignedAlloc(length, Alignment);
	}

	// The memory must already be wiped.
	// Every region ends up cached or freed even if an allocation throws: each region is listed for freeing before it leaves the cache, and the timer starts before the returned region joins it.
	[SuppressMessage("ReSharper", "InconsistentlySynchronizedField", Justification = "_gate is entered through Uninterruptibly instead of a lock statement.")]
	internal void Return(nint address, nuint length)
	{
		if (length > maxCachedBytes)
		{
			NativeMemory.AlignedFree((void*)address);
			return;
		}

		List<Region>? evicted = null;
		bool interrupted = false;
		bool entered = false;
		bool cached = false;

		try
		{
			// The lock creates its wait event when first contended, so entering it can throw.
			Uninterruptibly(static gate => gate.Enter(), _gate, ref interrupted);
			entered = true;

			while (_cachedBytes + length > maxCachedBytes)
			{
				Region oldest = _regions[0];
				(evicted ??= []).Add(oldest);
				_regions.RemoveAt(0);
				_cachedBytes -= oldest.Length;
			}

			_trimTimer ??= CreateTrimTimer(ref interrupted);
			_regions.Add((address, length, Environment.TickCount64));
			_cachedBytes += length;
			cached = true;
		}
		finally
		{
			if (entered)
			{
				_gate.Exit();
			}

			if (!cached)
			{
				NativeMemory.AlignedFree((void*)address);
			}

			Free(evicted);
			RestoreInterrupt(interrupted);
		}
	}

	internal static void Discard(nint address, nuint length)
	{
		NativeMemory.Clear((void*)address, length);
		NativeMemory.AlignedFree((void*)address);
	}

	// Starting a timer links it into its queue before a wait an interrupt can cut short, so retrying the constructor of a running timer would leave the first one running unreferenced.
	// The timer is created stopped, which takes no lock, and Change only reschedules it.
	private Timer CreateTrimTimer(ref bool interrupted)
	{
		Timer timer;

		using (ExecutionContext.SuppressFlow())
		{
			timer = new Timer(static state => (state as Argon2MemoryCache)?.Trim(false), this, Timeout.Infinite, Timeout.Infinite);
		}

		Uninterruptibly(static state => state.Timer.Change(state.Period, state.Period), (Timer: timer, Period: trimPeriodMilliseconds), ref interrupted);
		return timer;
	}

	// The timer calls this on a pool thread, where an exception would end the process, so an interrupt must not cut short its waits.
	[SuppressMessage("ReSharper", "InconsistentlySynchronizedField", Justification = "_gate is entered through Uninterruptibly instead of a lock statement.")]
	internal void Trim(bool all)
	{
		List<Region>? idle = null;
		bool interrupted = false;
		Uninterruptibly(static gate => gate.Enter(), _gate, ref interrupted);

		try
		{
			long now = Environment.TickCount64;

			for (int i = _regions.Count - 1; i >= 0; --i)
			{
				Region region = _regions[i];

				if (all || now - region.ReturnedAt >= trimPeriodMilliseconds)
				{
					(idle ??= []).Add(region);
					_regions.RemoveAt(i);
					_cachedBytes -= region.Length;
				}
			}

			if (_regions.Count is 0 && _trimTimer is not null)
			{
				Uninterruptibly(static timer => timer.Dispose(), _trimTimer, ref interrupted);
				_trimTimer = null;
			}
		}
		finally
		{
			_gate.Exit();
			Free(idle);
			RestoreInterrupt(interrupted);
		}
	}

	private static void Free(List<Region>? regions)
	{
		if (regions is null)
		{
			return;
		}

		foreach (Region region in regions)
		{
			NativeMemory.AlignedFree((void*)region.Address);
		}
	}
}
