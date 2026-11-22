using System.Diagnostics.CodeAnalysis;
using static CryptoBase.Internal.ThreadInterrupts;
using Region = (nint Address, nuint Length, long ReturnedAt);

namespace CryptoBase.Kdf.Argon2;

// Keeps recently released working memory for reuse: touching fresh memory costs a page fault per page.
// Freeing a large region is slow, so it happens outside the lock.
// The regions leaving the cache to be freed are chained through their first word, so evicting and trimming allocate nothing managed.
internal sealed unsafe class Argon2MemoryCache(nuint maxCachedBytes, int trimPeriodMilliseconds)
{
	internal const nuint Alignment = 64;

	private readonly Lock _gate = new();

	// The cached regions are _count entries from _oldest, from the least to the most recently returned, so the return times rise along them.
	private Region[] _regions = [];
	private int _oldest;
	private int _count;
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
			Span<Region> regions = _regions.AsSpan(_oldest, _count);

			for (int i = regions.Length - 1; i >= 0; --i)
			{
				if (regions[i].Length == length)
				{
					nint address = regions[i].Address;
					regions.Slice(i + 1).CopyTo(regions.Slice(i));
					--_count;
					_cachedBytes -= length;
					return address;
				}
			}
		}

		return (nint)NativeMemory.AlignedAlloc(length, Alignment);
	}

	// The memory must already be wiped.
	// Every region ends up cached or freed even if an allocation throws.
	// Chaining an evicted region cannot fail, and the timer starts and the array makes room before the returned region joins it.
	[SuppressMessage("ReSharper", "InconsistentlySynchronizedField", Justification = "_gate is entered through Uninterruptibly instead of a lock statement.")]
	internal void Return(nint address, nuint length)
	{
		if (length > maxCachedBytes)
		{
			NativeMemory.AlignedFree((void*)address);
			return;
		}

		Debug.Assert(length >= (nuint)sizeof(nint));

		nint evicted = 0;
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
				Chain(ref evicted, RemoveOldest());
			}

			_trimTimer ??= CreateTrimTimer(ref interrupted);

			if (_oldest + _count == _regions.Length)
			{
				MakeRoom();
			}

			_regions[_oldest + _count] = (address, length, Environment.TickCount64);
			++_count;
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

	// Starting a timer links it into its queue before a wait an interrupt can cut short.
	// So retrying the constructor of a running timer would leave the first one running unreferenced.
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
		nint idle = 0;
		bool interrupted = false;
		Uninterruptibly(static gate => gate.Enter(), _gate, ref interrupted);

		try
		{
			long now = Environment.TickCount64;

			while (_count is not 0 && (all || now - _regions[_oldest].ReturnedAt >= trimPeriodMilliseconds))
			{
				Chain(ref idle, RemoveOldest());
			}

			if (_count is 0 && _trimTimer is not null)
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

	private nint RemoveOldest()
	{
		Region oldest = _regions[_oldest];
		++_oldest;
		--_count;
		_cachedBytes -= oldest.Length;
		return oldest.Address;
	}

	// The regions move to the front only when that frees at least half the array, so appending takes constant time on average.
	private void MakeRoom()
	{
		Region[] regions = _count < _regions.Length / 2 ? _regions : new Region[Math.Max(4, 2 * _regions.Length)];
		_regions.AsSpan(_oldest, _count).CopyTo(regions);
		_regions = regions;
		_oldest = 0;
	}

	private static void Chain(ref nint chain, nint address)
	{
		*(nint*)address = chain;
		chain = address;
	}

	private static void Free(nint chain)
	{
		while (chain is not 0)
		{
			nint next = *(nint*)chain;
			NativeMemory.AlignedFree((void*)chain);
			chain = next;
		}
	}
}
