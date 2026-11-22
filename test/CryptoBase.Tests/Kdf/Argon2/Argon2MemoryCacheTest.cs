using CryptoBase.Kdf.Argon2;
using System.Runtime.CompilerServices;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Kdf.Argon2;

public class Argon2MemoryCacheTest
{
	private const int TrimPeriodMilliseconds = 60_000;

	[Test]
	public async Task ReusesReturnedRegionOfTheSameLength()
	{
		Argon2MemoryCache cache = new(1 << 20, TrimPeriodMilliseconds);

		try
		{
			nint first = cache.Rent(4096);
			cache.Return(first, 4096);
			nint other = cache.Rent(8192);
			nint reused = cache.Rent(4096);

			using (Assert.Multiple())
			{
				await Assert.That(first % (nint)Argon2MemoryCache.Alignment).IsEqualTo(0);
				await Assert.That(other % (nint)Argon2MemoryCache.Alignment).IsEqualTo(0);
				await Assert.That(other).IsNotEqualTo(first);
				await Assert.That(reused).IsEqualTo(first);
				await Assert.That(cache.CachedBytes).IsEqualTo(0u);
			}

			cache.Return(other, 8192);
			cache.Return(reused, 4096);
		}
		finally
		{
			cache.Trim(true);
		}
	}

	[Test]
	public async Task EvictsLeastRecentlyReturnedRegionsBeyondTheLimit()
	{
		Argon2MemoryCache cache = new(8192, TrimPeriodMilliseconds);

		try
		{
			nint first = cache.Rent(4096);
			nint second = cache.Rent(4096);
			nint third = cache.Rent(4096);
			nint oversized = cache.Rent(16384);
			cache.Return(first, 4096);
			cache.Return(second, 4096);
			cache.Return(third, 4096);
			cache.Return(oversized, 16384);

			await Assert.That(cache.CachedBytes).IsEqualTo(8192u);

			nint mostRecent = cache.Rent(4096);
			nint older = cache.Rent(4096);

			using (Assert.Multiple())
			{
				await Assert.That(mostRecent).IsEqualTo(third);
				await Assert.That(older).IsEqualTo(second);
				await Assert.That(cache.CachedBytes).IsEqualTo(0u);
			}

			cache.Return(mostRecent, 4096);
			cache.Return(older, 4096);
		}
		finally
		{
			cache.Trim(true);
		}

		await Assert.That(cache.CachedBytes).IsEqualTo(0u);
	}

	[Test]
	public async Task ReturnKeepsTheRegionDespiteAnInterrupt()
	{
		Argon2MemoryCache cache = new(1 << 20, TrimPeriodMilliseconds);
		Lock gate = Gate(cache);
		Exception? failure = null;
		bool interruptPending = false;

		try
		{
			nint region = cache.Rent(4096);

			Thread thread = new
			(() =>
				{
					Thread.CurrentThread.Interrupt();

					try
					{
						cache.Return(region, 4096);
					}
					catch (Exception e)
					{
						failure = e;
					}

					interruptPending = ConsumePendingInterrupt();
				}
			);

			// Only a contended wait throws the interrupt, so the lock is held until the thread waits for it or has ended.
			gate.Enter();

			try
			{
				thread.Start();
				SpinWait.SpinUntil(() => !thread.IsAlive || thread.ThreadState.HasFlag(ThreadState.WaitSleepJoin), 10_000);
			}
			finally
			{
				gate.Exit();
			}

			thread.Join();

			using (Assert.Multiple())
			{
				await Assert.That(failure).IsNull();
				await Assert.That(interruptPending).IsTrue();
				await Assert.That(cache.CachedBytes).IsEqualTo(4096u);
			}
		}
		finally
		{
			cache.Trim(true);
		}
	}

	[Test]
	public async Task KeepsRegionsReturnedWithinThePeriod()
	{
		Argon2MemoryCache cache = new(1 << 20, TrimPeriodMilliseconds);

		try
		{
			cache.Return(cache.Rent(4096), 4096);
			cache.Trim(false);

			using (Assert.Multiple())
			{
				await Assert.That(cache.CachedBytes).IsEqualTo(4096u);
				await Assert.That(TrimTimer(cache)).IsNotNull();
			}
		}
		finally
		{
			cache.Trim(true);
		}
	}

	// The trim timer calls back on the thread pool, where other tests running in parallel could hold it back past the deadline.
	[Test]
	[NotInParallel]
	public async Task FreesIdleRegions()
	{
		Argon2MemoryCache cache = new(1 << 20, 50);

		try
		{
			cache.Return(cache.Rent(4096), 4096);
			long deadline = Environment.TickCount64 + 10_000;

			while (cache.CachedBytes is not 0 && Environment.TickCount64 < deadline)
			{
				await Task.Delay(20);
			}

			using (Assert.Multiple())
			{
				await Assert.That(cache.CachedBytes).IsEqualTo(0u);
				await Assert.That(TrimTimer(cache)).IsNull();
			}
		}
		finally
		{
			cache.Trim(true);
		}
	}

	[Test]
	public async Task ReusesTheMostRecentlyReturnedRegionOfEachLength()
	{
		Argon2MemoryCache cache = new(1 << 20, TrimPeriodMilliseconds);

		try
		{
			nint first = cache.Rent(4096);
			nint second = cache.Rent(8192);
			nint third = cache.Rent(4096);
			nint fourth = cache.Rent(8192);
			nint fifth = cache.Rent(12288);
			cache.Return(first, 4096);
			cache.Return(second, 8192);
			cache.Return(third, 4096);
			cache.Return(fourth, 8192);
			cache.Return(fifth, 12288);

			nint[] reused = [cache.Rent(8192), cache.Rent(4096), cache.Rent(4096), cache.Rent(12288), cache.Rent(8192)];

			using (Assert.Multiple())
			{
				await Assert.That(reused).IsEquivalentTo([fourth, third, first, fifth, second], CollectionOrdering.Matching);
				await Assert.That(cache.CachedBytes).IsEqualTo(0u);
			}

			cache.Return(reused[0], 8192);
			cache.Return(reused[1], 4096);
			cache.Return(reused[2], 4096);
			cache.Return(reused[3], 12288);
			cache.Return(reused[4], 8192);
		}
		finally
		{
			cache.Trim(true);
		}
	}

	[Test]
	public async Task EvictsTheOldestOfManySmallRegions()
	{
		const int count = 1024;
		const nuint length = 8192;
		Argon2MemoryCache cache = new(count * length, TrimPeriodMilliseconds);

		try
		{
			nint[] regions = [.. Enumerable.Range(0, count).Select(_ => cache.Rent(length))];

			foreach (nint region in regions)
			{
				cache.Return(region, length);
			}

			nint large = cache.Rent(8 * length);
			cache.Return(large, 8 * length);
			nuint afterEviction = cache.CachedBytes;

			nint reusedLarge = cache.Rent(8 * length);
			nint[] reused = [.. Enumerable.Range(0, count - 8).Select(_ => cache.Rent(length))];

			using (Assert.Multiple())
			{
				await Assert.That(afterEviction).IsEqualTo(count * length);
				await Assert.That(reusedLarge).IsEqualTo(large);
				await Assert.That(reused).IsEquivalentTo(regions.Skip(8).Reverse(), CollectionOrdering.Matching);
				await Assert.That(cache.CachedBytes).IsEqualTo(0u);
			}

			cache.Return(reusedLarge, 8 * length);

			foreach (nint region in reused)
			{
				cache.Return(region, length);
			}
		}
		finally
		{
			cache.Trim(true);
		}
	}

	// The trim timer frees the same regions as the explicit trim, so it only has to stay clear of the second batch.
	[Test]
	[NotInParallel]
	public async Task FreesOnlyTheIdleOfManySmallRegions()
	{
		const int count = 512;
		const nuint length = 8192;
		const int periodMilliseconds = 2000;
		Argon2MemoryCache cache = new(4 * count * length, periodMilliseconds);

		try
		{
			nint[] idle = [.. Enumerable.Range(0, count).Select(_ => cache.Rent(length))];
			nint[] recent = [.. Enumerable.Range(0, count).Select(_ => cache.Rent(length))];

			foreach (nint region in idle)
			{
				cache.Return(region, length);
			}

			long idleSince = Environment.TickCount64;

			while (Environment.TickCount64 - idleSince < periodMilliseconds)
			{
				await Task.Delay(20);
			}

			foreach (nint region in recent)
			{
				cache.Return(region, length);
			}

			cache.Trim(false);
			nuint afterTrim = cache.CachedBytes;
			nint[] reused = [.. Enumerable.Range(0, count).Select(_ => cache.Rent(length))];

			using (Assert.Multiple())
			{
				await Assert.That(afterTrim).IsEqualTo(count * length);
				await Assert.That(reused).IsEquivalentTo(recent.Reverse(), CollectionOrdering.Matching);
				await Assert.That(cache.CachedBytes).IsEqualTo(0u);
			}

			foreach (nint region in reused)
			{
				cache.Return(region, length);
			}
		}
		finally
		{
			cache.Trim(true);
		}
	}

	[Test]
	public async Task TrimAllEmptiesTheCacheAndItFillsAgain()
	{
		Argon2MemoryCache cache = new(1 << 20, TrimPeriodMilliseconds);

		try
		{
			nint first = cache.Rent(4096);
			nint second = cache.Rent(8192);
			nint third = cache.Rent(4096);
			cache.Return(first, 4096);
			cache.Return(second, 8192);
			cache.Return(third, 4096);
			cache.Trim(true);
			nuint afterTrim = cache.CachedBytes;
			Timer? timerAfterTrim = TrimTimer(cache);

			nint region = cache.Rent(4096);
			cache.Return(region, 4096);
			nuint refilled = cache.CachedBytes;
			nint reused = cache.Rent(4096);

			using (Assert.Multiple())
			{
				await Assert.That(afterTrim).IsEqualTo(0u);
				await Assert.That(timerAfterTrim).IsNull();
				await Assert.That(refilled).IsEqualTo(4096u);
				await Assert.That(reused).IsEqualTo(region);
				await Assert.That(TrimTimer(cache)).IsNotNull();
			}

			cache.Return(reused, 4096);
		}
		finally
		{
			cache.Trim(true);
		}

		await Assert.That(TrimTimer(cache)).IsNull();
	}

	[UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_gate")]
	private static extern ref Lock Gate(Argon2MemoryCache cache);

	[UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_trimTimer")]
	private static extern ref Timer? TrimTimer(Argon2MemoryCache cache);
}
