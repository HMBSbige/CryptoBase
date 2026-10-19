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

	[UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_gate")]
	private static extern ref Lock Gate(Argon2MemoryCache cache);

	[UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_trimTimer")]
	private static extern ref Timer? TrimTimer(Argon2MemoryCache cache);
}
