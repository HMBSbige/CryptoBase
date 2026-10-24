using CryptoBase.Hashes.Blake3;
using CryptoBase.Internal;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hashes.Blake3;

public class Blake3ParallelTest
{
	public enum StateBeforeFailedAppend
	{
		// 100 bytes in the group buffer, which the failing append fills to a group of chunks.
		BufferedGroup,

		// 100 bytes and a read, after which the failing append fills a single chunk in chunk mode.
		BufferedChunk,

		// Reads after 100 bytes and after 5000, after which chunk mode has stacked chunks and compressed the first blocks of the one it buffers.
		PartlyCompressedChunk,

		// 2048 bytes in the group buffer and a read; the failing append switches to chunk mode, stacking both chunks and emptying the buffer, unless ChunkModeInterval is shorter, as with AVX-512.
		BufferedTwoChunks,

		// Reads after 8191 bytes and after 8192, with nothing appended in between but the byte that separates them; the failing append switches to chunk mode, stacking the eight chunks of the group buffer and emptying it, unless a longer ChunkModeInterval, as without hardware intrinsics, switched already.
		BufferedEightChunksAfterReads
	}

	private const int OutputLength = 131;
	private const int TimeoutMilliseconds = 30_000;

	// The calling thread spins for about 500 µs, ParallelJob.SpinTicks, before it blocks, so one that still waits this long after Finish started has blocked.
	private const int BlockedAfterMilliseconds = 50;

	private const int HoldMilliseconds = 100;

	public static IEnumerable<int> Lengths => [65537, 131072, 131073, 1048576, 1048577, 3 * 1048576 + 1025];

	public static IEnumerable<int> Parallelisms => [2, 3, 4, 16, -1];

	private static readonly int[] HeadLengths = [0, 1, 1024, 3 * 1024 + 5, 65536 + 1024];

	private static readonly int[][] PieceSequences =
	[
		[1_000_000, 1_000_000, 1_000_000],
		[777, 1048576, 1048576, 1048576],
		[1048576, 2 * 1048576, 3 * 1048576],
		[65536 + 1024, 3 * 1024 + 5, 2 * 1048576 + 1, 131072 - 1, 999]
	];

	private static readonly int[][] GroupPieceSequences =
	[
		[100, 16284, 1, 16383, 16384, 16385, 2],
		[16384, 16384, 1, 16384, 16383, 32768, 32769, 5],
		[1000, 1000, 70000, 16384, 49152, 7, 65536 + 16384, 3],
		[16385, 16385, 16385, 16385, 262144, 1],
		[0, 16384, 0, 1, 0, 300000, 0, 16383, 1, 16384],
		[3 * 1048576 + 16384, 16384, 1048576 - 1, 1, 2 * 1048576],
		[1024],
		[1024, 1024, 1]
	];

	[Test]
	[CombinedDataSources]
	public async Task HashingMatchesSerial([MethodDataSource(nameof(Lengths))] int length, [MethodDataSource(nameof(Parallelisms))] int maxDegreeOfParallelism)
	{
		byte[] source = CreateDeterministicSource(length);

		foreach (Blake3Mode mode in Blake3TestUtils.Modes)
		{
			byte[] expected = Blake3TestUtils.HashData(mode, source, OutputLength);

			await Assert.That(Blake3TestUtils.HashData(mode, source, OutputLength, maxDegreeOfParallelism)).IsEquivalentTo(expected, CollectionOrdering.Matching);

			foreach (int headLength in HeadLengths.Where(headLength => headLength < length))
			{
				int tailLength = Math.Min(7, length - headLength);
				using Blake3HashAlgorithm hasher = Blake3TestUtils.CreateHasher(mode);
				hasher.Append(source.AsSpan(0, headLength));
				hasher.Append(source.AsSpan(headLength, length - headLength - tailLength), maxDegreeOfParallelism);
				hasher.Append(source.AsSpan(length - tailLength));

				byte[] actual = new byte[OutputLength];
				hasher.GetCurrentHash(actual);
				await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
			}
		}
	}

	// Array.MaxLength is less than a leaf short of 2^31 for every leaf length, so a whole last leaf ends past int.MaxValue. NumberLeaves and FindLeaf only compute offsets, so the split is checked without allocating the input.
	[Test]
	[Arguments(new[] { 0, int.MaxValue }, 16 * 1024)]
	[Arguments(new[] { 0, int.MaxValue }, 1 << 27)]
	[Arguments(new[] { 0, int.MaxValue - (1 << 27) + 2 }, 1 << 27)]
	[Arguments(new[] { 0, 1 << 30, 0x7FFFFFC7 }, 1 << 26)]
	[Arguments(new[] { 0, 1 << 30, 0x7FFFFFC7 }, 1 << 30)]
	[Arguments(new[] { 0, 1 << 30, (1 << 30) + (1 << 29), 0x7FFFFFC7 }, 1 << 28)]
	public async Task LeavesTileInputNearMaxLength(int[] boundaries, int leafLength)
	{
		int subtrees = boundaries.Length - 1;
		int[] firstItems = new int[subtrees + 1];
		int items = Blake3Parallel.NumberLeaves(boundaries, leafLength, firstItems);
		int end = 0;
		int subtree = 0;
		string? failure = null;

		for (int index = 0; index < items && failure is null; ++index)
		{
			Blake3Leaf leaf = Blake3Parallel.FindLeaf(boundaries, firstItems, leafLength, index);

			if (leaf.Start == boundaries[subtree + 1])
			{
				++subtree;
			}

			bool whole = firstItems[subtree + 1] - firstItems[subtree] is 1;

			if (leaf.Subtree != subtree || leaf.Start != end || leaf.Length is <= 0 || leaf.Length > (whole ? boundaries[subtree + 1] - boundaries[subtree] : leafLength) || leaf.IsWholeSubtree != whole)
			{
				failure = $"item {index}: {leaf}, expected subtree {subtree} from {end}";
			}

			end = leaf.Start + leaf.Length;
		}

		using (Assert.Multiple())
		{
			await Assert.That(failure).IsNull();
			await Assert.That(end).IsEqualTo(boundaries[subtrees]);
		}
	}

	[Test]
	[MethodDataSource(nameof(Parallelisms))]
	public async Task PiecewiseAppendsMatchOneShot(int maxDegreeOfParallelism)
	{
		foreach (int[] pieceLengths in PieceSequences)
		{
			byte[] source = CreateDeterministicSource(pieceLengths.Sum());

			foreach (Blake3Mode mode in Blake3TestUtils.Modes)
			{
				using Blake3HashAlgorithm hasher = Blake3TestUtils.CreateHasher(mode);
				await AppendAndVerify(hasher, mode, source, 0, pieceLengths, maxDegreeOfParallelism);
			}
		}
	}

	[Test]
	[Arguments(1)]
	[Arguments(2)]
	[Arguments(-1)]
	public async Task GroupBufferedAppendsMatchOneShot(int maxDegreeOfParallelism)
	{
		foreach (int[] pieceLengths in GroupPieceSequences)
		{
			byte[] source = CreateDeterministicSource(pieceLengths.Sum());
			int half = pieceLengths.Length / 2;

			foreach (Blake3Mode mode in Blake3TestUtils.Modes)
			{
				using Blake3HashAlgorithm hasher = Blake3TestUtils.CreateHasher(mode);
				int length = await AppendAndVerify(hasher, mode, source, 0, pieceLengths.Take(half), maxDegreeOfParallelism);

				using Blake3HashAlgorithm clone = hasher.Clone();
				await AppendAndVerify(hasher, mode, source, length, pieceLengths.Skip(half), maxDegreeOfParallelism);
				await AppendAndVerify(clone, mode, source, length, pieceLengths.Skip(half), maxDegreeOfParallelism);

				hasher.Reset();
				await AppendAndVerify(hasher, mode, source, 0, pieceLengths, maxDegreeOfParallelism);
				byte[] actual = new byte[OutputLength];
				hasher.GetHashAndReset(actual);
				await Assert.That(actual).IsEquivalentTo(Blake3TestUtils.HashData(mode, source, OutputLength), CollectionOrdering.Matching);
				hasher.GetCurrentHash(actual);
				await Assert.That(actual).IsEquivalentTo(Blake3TestUtils.HashData(mode, [], OutputLength), CollectionOrdering.Matching);
			}
		}
	}

	[Test]
	[MethodDataSource(nameof(Parallelisms))]
	public async Task OutputMatchesSerial(int maxDegreeOfParallelism)
	{
		byte[] source = CreateDeterministicSource(5000);
		using Blake3HashAlgorithm hasher = Blake3HashAlgorithm.Create();
		hasher.Append(source);

		foreach (ulong position in new ulong[] { 0, 7, (1UL << 38) - 64 * 100 - 3 })
		{
			foreach (int length in new[] { 128 * 1024 + 64 + 5, 1024 * 1024 + 13 })
			{
				byte[] expected = new byte[length];
				hasher.GetCurrentHash(expected, position);
				byte[] actual = new byte[length + 1];
				PrepareDestination(actual);
				hasher.GetCurrentHash(actual.AsSpan(0, length), position, maxDegreeOfParallelism);
				await AssertOutput(actual, expected);
			}
		}

		byte[] oneShotExpected = new byte[1024 * 1024 + 13];
		Blake3HashAlgorithm.HashData(source, oneShotExpected);
		byte[] oneShot = new byte[oneShotExpected.Length];
		Blake3HashAlgorithm.HashData(source, oneShot, maxDegreeOfParallelism);
		await Assert.That(oneShot).IsEquivalentTo(oneShotExpected, CollectionOrdering.Matching);
	}

	// The reference takes far longer than the hashing it checks, so one output of it serves both positions and every degree of parallelism.
	[Test]
	[CombinedDataSources]
	public async Task OutputMatchesReferenceInEveryMode([Arguments(0, 7, 64, 65, 1024, 5000)] int sourceLength, [MethodDataSource(typeof(Blake3TestUtils), nameof(Blake3TestUtils.Modes))] Blake3Mode mode)
	{
		const int length = 128 * 1024 + 64 + 5;
		const int position = 7;
		byte[] source = CreateDeterministicSource(sourceLength);
		byte[] reference = Blake3TestUtils.ReferenceHash(mode, source, position + length);
		byte[] expected = reference.AsSpan(0, length).ToArray();
		byte[] expectedAtPosition = reference.AsSpan(position, length).ToArray();

		foreach (int maxDegreeOfParallelism in Parallelisms)
		{
			byte[] oneShot = Blake3TestUtils.HashData(mode, source, length, maxDegreeOfParallelism);
			await Assert.That(oneShot).IsEquivalentTo(expected, CollectionOrdering.Matching);

			using Blake3HashAlgorithm hasher = Blake3TestUtils.CreateHasher(mode);
			hasher.Append(source);
			byte[] actual = new byte[length + 1];
			PrepareDestination(actual);
			hasher.GetCurrentHash(actual.AsSpan(0, length), position, maxDegreeOfParallelism);
			await AssertOutput(actual, expectedAtPosition);
		}
	}

	// Queuing a helper may fail for lack of memory; the append then throws and the hasher keeps its input, so the append can be retried.
	[Test]
	[Arguments(StateBeforeFailedAppend.BufferedGroup)]
	[Arguments(StateBeforeFailedAppend.BufferedChunk)]
	[Arguments(StateBeforeFailedAppend.PartlyCompressedChunk)]
	[Arguments(StateBeforeFailedAppend.BufferedTwoChunks)]
	[Arguments(StateBeforeFailedAppend.BufferedEightChunksAfterReads)]
	[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Catch runs the closure synchronously before the hasher is disposed.")]
	public async Task FailedParallelAppendKeepsTheInput(StateBeforeFailedAppend state)
	{
		byte[] source = CreateDeterministicSource(8192 + 1048576);
		ThreadPoolHelperBudget failing = new(8, static _ => throw new OutOfMemoryException());

		foreach (Blake3Mode mode in Blake3TestUtils.Modes)
		{
			using Blake3HashAlgorithm hasher = Blake3TestUtils.CreateHasher(mode);
			int length = Prepare(hasher, source, state);
			Exception? failure = Catch(() => hasher.Append(source.AsSpan(length), 4, failing));
			byte[] afterFailure = new byte[OutputLength];
			hasher.GetCurrentHash(afterFailure);
			hasher.Append(source.AsSpan(length), 4);
			byte[] afterRetry = new byte[OutputLength];
			hasher.GetCurrentHash(afterRetry);

			using (Assert.Multiple())
			{
				await Assert.That(failure).IsTypeOf<OutOfMemoryException>();
				await Assert.That(afterFailure).IsEquivalentTo(Blake3TestUtils.HashData(mode, source.AsSpan(0, length), OutputLength), CollectionOrdering.Matching);
				await Assert.That(afterRetry).IsEquivalentTo(Blake3TestUtils.HashData(mode, source, OutputLength), CollectionOrdering.Matching);
			}
		}
	}

	// With no helper granted, the work takes the serial path, which beats the calling thread hashing every leaf alone; helpers run inline show that only the budget keeps it serial.
	[Test]
	[Arguments(2)]
	[Arguments(16)]
	public async Task HashingWithoutHelpersTakesTheSerialPath(int maxDegreeOfParallelism)
	{
		byte[] source = CreateDeterministicSource(1048576 + 1025);
		ThreadPoolHelperBudget none = new(0, static _ => throw new InvalidOperationException("The budget grants no helper."));
		ThreadPoolHelperBudget inlineHelpers = new(maxDegreeOfParallelism, static helper => helper.Execute());

		bool parallelWithoutHelpers = TryCompressInParallel(source, maxDegreeOfParallelism, none);
		bool parallelWithInlineHelpers = TryCompressInParallel(source, maxDegreeOfParallelism, inlineHelpers);
		(byte[] OneShot, byte[] Incremental, byte[] Output) expected = HashEveryWay(source, 1, ThreadPoolHelperBudget.Shared);
		(byte[] OneShot, byte[] Incremental, byte[] Output) actual = HashEveryWay(source, maxDegreeOfParallelism, none);

		using (Assert.Multiple())
		{
			await Assert.That(parallelWithoutHelpers).IsFalse();
			await Assert.That(parallelWithInlineHelpers).IsTrue();
			await Assert.That(actual.OneShot).IsEquivalentTo(expected.OneShot, CollectionOrdering.Matching);
			await Assert.That(actual.Incremental).IsEquivalentTo(expected.Incremental, CollectionOrdering.Matching);
			await Assert.That(actual.Output).IsEquivalentTo(expected.Output, CollectionOrdering.Matching);
		}
	}

	// Other tests contending for the array pool's locks would let the interrupt throw.
	[Test]
	[NotInParallel]
	public async Task PendingInterruptSurvivesParallelHashing()
	{
		byte[] source = CreateDeterministicSource(4 * 1048576 + 1);
		byte[] expected = Blake3TestUtils.HashData(Blake3Mode.Hash, source, OutputLength);
		byte[] oneShot = new byte[OutputLength];
		byte[] incremental = new byte[OutputLength];
		Exception? failure = null;
		bool interruptPending = false;

		// A dedicated thread keeps the interrupt away from other work.
		Thread thread = new
			(() =>
				{
					try
					{
						Thread.CurrentThread.Interrupt();
						Blake3HashAlgorithm.HashData(source, oneShot, 4);

						using Blake3HashAlgorithm hasher = Blake3HashAlgorithm.Create();
						hasher.Append(source, 4);
						hasher.GetCurrentHash(incremental, 0, 4);
					}
					catch (Exception e)
					{
						failure = e;
					}

					interruptPending = ConsumePendingInterrupt();
				}
			)
		{ IsBackground = true };

		thread.Start();
		bool finished = thread.Join(TimeoutMilliseconds);

		using (Assert.Multiple())
		{
			await Assert.That(finished).IsTrue();
			await Assert.That(failure).IsNull();
			await Assert.That(interruptPending).IsTrue();
			await Assert.That(oneShot).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(incremental).IsEquivalentTo(expected, CollectionOrdering.Matching);
		}
	}

	// The test runs the helper on a dedicated thread rather than queuing it, so that it is sure to take part.
	[Test]
	[Arguments(false)]
	[Arguments(true)]
	public async Task InterruptedCallerWaitsForHelpers(bool whileBlocked)
	{
		HeldJob job = new();
		Exception? callerFailure = null;
		Exception? helperFailure = null;
		bool interruptPending = false;
		long finishStarted = 0;

		Thread helper = new(() => helperFailure = Catch(job.Help)) { IsBackground = true };
		Thread caller = new
			(() =>
				{
					// Interrupted before Finish, the calling thread takes the interrupt while it spins; otherwise the test interrupts it once it has blocked.
					if (!whileBlocked)
					{
						Thread.CurrentThread.Interrupt();
					}

					Volatile.Write(ref finishStarted, Stopwatch.GetTimestamp());
					callerFailure = Catch(job.Finish);
					interruptPending = ConsumePendingInterrupt();
				}
			)
		{ IsBackground = true };

		helper.Start();
		bool helperEntered = SpinWait.SpinUntil(() => job.Entered, TimeoutMilliseconds);
		caller.Start();
		bool callerBlocked;
		bool callerWaited;
		bool callerLeft;
		bool helperLeft;

		try
		{
			callerBlocked = SpinWait.SpinUntil(() => IsBlocked(caller, Volatile.Read(ref finishStarted)), TimeoutMilliseconds);

			if (whileBlocked)
			{
				caller.Interrupt();
			}

			callerWaited = !caller.Join(HoldMilliseconds);
		}
		finally
		{
			job.Release();
			callerLeft = caller.Join(TimeoutMilliseconds);
			helperLeft = helper.Join(TimeoutMilliseconds);
		}

		using (Assert.Multiple())
		{
			await Assert.That(helperEntered).IsTrue();
			await Assert.That(callerBlocked).IsTrue();
			await Assert.That(callerWaited).IsTrue();
			await Assert.That(callerLeft).IsTrue();
			await Assert.That(helperLeft).IsTrue();
			await Assert.That(callerFailure).IsNull();
			await Assert.That(helperFailure).IsNull();
			await Assert.That(interruptPending).IsTrue();
			await Assert.That(job.Processed).IsEqualTo(1);
		}
	}

	// The pool thread that finishes the last item may carry an interrupt meant for other work: waking a blocked calling thread must neither throw it, which would end the process, nor lose it.
	[Test]
	public async Task HelperWithPendingInterruptWakesBlockedCaller()
	{
		HeldJob job = new();
		Exception? callerFailure = null;
		Exception? helperFailure = null;
		bool callerInterruptPending = false;
		bool helperInterruptPending = false;
		StrongBox<bool> helperReturned = new();
		long finishStarted = 0;

		Thread helper = new
			(() =>
				{
					helperFailure = Catch(job.Help);
					Volatile.Write(ref helperReturned.Value, true);
					helperInterruptPending = ConsumePendingInterrupt();
				}
			)
		{ IsBackground = true };
		Thread caller = new
			(() =>
				{
					Volatile.Write(ref finishStarted, Stopwatch.GetTimestamp());
					callerFailure = Catch(job.Finish);
					callerInterruptPending = ConsumePendingInterrupt();
				}
			)
		{ IsBackground = true };

		helper.Start();
		bool helperEntered = SpinWait.SpinUntil(() => job.Entered, TimeoutMilliseconds);
		caller.Start();
		bool callerBlocked;
		bool helperContended;
		bool callerLeft;
		bool helperLeft;

		try
		{
			callerBlocked = SpinWait.SpinUntil(() => IsBlocked(caller, Volatile.Read(ref finishStarted)), TimeoutMilliseconds);

			// The helper only spins on its item, so the interrupt stays pending until the helper waits for the lock that the test holds, to wake the caller.
			helper.Interrupt();

			lock (job)
			{
				job.Release();
				helperContended = SpinWait.SpinUntil(() => Volatile.Read(ref helperReturned.Value) || helper.ThreadState.HasFlag(System.Threading.ThreadState.WaitSleepJoin), TimeoutMilliseconds) && !Volatile.Read(ref helperReturned.Value);
			}
		}
		finally
		{
			job.Release();
			callerLeft = caller.Join(TimeoutMilliseconds);
			helperLeft = helper.Join(TimeoutMilliseconds);
		}

		using (Assert.Multiple())
		{
			await Assert.That(helperEntered).IsTrue();
			await Assert.That(callerBlocked).IsTrue();
			await Assert.That(helperContended).IsTrue();
			await Assert.That(callerLeft).IsTrue();
			await Assert.That(helperLeft).IsTrue();
			await Assert.That(callerFailure).IsNull();
			await Assert.That(helperFailure).IsNull();
			await Assert.That(callerInterruptPending).IsFalse();
			await Assert.That(helperInterruptPending).IsTrue();
			await Assert.That(job.Processed).IsEqualTo(1);
		}
	}

	// An item that throws on the calling thread must not escape Finish while a helper still works in memory that the caller then releases.
	[Test]
	public async Task CallerFailureWaitsForHelpers()
	{
		FailingJob job = new();
		Exception? callerFailure = null;
		Exception? helperFailure = null;
		long finishStarted = 0;

		Thread helper = new(() => helperFailure = Catch(job.Help)) { IsBackground = true };
		Thread caller = new
			(() =>
				{
					Volatile.Write(ref finishStarted, Stopwatch.GetTimestamp());
					callerFailure = Catch(job.Finish);
				}
			)
		{ IsBackground = true };

		helper.Start();
		bool helperEntered = SpinWait.SpinUntil(() => job.Entered, TimeoutMilliseconds);
		caller.Start();
		// The calling thread blocks only after taking the failing item and abandoning the rest, so releasing the helper earlier would let it take them.
		bool callerBlocked = SpinWait.SpinUntil(() => !caller.IsAlive || IsBlocked(caller, Volatile.Read(ref finishStarted)), TimeoutMilliseconds) && caller.IsAlive;
		job.Release();
		bool callerLeft = caller.Join(TimeoutMilliseconds);
		bool helperLeft = helper.Join(TimeoutMilliseconds);

		using (Assert.Multiple())
		{
			await Assert.That(helperEntered).IsTrue();
			await Assert.That(callerBlocked).IsTrue();
			await Assert.That(callerLeft).IsTrue();
			await Assert.That(helperLeft).IsTrue();
			await Assert.That(callerFailure).IsTypeOf<InvalidOperationException>();
			await Assert.That(helperFailure).IsNull();
			await Assert.That(job.AbandonedItemTaken).IsFalse();
		}
	}

	// On Windows a helper preempted by a busier thread of higher priority can only move to the calling thread's processor, which a caller above the pool's priority would keep busy for as long as it spins; blocking frees it. The busy thread ranks below the caller, so it never preempts the caller itself. The test narrows the affinity of the whole process, so it runs alone and only on request.
	[Test]
	[Explicit]
	[NotInParallel]
	public async Task CallerAbovePoolPriorityLetsStarvedHelperFinish()
	{
		const int busyMilliseconds = 1000;
		const int runMilliseconds = 5000;
		const int longestJobMilliseconds = 250;

		if (!OperatingSystem.IsWindows() || Environment.ProcessorCount < 2)
		{
			Skip.Test("Windows thread priorities and two processors are required.");
			return;
		}

		using Process process = Process.GetCurrentProcess();
		nint affinity = process.ProcessorAffinity;
		StrongBox<bool> stop = new();
		long longestTicks = 0;

		Thread busy = new
			(() =>
				{
					while (!Volatile.Read(ref stop.Value))
					{
						SpinFor(busyMilliseconds * Stopwatch.Frequency / 1000);
						Thread.Sleep(10);
					}
				}
			)
		{ IsBackground = true, Priority = ThreadPriority.AboveNormal };
		Thread caller = new
			(() =>
				{
					long end = Stopwatch.GetTimestamp() + runMilliseconds * Stopwatch.Frequency / 1000;

					while (Stopwatch.GetTimestamp() < end)
					{
						long start = Stopwatch.GetTimestamp();
						SpinningJob job = new();

						// Finish takes the items that no helper takes, so the job runs whole whether or not the budget grants helpers.
						_ = job.TryStart(SpinningJob.Threads);
						job.Finish();
						longestTicks = Math.Max(longestTicks, Stopwatch.GetTimestamp() - start);
					}
				}
			)
		{ IsBackground = true, Priority = ThreadPriority.Highest };

		process.ProcessorAffinity = 0b11;
		bool callerLeft;
		bool busyLeft;

		try
		{
			busy.Start();
			caller.Start();
			callerLeft = caller.Join(TimeoutMilliseconds);
		}
		finally
		{
			Volatile.Write(ref stop.Value, true);
			busyLeft = busy.Join(TimeoutMilliseconds);
			process.ProcessorAffinity = affinity;
		}

		using (Assert.Multiple())
		{
			await Assert.That(callerLeft).IsTrue();
			await Assert.That(busyLeft).IsTrue();
			await Assert.That(Stopwatch.GetElapsedTime(0, longestTicks).TotalMilliseconds).IsLessThan(longestJobMilliseconds);
		}
	}

	private static async Task<int> AppendAndVerify(Blake3HashAlgorithm hasher, Blake3Mode mode, byte[] source, int length, IEnumerable<int> pieceLengths, int maxDegreeOfParallelism)
	{
		foreach (int pieceLength in pieceLengths)
		{
			if (maxDegreeOfParallelism is 1)
			{
				hasher.Append(source.AsSpan(length, pieceLength));
			}
			else
			{
				hasher.Append(source.AsSpan(length, pieceLength), maxDegreeOfParallelism);
			}

			length += pieceLength;
			byte[] actual = new byte[OutputLength];
			hasher.GetCurrentHash(actual);
			await Assert.That(actual).IsEquivalentTo(Blake3TestUtils.HashData(mode, source.AsSpan(0, length), OutputLength), CollectionOrdering.Matching);
		}

		return length;
	}

	// Brings the hasher to the state before the failing append, returning the length of the input that it has taken.
	private static int Prepare(Blake3HashAlgorithm hasher, byte[] source, StateBeforeFailedAppend state)
	{
		byte[] hash = new byte[OutputLength];

		if (state is StateBeforeFailedAppend.BufferedTwoChunks)
		{
			hasher.Append(source.AsSpan(0, 2048));
			hasher.GetCurrentHash(hash);
			return 2048;
		}

		if (state is StateBeforeFailedAppend.BufferedEightChunksAfterReads)
		{
			hasher.Append(source.AsSpan(0, 8191));
			hasher.GetCurrentHash(hash);
			hasher.Append(source.AsSpan(8191, 1));
			hasher.GetCurrentHash(hash);
			return 8192;
		}

		hasher.Append(source.AsSpan(0, 100));

		if (state is StateBeforeFailedAppend.BufferedGroup)
		{
			return 100;
		}

		hasher.GetCurrentHash(hash);

		if (state is StateBeforeFailedAppend.BufferedChunk)
		{
			return 100;
		}

		hasher.Append(source.AsSpan(100, 4900));
		hasher.GetCurrentHash(hash);
		return 5000;
	}

	private static bool TryCompressInParallel(byte[] source, int maxDegreeOfParallelism, ThreadPoolHelperBudget budget)
	{
		Span<byte> children = stackalloc byte[2 * Blake3Constants.OutLength];
		return Blake3Parallel.TryCompressSubtreeToParentNode(source, in Blake3Constants.IV, 0, children, maxDegreeOfParallelism, budget);
	}

	// Hashes in one shot, appends after a buffered head and reads long output, all of which hash in parallel when helpers take part.
	private static (byte[] OneShot, byte[] Incremental, byte[] Output) HashEveryWay(byte[] source, int maxDegreeOfParallelism, ThreadPoolHelperBudget budget)
	{
		byte[] oneShot = new byte[OutputLength];
		Blake3HashAlgorithm.HashData(source, oneShot, maxDegreeOfParallelism, budget);

		using Blake3HashAlgorithm hasher = Blake3HashAlgorithm.Create();
		hasher.Append(source.AsSpan(0, 1000));
		hasher.Append(source.AsSpan(1000), maxDegreeOfParallelism, budget);
		byte[] incremental = new byte[OutputLength];
		hasher.GetCurrentHash(incremental);

		byte[] output = new byte[1048576 + 13];
		hasher.GetCurrentHash(output, 7, maxDegreeOfParallelism, budget);
		return (oneShot, incremental, output);
	}

	private static Exception? Catch(Action action)
	{
		try
		{
			action();
			return null;
		}
		catch (Exception e)
		{
			return e;
		}
	}

	private static bool IsBlocked(Thread thread, long finishStarted)
	{
		return finishStarted is not 0 && Stopwatch.GetElapsedTime(finishStarted).TotalMilliseconds > BlockedAfterMilliseconds && thread.ThreadState.HasFlag(System.Threading.ThreadState.WaitSleepJoin);
	}

	private static void SpinFor(long ticks)
	{
		long end = Stopwatch.GetTimestamp() + ticks;

		while (Stopwatch.GetTimestamp() < end)
		{
			Thread.SpinWait(1);
		}
	}

	// One item, which its helper holds until the test releases it, spinning rather than waiting, so that an interrupt pending on the helper can only surface in the waits of the job.
	private sealed class HeldJob() : Blake3Parallel.ParallelJob(1, ThreadPoolHelperBudget.Shared)
	{
		private bool _entered;
		private bool _released;
		private int _processed;

		public bool Entered => Volatile.Read(ref _entered);

		public int Processed => Volatile.Read(ref _processed);

		public void Release()
		{
			Volatile.Write(ref _released, true);
		}

		protected override void ProcessItem(int index)
		{
			Volatile.Write(ref _entered, true);
			long deadline = Stopwatch.GetTimestamp() + TimeoutMilliseconds * Stopwatch.Frequency / 1000;

			while (!Volatile.Read(ref _released) && Stopwatch.GetTimestamp() < deadline)
			{
				Thread.Yield();
			}

			Interlocked.Increment(ref _processed);
		}
	}

	// The helper holds the first item until the test releases it, the calling thread throws on the second, and nobody may take the third.
	private sealed class FailingJob() : Blake3Parallel.ParallelJob(3, ThreadPoolHelperBudget.Shared)
	{
		private bool _entered;
		private bool _released;
		private bool _abandonedItemTaken;

		public bool Entered => Volatile.Read(ref _entered);

		public bool AbandonedItemTaken => Volatile.Read(ref _abandonedItemTaken);

		public void Release()
		{
			Volatile.Write(ref _released, true);
		}

		protected override void ProcessItem(int index)
		{
			switch (index)
			{
				case 0:
				{
					Volatile.Write(ref _entered, true);
					SpinWait.SpinUntil(() => Volatile.Read(ref _released), TimeoutMilliseconds);
					break;
				}
				case 1:
				{
					throw new InvalidOperationException();
				}
				default:
				{
					Volatile.Write(ref _abandonedItemTaken, true);
					break;
				}
			}
		}
	}

	// Items of about 100 µs each, so that helpers take some while the calling thread takes the rest.
	private sealed class SpinningJob() : Blake3Parallel.ParallelJob(32, ThreadPoolHelperBudget.Shared)
	{
		public const int Threads = 8;

		private static readonly long ItemTicks = Stopwatch.Frequency / 10_000;

		protected override void ProcessItem(int index)
		{
			SpinFor(ItemTicks);
		}
	}
}
