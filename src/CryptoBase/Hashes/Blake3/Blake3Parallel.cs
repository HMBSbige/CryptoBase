using static CryptoBase.Hashes.Blake3.Blake3Constants;
using static CryptoBase.Internal.ThreadInterrupts;

namespace CryptoBase.Hashes.Blake3;

internal static unsafe class Blake3Parallel
{
	// A leaf fills every lane of the widest kernel at least twice, and is at least 16 KiB long: the parents at its top fill fewer and fewer lanes, which costs
	// the 16-lane kernel most next to the chunks of the leaf.
	private static readonly int MinLeafLength = Math.Max(16 * 1024, 2 * Blake3Tree.Degree * ChunkLength);

	// Starting a pool thread, and merging the chaining values of its leaves, takes a warm pool about as long as hashing this many bytes: p threads then
	// hash n bytes in time in proportion to n / p + p * ThreadCost, which is least for p = sqrt(n / ThreadCost).
	private const int ThreadCost = 4 * 1024;

	// About eight leaves per thread let threads that start late or run slow, such as those on efficiency cores, take fewer.
	private const int LeavesPerThread = 8;

	// The least input, or output, that threads share, a compromise: a warm pool gains from here on, but a pool whose threads sleep wakes them one after
	// another, each in about the time the calling thread takes to hash this much, so it may only gain from a few times this length.
	internal const int MinParallelLength = 128 * 1024;

	internal static bool TryCompressSubtreeToParentNode(ReadOnlySpan<byte> input, ref readonly InlineArray8<uint> key, ulong chunkCounter, uint flags, Span<byte> output, int maxDegreeOfParallelism, ThreadPoolHelperBudget budget)
	{
		return TryCompressSubtrees(input, [0, input.Length], in key, chunkCounter, flags, output, maxDegreeOfParallelism, budget);
	}

	// A head, a subtree of several chunks that ends where the input starts, is hashed by the calling thread while pool threads start, writing its children to headOutput.
	// Returns false, having hashed nothing, when no second thread would take part: the serial path then hashes faster, keeping its rows wide up to the top of the tree.
	[SkipLocalsInit]
	internal static bool TryCompressSubtrees(ReadOnlySpan<byte> input, ReadOnlySpan<int> boundaries, ref readonly InlineArray8<uint> key, ulong chunkCounter, uint flags, Span<byte> output, int maxDegreeOfParallelism, ThreadPoolHelperBudget budget, ReadOnlySpan<byte> head = default, Span<byte> headOutput = default)
	{
		int subtrees = boundaries.Length - 1;
		Debug.Assert(boundaries[0] is 0 && boundaries[subtrees] == input.Length);
		Debug.Assert(output.Length == subtrees * 2 * OutLength);

		int threads = ThreadCount(maxDegreeOfParallelism, input.Length);

		if (threads < 2)
		{
			return false;
		}

		int leafLength = LeafLength(input.Length, threads);
		Debug.Assert(input.Length > leafLength);

		Span<int> firstItems = stackalloc int[subtrees + 1];
		int items = NumberLeaves(boundaries, leafLength, firstItems);
		int rowLength = items * OutLength;
		using CryptoBuffer<byte> row = CryptoBuffer<byte>.ShouldUsePool(rowLength) ? new CryptoBuffer<byte>(rowLength) : new CryptoBuffer<byte>(stackalloc byte[rowLength]);

		fixed (byte* inputPointer = input)
		fixed (int* boundariesPointer = boundaries)
		fixed (int* firstItemsPointer = firstItems)
		fixed (InlineArray8<uint>* keyPointer = &key)
		fixed (byte* outputPointer = output)
		fixed (byte* rowPointer = row.Span)
		{
			SubtreeJob job = new(inputPointer, boundariesPointer, firstItemsPointer, subtrees, leafLength, keyPointer, chunkCounter, flags, outputPointer, rowPointer, items, budget);

			if (!job.TryStart(threads))
			{
				return false;
			}

			try
			{
				if (!head.IsEmpty)
				{
					Blake3Tree.CompressSubtreeToParentNode(head, in key, chunkCounter - (uint)head.Length / ChunkLength, flags, headOutput);
				}
			}
			finally
			{
				job.Finish();
			}
		}

		for (int i = 0; i < subtrees; ++i)
		{
			int count = firstItems[i + 1] - firstItems[i];

			if (count is not 1)
			{
				Blake3Tree.ReduceToChildren(row.Span.Slice(firstItems[i] * OutLength, count * OutLength), count, in key, flags, output.Slice(i * 2 * OutLength, 2 * OutLength));
			}
		}

		return true;
	}

	internal static void XofMany(ref readonly InlineArray8<uint> cv, ref byte block, uint blockLength, ulong counter, uint flags, Span<byte> destination, int maxDegreeOfParallelism, ThreadPoolHelperBudget budget)
	{
		Debug.Assert(destination.Length % BlockLength is 0);

		int blocks = destination.Length / BlockLength;

		if (maxDegreeOfParallelism is not 1)
		{
			int threads = ThreadCount(maxDegreeOfParallelism, destination.Length);

			if (threads > 1)
			{
				int leafBlocks = LeafLength(destination.Length, threads) / BlockLength;

				fixed (InlineArray8<uint>* chainingValuePointer = &cv)
				fixed (byte* blockPointer = &block)
				fixed (byte* destinationPointer = destination)
				{
					XofJob job = new(chainingValuePointer, blockPointer, blockLength, counter, flags, destinationPointer, blocks, leafBlocks, budget);

					if (job.TryStart(threads))
					{
						job.Finish();
						return;
					}
				}
			}
		}

		Blake3Tree.XofMany(in cv[0], ref block, blockLength, counter, flags, (uint)blocks, ref MemoryMarshal.GetReference(destination));
	}

	// Writes the first item of every subtree and, last, the item count, which it returns.
	internal static int NumberLeaves(ReadOnlySpan<int> boundaries, int leafLength, Span<int> firstItems)
	{
		int subtrees = boundaries.Length - 1;
		int items = 0;

		for (int i = 0; i < subtrees; ++i)
		{
			firstItems[i] = items;
			items += (boundaries[i + 1] - boundaries[i] - 1) / leafLength + 1;
		}

		firstItems[subtrees] = items;
		return items;
	}

	// A subtree of one leaf is hashed whole, keeping the children of its top node; any other subtree is cut into leaves of leafLength bytes from its start.
	internal static Blake3Leaf FindLeaf(ReadOnlySpan<int> boundaries, ReadOnlySpan<int> firstItems, int leafLength, int index)
	{
		int subtree = 0;

		while (index >= firstItems[subtree + 1])
		{
			++subtree;
		}

		int start = boundaries[subtree];
		int end = boundaries[subtree + 1];

		if (firstItems[subtree + 1] - firstItems[subtree] is 1)
		{
			return new Blake3Leaf(subtree, start, end - start, true);
		}

		start += (index - firstItems[subtree]) * leafLength;

		// The length is clamped rather than the end: when the input ends less than a leaf short of 2^31 bytes, a whole last leaf would end past int.MaxValue.
		return new Blake3Leaf(subtree, start, Math.Min(leafLength, end - start), false);
	}

	private static int ThreadCount(int maxDegreeOfParallelism, int length)
	{
		if (length < MinParallelLength)
		{
			return 1;
		}

		return Math.Min(ThreadPoolHelper.GetThreadLimit(maxDegreeOfParallelism), (int)Math.Sqrt((double)length / ThreadCost));
	}

	private static int LeafLength(int length, int threads)
	{
		long target = length / ((long)threads * LeavesPerThread);
		return (int)BitOperations.RoundUpToPowerOf2((uint)Math.Max(MinLeafLength, target));
	}

	private sealed class SubtreeJob : ParallelJob
	{
		private readonly byte* _input;
		private readonly int* _boundaries;
		private readonly int* _firstItems;
		private readonly int _subtrees;
		private readonly int _leafLength;
		private readonly InlineArray8<uint>* _key;
		private readonly ulong _chunkCounter;
		private readonly uint _flags;
		private readonly byte* _output;
		private readonly byte* _row;

		internal SubtreeJob(byte* input, int* boundaries, int* firstItems, int subtrees, int leafLength, InlineArray8<uint>* key, ulong chunkCounter, uint flags, byte* output, byte* row, int items, ThreadPoolHelperBudget budget) : base(items, budget)
		{
			_input = input;
			_boundaries = boundaries;
			_firstItems = firstItems;
			_subtrees = subtrees;
			_leafLength = leafLength;
			_key = key;
			_chunkCounter = chunkCounter;
			_flags = flags;
			_output = output;
			_row = row;
		}

		protected override void ProcessItem(int index)
		{
			Blake3Leaf leaf = FindLeaf(new ReadOnlySpan<int>(_boundaries, _subtrees + 1), new ReadOnlySpan<int>(_firstItems, _subtrees + 1), _leafLength, index);
			byte* destination = leaf.IsWholeSubtree ? _output + leaf.Subtree * 2 * OutLength : _row + index * OutLength;
			HashNode(leaf.Start, leaf.Length, leaf.IsWholeSubtree, destination);
		}

		[SkipLocalsInit]
		private void HashNode(int start, int length, bool keepChildren, byte* destination)
		{
			ReadOnlySpan<byte> input = new(_input + start, length);
			ref readonly InlineArray8<uint> key = ref *_key;
			ulong chunkCounter = _chunkCounter + (uint)start / ChunkLength;

			if (input.Length <= ChunkLength)
			{
				Blake3Compressor.HashChunk(ref MemoryMarshal.GetReference(input), (uint)input.Length, in key[0], chunkCounter, _flags, ref *destination);
				return;
			}

			if (keepChildren)
			{
				Blake3Tree.CompressSubtreeToParentNode(input, in key, chunkCounter, _flags, new Span<byte>(destination, 2 * OutLength));
				return;
			}

			Unsafe.SkipInit(out InlineArray64<byte> children);
			Blake3Tree.CompressSubtreeToParentNode(input, in key, chunkCounter, _flags, children);
			Blake3Compressor.Compress(in key[0], ref children[0], BlockLength, 0, _flags | Blake3Flags.Parent, ref *destination);
		}
	}

	private sealed class XofJob : ParallelJob
	{
		private readonly InlineArray8<uint>* _chainingValue;
		private readonly byte* _block;
		private readonly uint _blockLength;
		private readonly ulong _counter;
		private readonly uint _flags;
		private readonly byte* _destination;
		private readonly int _blocks;
		private readonly int _leafBlocks;

		internal XofJob(InlineArray8<uint>* cv, byte* block, uint blockLength, ulong counter, uint flags, byte* destination, int blocks, int leafBlocks, ThreadPoolHelperBudget budget) : base((blocks + leafBlocks - 1) / leafBlocks, budget)
		{
			_chainingValue = cv;
			_block = block;
			_blockLength = blockLength;
			_counter = counter;
			_flags = flags;
			_destination = destination;
			_blocks = blocks;
			_leafBlocks = leafBlocks;
		}

		protected override void ProcessItem(int index)
		{
			int first = index * _leafBlocks;
			int count = Math.Min(_leafBlocks, _blocks - first);
			Blake3Tree.XofMany(in (*_chainingValue)[0], ref *_block, _blockLength, _counter + (uint)first, _flags, (uint)count, ref _destination[first * BlockLength]);
		}
	}

	// Items must not throw on a pool thread, which would take the process down.
	// Jobs point at the memory that the caller keeps, keys and root blocks included, rather than copying it: a job stays queued after Finish until every pool
	// thread has taken it, and nothing erases a copy on the heap, which the garbage collector may also have moved.
	// Once no item is pending, threads only touch the job itself, and may still be waking the calling thread after Finish has returned, so a job serves once.
	internal abstract class ParallelJob(int itemCount, ThreadPoolHelperBudget budget) : ThreadPoolHelper(budget)
	{
		// The calling thread spins and yields, never sleeping for the timer tick that Thread.Sleep(1) may take, for about 500 µs before it blocks: long enough
		// to cover the last leaves of all but the longest input, whose hashing takes far longer than waking up, and short enough to bound how long it holds a
		// processor that a helper it waits for may need.
		private static readonly long SpinTicks = Stopwatch.Frequency / 2000;

		private readonly int _itemCount = itemCount;
		private int _nextItem;
		private int _pendingItems = itemCount;
		private int _callerBlocked;

		protected abstract void ProcessItem(int index);

		// Returns false, having queued nothing, when the budget grants no helper: the calling thread does better on its serial path than taking every item alone.
		// Should queuing a helper fail for lack of memory, those queued before take items all the same, so every item is finished before it throws.
		// Finish has to follow true.
		internal bool TryStart(int threads)
		{
			try
			{
				return QueueHelpers(Math.Min(threads, _itemCount) - 1) is not 0;
			}
			catch
			{
				Finish();
				throw;
			}
		}

		// Pool threads may still be hashing items that read and write memory the caller releases once Finish returns, so neither an interrupt, a failure to
		// block, nor an item that throws on the calling thread cuts the wait short.
		internal void Finish()
		{
			try
			{
				ProcessItems();
			}
			catch
			{
				Abandon();
				WaitForPendingItems();
				throw;
			}

			WaitForPendingItems();
		}

		// Takes the item that threw and those that no thread has claimed off the pending count, leaving the items that helpers hold.
		private void Abandon()
		{
			int claimed = Interlocked.Exchange(ref _nextItem, _itemCount);
			Interlocked.Add(ref _pendingItems, -1 - Math.Max(_itemCount - claimed, 0));
		}

		private void WaitForPendingItems()
		{
			if (Volatile.Read(ref _pendingItems) is 0)
			{
				return;
			}

			bool interrupted = false;

			try
			{
				WaitForHelpers(ref interrupted);
			}
			finally
			{
				SpinUntilZero(ref _pendingItems);
				RestoreInterrupt(interrupted);
			}
		}

		internal override void Help()
		{
			ProcessItems();
		}

		// Spinning and yielding keep the processor of the calling thread busy, so a helper that a thread of higher priority preempted
		// elsewhere cannot move to it; once the spin runs out, blocking frees the processor. On an STA thread, blocking pumps COM and
		// SendMessage messages, as the waits of Argon2LaneScheduler do.
		private void WaitForHelpers(ref bool interrupted)
		{
			long spinDeadline = Stopwatch.GetTimestamp() + SpinTicks;
			SpinWait spinner = default;

			while (Volatile.Read(ref _pendingItems) is not 0)
			{
				if (Stopwatch.GetTimestamp() < spinDeadline)
				{
					try
					{
						spinner.SpinOnce(sleep1Threshold: -1);
					}
					catch (ThreadInterruptedException)
					{
						interrupted = true;
					}

					continue;
				}

				// Flagging the calling thread as blocked is a full fence that pairs with the one decrementing the last pending item: either the helper sees the
				// flag, or the calling thread sees no item pending.
				Uninterruptibly
				(
					static job =>
					{
						lock (job)
						{
							Interlocked.Exchange(ref job._callerBlocked, 1);

							while (Volatile.Read(ref job._pendingItems) is not 0)
							{
								Monitor.Wait(job);
							}
						}
					}, this, ref interrupted
				);
			}
		}

		private void ProcessItems()
		{
			int index;

			while ((index = Interlocked.Increment(ref _nextItem) - 1) < _itemCount)
			{
				ProcessItem(index);

				if (Interlocked.Decrement(ref _pendingItems) is 0 && Volatile.Read(ref _callerBlocked) is not 0)
				{
					WakeCaller();
				}
			}
		}

		// A pool thread may carry an interrupt meant for other work, and an exception escaping a work item ends the process, so waking the calling thread retries
		// after an interrupt, which is raised again afterwards.
		private void WakeCaller()
		{
			bool interrupted = false;
			Uninterruptibly
			(
				static job =>
				{
					lock (job)
					{
						Monitor.Pulse(job);
					}
				}, this, ref interrupted
			);
			RestoreInterrupt(interrupted);
		}
	}
}
