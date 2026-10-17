using static CryptoBase.Hashes.Blake3.Blake3Constants;

namespace CryptoBase.Hashes.Blake3;

internal struct Blake3State
{
	// Input shorter than 2^31 bytes spans fewer than 2^21 chunks, so it splits into at most 21 subtrees that grow until the chunk counter is aligned to the rest,
	// then at most 21 that shrink to fit it.
	private const int MaxSubtrees = 42;

	// A group is a node of 2^GroupDepth chunks, which fills every lane of the widest kernel.
	private const int GroupDepth = 4;
	internal const int GroupLength = ChunkLength << GroupDepth;

	internal const int MaxStackLength = (MaxDepth + 1) * OutLength;

	private InlineArray8<uint> _key;
	private uint _flags;

	private int _stackDepth;

	private ulong _chunkCounter;

	private int _capacity;

	// The chaining value after the blocks of the buffered chunk that chunk mode has compressed as they filled, so that reads that keep following appends
	// compress each block once.
	private InlineArray8<uint> _chunkChainingValue;
	private int _compressedBlocks;

	private bool _usedChunkChainingValue;

	private int _usedBufferLength;

	internal int BufferLength { readonly get; private set; }

	internal readonly int StackLength => _stackDepth * OutLength;

	internal readonly bool IsSecret => Blake3Flags.IsSecret(_flags);

	internal readonly ulong InputLength => _chunkCounter * ChunkLength + (uint)BufferLength;

	internal readonly int UsedBufferLength => Math.Max(_usedBufferLength, BufferLength);
	internal int UsedStackLength { readonly get; private set; }

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal void Initialize(ref readonly InlineArray8<uint> key, uint flags)
	{
		_key = key;
		_flags = flags;
		Reset();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal void Reset()
	{
		_usedBufferLength = UsedBufferLength;
		_stackDepth = 0;
		_chunkCounter = 0;
		_capacity = GroupLength;
		_compressedBlocks = 0;
		BufferLength = 0;
	}

	// Erasing skips what the input has left untouched, as short input does the stack, since every erasure costs a call.
	internal void EraseAndReset(Span<byte> buffer, Span<byte> stack)
	{
		int usedBufferLength = UsedBufferLength;
		int usedStackLength = UsedStackLength;

		if (usedBufferLength is not 0)
		{
			buffer.Slice(0, usedBufferLength).ZeroMemory();
		}

		if (usedStackLength is not 0)
		{
			stack.Slice(0, usedStackLength).ZeroMemory();
		}

		if (_usedChunkChainingValue)
		{
			_chunkChainingValue.ZeroMemory();
		}

		_usedChunkChainingValue = false;
		_usedBufferLength = 0;
		BufferLength = 0;
		UsedStackLength = 0;
		Reset();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal bool TryBuffer(ReadOnlySpan<byte> source, Span<byte> buffer)
	{
		int bufferLength = BufferLength;

		if (source.Length >= Math.Min(_capacity, buffer.Length) - bufferLength)
		{
			return false;
		}

		source.CopyTo(buffer.Slice(bufferLength));
		BufferLength = bufferLength + source.Length;
		return true;
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	internal void Append(ReadOnlySpan<byte> source, int maxDegreeOfParallelism, ThreadPoolHelperBudget budget, Span<byte> buffer, Span<byte> stack)
	{
		int bufferLength = BufferLength;
		scoped ReadOnlySpan<byte> head = default;

		if (bufferLength is not 0)
		{
			int capacity = Math.Min(_capacity, buffer.Length);
			Debug.Assert(bufferLength <= capacity);

			int take = Math.Min(capacity - bufferLength, source.Length);
			source.Slice(0, take).CopyTo(buffer.Slice(bufferLength));
			source = source.Slice(take);
			bufferLength += take;

			if (source.IsEmpty && (bufferLength < capacity || capacity is ChunkLength))
			{
				BufferLength = bufferLength;
				return;
			}

			head = buffer.Slice(0, capacity);
			_usedBufferLength = Math.Max(_usedBufferLength, capacity);
		}

		ulong bodyCounter = _chunkCounter + (uint)head.Length / ChunkLength;
		int nodeLength = Math.Min(NodeLength(bodyCounter), buffer.Length);
		int bodyLength = (bodyCounter is 0 && source.Length is ChunkLength ? 0 : source.Length) / nodeLength * nodeLength;
		ReadOnlySpan<byte> body = source.Slice(0, bodyLength);
		source = source.Slice(bodyLength);

		// Hashing in parallel is the one step that may throw, for lack of memory, so the head stays buffered until it is pushed, and a failure leaves the input
		// as it was.
		if (maxDegreeOfParallelism is not 1 && body.Length >= Blake3Parallel.MinParallelLength && AppendSubtreesInParallel(head, body, maxDegreeOfParallelism, budget, stack))
		{
			head = default;
			body = default;
		}

		if (!head.IsEmpty)
		{
			PushSubtree(head, stack);
		}

		PushSubtrees(body, stack);
		BufferLength = source.Length;

		if (!source.IsEmpty)
		{
			source.CopyTo(buffer);
			MergeStack(_chunkCounter, stack);
		}

		UpdateCapacity();
	}

	internal void AppendToChunk(ReadOnlySpan<byte> source, int maxDegreeOfParallelism, ThreadPoolHelperBudget budget, Span<byte> buffer, Span<byte> stack)
	{
		buffer = buffer.Slice(0, ChunkLength);
		Append(source, maxDegreeOfParallelism, budget, buffer, stack);
		CompressBufferedBlocks(buffer);
	}

	internal bool TryAppendToChunk(ReadOnlySpan<byte> source, Span<byte> buffer)
	{
		int bufferLength = BufferLength;
		Debug.Assert(_capacity is 0 == (bufferLength is 0 && _stackDepth is not 0));

		if (source.Length >= ChunkLength - bufferLength || _capacity is 0)
		{
			return false;
		}

		source.CopyTo(buffer.Slice(bufferLength));
		BufferLength = bufferLength + source.Length;
		CompressBufferedBlocks(buffer);
		return true;
	}

	internal void ShrinkBuffer(Span<byte> buffer, Span<byte> stack)
	{
		int bufferLength = BufferLength;
		Debug.Assert(bufferLength > ChunkLength);

		int hashedLength = bufferLength & ~(ChunkLength - 1);
		PushSubtrees(buffer.Slice(0, hashedLength), stack);
		buffer.Slice(hashedLength, bufferLength - hashedLength).CopyTo(buffer);
		_usedBufferLength = Math.Max(_usedBufferLength, bufferLength);
		BufferLength = bufferLength - hashedLength;

		// An empty buffer leaves the children of the root on the stack, as Append does: should the append that shrinks the buffer fail, the input ends here.
		if (BufferLength is not 0)
		{
			MergeStack(_chunkCounter, stack);
		}

		UpdateCapacity();
	}

	private void CompressBufferedBlocks(ReadOnlySpan<byte> buffer)
	{
		Debug.Assert(BufferLength <= ChunkLength);

		int blocks = (BufferLength - 1) / BlockLength;
		int compressedBlocks = _compressedBlocks;

		if (blocks <= compressedBlocks)
		{
			return;
		}

		uint startFlag = 0;

		if (compressedBlocks is 0)
		{
			_chunkChainingValue = _key;
			_usedChunkChainingValue = true;
			startFlag = Blake3Flags.ChunkStart;
		}

		Blake3Compressor.CompressBlocks(ref _chunkChainingValue[0], ref MemoryMarshal.GetReference(buffer.Slice(compressedBlocks * BlockLength)), (uint)(blocks - compressedBlocks), _chunkCounter, _flags, startFlag, 0);
		_compressedBlocks = blocks;
	}

	private void PushSubtrees(ReadOnlySpan<byte> chunks, Span<byte> stack)
	{
		while (!chunks.IsEmpty)
		{
			int subtreeLength = SubtreeLength(_chunkCounter, chunks.Length);
			PushSubtree(chunks.Slice(0, subtreeLength), stack);
			chunks = chunks.Slice(subtreeLength);
		}
	}

	[SkipLocalsInit]
	private void PushSubtree(ReadOnlySpan<byte> subtree, Span<byte> stack)
	{
		Unsafe.SkipInit(out InlineArray64<byte> buffer);
		Span<byte> chainingValues = buffer;
		ulong chunkCounter = _chunkCounter;

		if (subtree.Length is ChunkLength)
		{
			int compressedBlocks = _compressedBlocks;

			if (compressedBlocks is 0)
			{
				Blake3Compressor.HashChunk(ref MemoryMarshal.GetReference(subtree), ChunkLength, in _key[0], chunkCounter, _flags, ref chainingValues[0]);
			}
			else
			{
				Blake3Compressor.CompressBlocks(ref _chunkChainingValue[0], ref MemoryMarshal.GetReference(subtree.Slice(compressedBlocks * BlockLength)), (uint)(ChunkBlocks - compressedBlocks), chunkCounter, _flags, 0, Blake3Flags.ChunkEnd);
				Blake3Words.Store(ref chainingValues[0], in _chunkChainingValue);
			}
		}
		else
		{
			Blake3Tree.CompressSubtreeToParentNode(subtree, in _key, chunkCounter, _flags, chainingValues);
		}

		PushNode(chainingValues, chunkCounter, subtree.Length, stack);
		_chunkCounter = chunkCounter + (uint)subtree.Length / ChunkLength;
		_compressedBlocks = 0;
	}

	// The calling thread hashes a head of several chunks while pool threads start on the body. A head of one chunk, which has no top node to keep and may go on
	// from blocks that chunk mode compressed, is pushed once the body is hashed instead, since the state must not change before hashing has succeeded.
	[SkipLocalsInit]
	private bool AppendSubtreesInParallel(ReadOnlySpan<byte> head, ReadOnlySpan<byte> source, int maxDegreeOfParallelism, ThreadPoolHelperBudget budget, Span<byte> stack)
	{
		Unsafe.SkipInit(out InlineArray64<byte> headChildren);
		ulong headCounter = _chunkCounter;
		ulong chunkCounter = headCounter + (uint)head.Length / ChunkLength;
		Span<int> boundaries = stackalloc int[MaxSubtrees + 1];
		int subtrees = 0;
		int end = 0;
		boundaries[0] = 0;

		while (end < source.Length)
		{
			end += SubtreeLength(chunkCounter + (uint)end / ChunkLength, source.Length - end);
			boundaries[++subtrees] = end;
		}

		Span<byte> chainingValues = stackalloc byte[subtrees * 2 * OutLength];

		if (!Blake3Parallel.TryCompressSubtrees(source, boundaries.Slice(0, subtrees + 1), in _key, chunkCounter, _flags, chainingValues, maxDegreeOfParallelism, budget, head.Length is ChunkLength ? default : head, headChildren))
		{
			return false;
		}

		if (head.Length is ChunkLength)
		{
			PushSubtree(head, stack);
		}
		else if (!head.IsEmpty)
		{
			PushNode(headChildren, headCounter, head.Length, stack);
		}

		for (int i = 0; i < subtrees; ++i)
		{
			int start = boundaries[i];
			ulong subtreeCounter = chunkCounter + (uint)start / ChunkLength;
			PushNode(chainingValues.Slice(i * 2 * OutLength, 2 * OutLength), subtreeCounter, boundaries[i + 1] - start, stack);
		}

		_chunkCounter = chunkCounter + (uint)end / ChunkLength;
		_compressedBlocks = 0;
		return true;
	}

	private void UpdateCapacity()
	{
		_capacity = BufferLength is 0 && _stackDepth is not 0 ? 0 : NodeLength(_chunkCounter);
	}

	private static int NodeLength(ulong chunkCounter)
	{
		return ChunkLength << Math.Min(BitOperations.TrailingZeroCount(chunkCounter), GroupDepth);
	}

	private static int SubtreeLength(ulong chunkCounter, int length)
	{
		ulong chunks = (ulong)(1 << BitOperations.Log2((uint)length)) / ChunkLength;

		if (chunkCounter is not 0)
		{
			chunks = Math.Min(chunks, chunkCounter & 0 - chunkCounter);
		}

		return (int)chunks * ChunkLength;
	}

	private void MergeStack(ulong chunks, Span<byte> stack)
	{
		int mergedDepth = BitOperations.PopCount(chunks);

		while (_stackDepth > mergedDepth)
		{
			ref byte parent = ref stack[(_stackDepth - 2) * OutLength];
			Blake3Compressor.Compress(in _key[0], ref parent, BlockLength, 0, _flags | Blake3Flags.Parent, ref parent);
			--_stackDepth;
		}
	}

	private void PushNode(ReadOnlySpan<byte> chainingValues, ulong chunkCounter, int length, Span<byte> stack)
	{
		PushChainingValue(chainingValues.Slice(0, OutLength), chunkCounter, stack);

		if (length > ChunkLength)
		{
			PushChainingValue(chainingValues.Slice(OutLength, OutLength), chunkCounter + (uint)length / (2 * ChunkLength), stack);
		}
	}

	private void PushChainingValue(ReadOnlySpan<byte> chainingValue, ulong chunkCounter, Span<byte> stack)
	{
		MergeStack(chunkCounter, stack);
		chainingValue.CopyTo(stack.Slice(StackLength));
		++_stackDepth;
		UsedStackLength = Math.Max(UsedStackLength, StackLength);
	}

	[SkipLocalsInit]
	internal readonly void CreateOutput(ReadOnlySpan<byte> buffer, ReadOnlySpan<byte> stack, out Blake3Output output)
	{
		ReadOnlySpan<byte> buffered = buffer.Slice(0, BufferLength);
		int remaining = _stackDepth;

		if (buffered.Length > ChunkLength)
		{
			Unsafe.SkipInit(out InlineArray64<byte> children);
			Blake3Tree.CompressSubtreeToParentNode(buffered, in _key, _chunkCounter, _flags, children);
			Blake3Output.FromParent(children, in _key, _flags, out output);

			if (IsSecret)
			{
				children.ZeroMemory();
			}
		}
		else if (_compressedBlocks is not 0)
		{
			Blake3Output.FromChunk(buffered.Slice(_compressedBlocks * BlockLength), in _chunkChainingValue, 0, _chunkCounter, _flags, out output);
		}
		else if (!buffered.IsEmpty || remaining is 0)
		{
			Blake3Output.FromChunk(buffered, in _key, _chunkCounter, _flags, out output);
		}
		else
		{
			remaining -= 2;
			Blake3Output.FromParent(stack.Slice(remaining * OutLength, 2 * OutLength), in _key, _flags, out output);
		}

		while (remaining is not 0)
		{
			--remaining;
			output.BecomeParent(stack.Slice(remaining * OutLength, OutLength), in _key, _flags);
		}
	}
}
