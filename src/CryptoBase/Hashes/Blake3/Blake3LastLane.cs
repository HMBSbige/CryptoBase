using static CryptoBase.Hashes.Blake3.Blake3Constants;

namespace CryptoBase.Hashes.Blake3;

// The blocks that the row kernels read for their last input, which may be a partial chunk. Its lane then joins late, so that it ends with the full chunks,
// and reads its last block from a zero-padded copy, which keeps every load inside the input; before it joins, it reads the chunk before it, whose result
// the key then replaces.
internal ref struct Blake3LastLane
{
	private ref byte _block;
	private readonly ref byte _lastBlock;

	// Zero when the last input is a whole chunk, whose lane runs with the others from the start.
	internal readonly nuint TailBlocks;

	internal readonly uint LastLength;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal Blake3LastLane(ref byte input, nuint blockCount, nuint tailLength, ref InlineArray64<byte> buffer)
	{
		if (tailLength is 0)
		{
			_block = ref input;
			_lastBlock = ref Unsafe.Add(ref input, (blockCount - 1) * BlockLength);
			return;
		}

		TailBlocks = (tailLength - 1) / BlockLength + 1;
		nuint lastBlockOffset = (TailBlocks - 1) * BlockLength;
		LastLength = (uint)(tailLength - lastBlockOffset);

		Span<byte> lastBlock = buffer;
		MemoryMarshal.CreateReadOnlySpan(ref Unsafe.Add(ref input, lastBlockOffset), (int)LastLength).CopyTo(lastBlock);
		lastBlock.Slice((int)LastLength).Clear();

		_block = ref Unsafe.Subtract(ref input, (blockCount - TailBlocks) * BlockLength);
		_lastBlock = ref buffer[0];
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal ref byte Next(nuint blockCount)
	{
		ref byte block = ref blockCount is 1 ? ref _lastBlock : ref _block;
		_block = ref Unsafe.Add(ref _block, BlockLength);
		return ref block;
	}
}
