using static CryptoBase.Hashes.Blake3.Blake3Constants;

namespace CryptoBase.Hashes.Blake3;

internal struct Blake3Output
{
	internal InlineArray8<uint> InputChainingValue;
	internal InlineArray64<byte> Block;
	internal ulong Counter;
	internal uint UsedBlockLength;
	internal uint Flags;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void FromChunk(ReadOnlySpan<byte> chunk, ref readonly InlineArray8<uint> key, ulong chunkCounter, uint flags, out Blake3Output output)
	{
		FromChunk(chunk, in key, Blake3Flags.ChunkStart, chunkCounter, flags, out output);
	}

	[SkipLocalsInit]
	internal static void FromChunk(ReadOnlySpan<byte> blocks, ref readonly InlineArray8<uint> cv, uint startFlag, ulong chunkCounter, uint flags, out Blake3Output output)
	{
		Debug.Assert(blocks.Length <= ChunkLength);

		Unsafe.SkipInit(out output);
		output.InputChainingValue = cv;
		int lastBlockOffset = blocks.Length - 1 & ~(BlockLength - 1);

		if (lastBlockOffset > 0)
		{
			Blake3Compressor.CompressBlocks(ref output.InputChainingValue[0], ref MemoryMarshal.GetReference(blocks), (uint)lastBlockOffset / BlockLength, chunkCounter, flags, startFlag, 0);
			startFlag = 0;
			blocks = blocks.Slice(lastBlockOffset);
		}

		Span<byte> block = output.Block;
		blocks.CopyTo(block);
		block.Slice(blocks.Length).Clear();
		output.UsedBlockLength = (uint)blocks.Length;
		output.Counter = chunkCounter;
		output.Flags = flags | startFlag | Blake3Flags.ChunkEnd;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void FromParent(ReadOnlySpan<byte> block, ref readonly InlineArray8<uint> key, uint flags, out Blake3Output output)
	{
		Debug.Assert(block.Length is BlockLength);

		Unsafe.SkipInit(out output);
		output.InputChainingValue = key;
		block.CopyTo(output.Block);
		output.Counter = 0;
		output.UsedBlockLength = BlockLength;
		output.Flags = flags | Blake3Flags.Parent;
	}

	// The destination may overlap the block, because the compressors read the whole block before writing.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal readonly void ChainingValue(ref byte destination)
	{
		Blake3Compressor.Compress(in InputChainingValue[0], ref Unsafe.AsRef(in Block[0]), UsedBlockLength, Counter, Flags, ref destination);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal void BecomeParent(ReadOnlySpan<byte> leftChainingValue, ref readonly InlineArray8<uint> key, uint flags)
	{
		Debug.Assert(leftChainingValue.Length is OutLength);

		Span<byte> block = Block;
		ChainingValue(ref block[OutLength]);
		leftChainingValue.CopyTo(block);
		InputChainingValue = key;
		Counter = 0;
		UsedBlockLength = BlockLength;
		Flags = flags | Blake3Flags.Parent;
	}

	[SkipLocalsInit]
	internal readonly void RootBytes(ulong position, Span<byte> destination, int maxDegreeOfParallelism, ThreadPoolHelperBudget budget)
	{
		uint flags = Flags | Blake3Flags.Root;
		ref byte block = ref Unsafe.AsRef(in Block[0]);

		if (position is 0 && destination.Length is OutLength)
		{
			Blake3Compressor.Compress(in InputChainingValue[0], ref block, UsedBlockLength, 0, flags, ref MemoryMarshal.GetReference(destination));
			return;
		}

		ulong counter = position / BlockLength;
		int offset = (int)(position % BlockLength);
		Unsafe.SkipInit(out InlineArray64<byte> buffer);
		Span<byte> outputBlock = buffer;

		if (offset is not 0 && !destination.IsEmpty)
		{
			Blake3Compressor.CompressXof(in InputChainingValue[0], ref block, UsedBlockLength, counter, flags, ref outputBlock[0]);
			int length = Math.Min(BlockLength - offset, destination.Length);
			outputBlock.Slice(offset, length).CopyTo(destination);
			destination = destination.Slice(length);
			++counter;
		}

		int fullBlocksLength = destination.Length & ~(BlockLength - 1);

		if (fullBlocksLength is not 0)
		{
			Blake3Parallel.XofMany(in InputChainingValue, ref block, UsedBlockLength, counter, flags, destination.Slice(0, fullBlocksLength), maxDegreeOfParallelism, budget);
			counter += (uint)fullBlocksLength / BlockLength;
			destination = destination.Slice(fullBlocksLength);
		}

		if (!destination.IsEmpty)
		{
			Blake3Compressor.CompressXof(in InputChainingValue[0], ref block, UsedBlockLength, counter, flags, ref outputBlock[0]);
			outputBlock.Slice(0, destination.Length).CopyTo(destination);
		}
	}
}
