namespace CryptoBase.Ciphers.Modes.Gcm;

internal static partial class GHashX86
{
	internal const int BlockSize = GHash.BlockSizeInBytes;
	private const int FourBlockThreshold = 7 * BlockSize;
	private const int Vector128Threshold = 16 * BlockSize;
	private const int Vector256Threshold = 32 * BlockSize;
	private const int Vector512ParallelBlockSize = 64 * BlockSize;
	internal const int Vector512Threshold = 128 * BlockSize;

	internal static bool IsSupported
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => Sse2.IsSupported && Pclmulqdq.IsSupported;
	}

	internal static bool IsSupported256
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => Avx2.IsSupported && Pclmulqdq.V256.IsSupported;
	}

	internal static bool IsSupported512
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => Vector512.IsHardwareAccelerated && X86Base.X64.IsSupported && IsSupported256 && Avx512BW.IsSupported && Pclmulqdq.V512.IsSupported;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static bool ShouldUseVector512(long firstPaddedLength, long secondPaddedLength, long thirdPaddedLength)
	{
		long parallelLength = (firstPaddedLength & -Vector512ParallelBlockSize) + (secondPaddedLength & -Vector512ParallelBlockSize) + (thirdPaddedLength & -Vector512ParallelBlockSize);
		return IsSupported512 && parallelLength >= Vector512Threshold;
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static void AppendPaddedSegments(ref Vector128<byte> accumulator, ref GHashKey key, scoped ReadOnlySpan<byte> first, scoped ReadOnlySpan<byte> second, scoped ReadOnlySpan<byte> third)
	{
		Debug.Assert(IsSupported);

		long firstPaddedLength = GHash.GetPaddedLength(first.Length);
		long secondPaddedLength = GHash.GetPaddedLength(second.Length);
		long thirdPaddedLength = GHash.GetPaddedLength(third.Length);
		long totalPaddedLength = firstPaddedLength + secondPaddedLength + thirdPaddedLength;

		if (ShouldUseVector512(firstPaddedLength, secondPaddedLength, thirdPaddedLength))
		{
			AppendPaddedSegments(ref accumulator, ref key.GetVector512().Value, first, second, third);
			return;
		}

		if (IsSupported256 && totalPaddedLength >= Vector256Threshold)
		{
			AppendPaddedSegments(ref accumulator, ref key.GetVector256().Value, first, second, third);
			return;
		}

		if (totalPaddedLength >= Vector128Threshold)
		{
			AppendPaddedSegments(ref accumulator, ref key.GetVector128().Value, first, second, third);
			return;
		}

		if (totalPaddedLength >= FourBlockThreshold)
		{
			AppendPaddedSegments(ref accumulator, ref key.GetFourBlock().Value, first, second, third);
			return;
		}

		Vector128<byte> internalKey = key.Value.ReverseEndianness128();
		Vector128<byte> internalAccumulator = accumulator.ReverseEndianness128();

		AppendPaddedSegmentSequential(ref internalAccumulator, in internalKey, first);
		AppendPaddedSegmentSequential(ref internalAccumulator, in internalKey, second);
		AppendPaddedSegmentSequential(ref internalAccumulator, in internalKey, third);
		accumulator = internalAccumulator.ReverseEndianness128();
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static void AppendPaddedSegments<T>(ref Vector128<byte> accumulator, ref T powers, scoped ReadOnlySpan<byte> first, scoped ReadOnlySpan<byte> second, scoped ReadOnlySpan<byte> third) where T : struct, IGHashPowers
	{
		Vector128<byte> internalAccumulator = accumulator.ReverseEndianness128();
		Unsafe.SkipInit(out Vector128<byte> finalBlock);

		try
		{
			powers.AppendPaddedSegment(ref internalAccumulator, first, ref finalBlock);
			powers.AppendPaddedSegment(ref internalAccumulator, second, ref finalBlock);
			powers.AppendPaddedSegment(ref internalAccumulator, third, ref finalBlock);
			accumulator = internalAccumulator.ReverseEndianness128();
		}
		finally
		{
			internalAccumulator.ZeroMemory();
			finalBlock.ZeroMemory();
		}
	}

	internal static void AppendPaddedSegmentFolded<T>(ref T powers, ref Vector128<byte> accumulator, scoped ReadOnlySpan<byte> source, ref Vector128<byte> finalBlock) where T : struct, IGHashFoldedPowers
	{
		int completeLength = source.Length & -BlockSize;
		ReadOnlySpan<byte> remaining = source.Slice(completeLength);

		if (remaining.IsEmpty)
		{
			if (completeLength is not 0)
			{
				powers.AppendBlocks(ref accumulator, source);
			}

			return;
		}

		finalBlock = GHash.PadFinalBlock(remaining);

		int batchOffset = completeLength & (T.BatchBlocks - 1) * BlockSize;
		int tailBlocks = batchOffset == (T.BatchBlocks / 2 - 1) * BlockSize ? T.BatchBlocks / 2 : batchOffset == (T.BatchBlocks - 1) * BlockSize ? T.BatchBlocks : 0;

		if (tailBlocks is not 0)
		{
			int prefixLength = completeLength - (tailBlocks - 1) * BlockSize;
			powers.AppendBlocks(ref accumulator, source.Slice(0, prefixLength));
			powers.AppendFoldedTail(ref accumulator, source.Slice(prefixLength, (tailBlocks - 1) * BlockSize), ref finalBlock, tailBlocks);
			return;
		}

		if (completeLength is not 0)
		{
			powers.AppendBlocks(ref accumulator, source.Slice(0, completeLength));
		}

		powers.AppendBlocks(ref accumulator, finalBlock.AsReadOnlySpan());
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void AppendSequential(ref Vector128<byte> accumulator, in Vector128<byte> key, scoped ReadOnlySpan<byte> source)
	{
		if (source.Length is BlockSize)
		{
			Vector128<byte> block = Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(source)).ReverseEndianness128();
			accumulator = GFMultiply(key, block ^ accumulator);
			return;
		}

		Vector128<byte> localAccumulator = accumulator;
		Vector128<byte> localKey = key;

		ref byte input = ref MemoryMarshal.GetReference(source);

		for (int remaining = source.Length; remaining > 0; remaining -= BlockSize)
		{
			Vector128<byte> block = Vector128.LoadUnsafe(ref input).ReverseEndianness128();
			localAccumulator = GFMultiply(localKey, block ^ localAccumulator);
			input = ref Unsafe.Add(ref input, BlockSize);
		}

		accumulator = localAccumulator;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void AppendPaddedSegmentSequential(ref Vector128<byte> accumulator, in Vector128<byte> key, scoped ReadOnlySpan<byte> source)
	{
		int completeLength = source.Length & -BlockSize;

		if (completeLength is not 0)
		{
			AppendSequential(ref accumulator, in key, source.Slice(0, completeLength));
		}

		ReadOnlySpan<byte> remaining = source.Slice(completeLength);

		if (remaining.IsEmpty)
		{
			return;
		}

		accumulator = GFMultiply(key, GHash.PadFinalBlock(remaining).ReverseEndianness128() ^ accumulator);
	}
}
