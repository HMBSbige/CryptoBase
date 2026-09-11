namespace CryptoBase.SymmetricCryptos.BlockCryptoModes.Gcm;

internal static partial class GHashX86
{
	internal const int BlockSize = GHash.BlockSizeInBytes;
	private const int FourBlockThreshold = 7 * BlockSize;
	private const int Vector128Threshold = 16 * BlockSize;
	private const int Vector256Threshold = 32 * BlockSize;
	private const int Vector512ParallelBlockSize = 64 * BlockSize;
	private const int Vector512Threshold = 128 * BlockSize;

	internal static bool IsSupported => Sse2.IsSupported && Pclmulqdq.IsSupported;

	internal static bool IsSupported256 => Avx2.IsSupported && Pclmulqdq.V256.IsSupported;

	private static bool IsSupported512 => X86Base.X64.IsSupported && IsSupported256 && Avx512BW.IsSupported && Pclmulqdq.V512.IsSupported;

	[SkipLocalsInit]
	internal static void AppendPaddedSegments(ref VectorBuffer16 accumulator, in VectorBuffer16 key, scoped ReadOnlySpan<byte> first, scoped ReadOnlySpan<byte> second, scoped ReadOnlySpan<byte> third)
	{
		Debug.Assert(IsSupported);

		long firstPaddedLength = GHash.GetPaddedLength(first.Length);
		long secondPaddedLength = GHash.GetPaddedLength(second.Length);
		long thirdPaddedLength = GHash.GetPaddedLength(third.Length);
		long totalPaddedLength = firstPaddedLength + secondPaddedLength + thirdPaddedLength;
		long vector512ParallelLength = (firstPaddedLength & -Vector512ParallelBlockSize) + (secondPaddedLength & -Vector512ParallelBlockSize) + (thirdPaddedLength & -Vector512ParallelBlockSize);

		if (IsSupported512 && vector512ParallelLength >= Vector512Threshold)
		{
			AppendPaddedSegmentsVector512(ref accumulator, in key, first, second, third);
			return;
		}

		if (IsSupported256 && totalPaddedLength >= Vector256Threshold)
		{
			AppendPaddedSegmentsVector256(ref accumulator, in key, first, second, third);
			return;
		}

		if (totalPaddedLength >= Vector128Threshold)
		{
			AppendPaddedSegmentsVector128(ref accumulator, in key, first, second, third);
			return;
		}

		if (totalPaddedLength >= FourBlockThreshold)
		{
			AppendPaddedSegmentsFourBlock(ref accumulator, in key, first, second, third);
			return;
		}

		Vector128<byte> internalKey = key.V128.ReverseEndianness128();
		Vector128<byte> internalAccumulator = accumulator.V128.ReverseEndianness128();
		Unsafe.SkipInit(out VectorBuffer16 finalBlock);

		try
		{
			AppendPaddedSegmentSequential(ref internalAccumulator, in internalKey, first, ref finalBlock);
			AppendPaddedSegmentSequential(ref internalAccumulator, in internalKey, second, ref finalBlock);
			AppendPaddedSegmentSequential(ref internalAccumulator, in internalKey, third, ref finalBlock);
			accumulator.V128 = internalAccumulator.ReverseEndianness128();
		}
		finally
		{
			finalBlock.ZeroMemory();
		}
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void AppendPaddedSegmentsVector128(ref VectorBuffer16 accumulator, in VectorBuffer16 key, scoped ReadOnlySpan<byte> first, scoped ReadOnlySpan<byte> second, scoped ReadOnlySpan<byte> third)
	{
		GHashVector128State state = new(key.V128.ReverseEndianness128(), accumulator.V128.ReverseEndianness128());
		Unsafe.SkipInit(out VectorBuffer16 finalBlock);

		try
		{
			state.AppendPaddedSegment(first, ref finalBlock);
			state.AppendPaddedSegment(second, ref finalBlock);
			state.AppendPaddedSegment(third, ref finalBlock);
			accumulator.V128 = state.GetAccumulator().ReverseEndianness128();
		}
		finally
		{
			state.ZeroMemory();
			finalBlock.ZeroMemory();
		}
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void AppendPaddedSegmentsFourBlock(ref VectorBuffer16 accumulator, in VectorBuffer16 key, scoped ReadOnlySpan<byte> first, scoped ReadOnlySpan<byte> second, scoped ReadOnlySpan<byte> third)
	{
		GHashFourBlockState state = new(key.V128.ReverseEndianness128(), accumulator.V128.ReverseEndianness128());
		Unsafe.SkipInit(out VectorBuffer16 finalBlock);

		try
		{
			state.AppendPaddedSegment(first, ref finalBlock);
			state.AppendPaddedSegment(second, ref finalBlock);
			state.AppendPaddedSegment(third, ref finalBlock);
			accumulator.V128 = state.GetAccumulator().ReverseEndianness128();
		}
		finally
		{
			state.ZeroMemory();
			finalBlock.ZeroMemory();
		}
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void AppendPaddedSegmentsVector256(ref VectorBuffer16 accumulator, in VectorBuffer16 key, scoped ReadOnlySpan<byte> first, scoped ReadOnlySpan<byte> second, scoped ReadOnlySpan<byte> third)
	{
		GHashVector256State state = new(key.V128.ReverseEndianness128(), accumulator.V128.ReverseEndianness128());
		Unsafe.SkipInit(out VectorBuffer16 finalBlock);

		try
		{
			state.AppendPaddedSegment(first, ref finalBlock);
			state.AppendPaddedSegment(second, ref finalBlock);
			state.AppendPaddedSegment(third, ref finalBlock);
			accumulator.V128 = state.GetAccumulator().ReverseEndianness128();
		}
		finally
		{
			state.ZeroMemory();
			finalBlock.ZeroMemory();
		}
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void AppendPaddedSegmentsVector512(ref VectorBuffer16 accumulator, in VectorBuffer16 key, scoped ReadOnlySpan<byte> first, scoped ReadOnlySpan<byte> second, scoped ReadOnlySpan<byte> third)
	{
		GHashVector512State state = new(key.V128.ReverseEndianness128(), accumulator.V128.ReverseEndianness128());
		Unsafe.SkipInit(out VectorBuffer16 finalBlock);

		try
		{
			state.AppendPaddedSegment(first, ref finalBlock);
			state.AppendPaddedSegment(second, ref finalBlock);
			state.AppendPaddedSegment(third, ref finalBlock);
			accumulator.V128 = state.GetAccumulator().ReverseEndianness128();
		}
		finally
		{
			state.ZeroMemory();
			finalBlock.ZeroMemory();
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void AppendSequential(ref Vector128<byte> accumulator, in Vector128<byte> key, scoped ReadOnlySpan<byte> source)
	{
		if (source.Length is BlockSize)
		{
			Vector128<byte> block = source.AsVectorBuffer16().V128.ReverseEndianness128();
			accumulator = GFMultiply(key, block ^ accumulator);
			return;
		}

		Vector128<byte> localAccumulator = accumulator;
		Vector128<byte> localKey = key;

		while (!source.IsEmpty)
		{
			Vector128<byte> block = source.AsVectorBuffer16().V128.ReverseEndianness128();
			localAccumulator = GFMultiply(localKey, block ^ localAccumulator);
			source = source.Slice(BlockSize);
		}

		accumulator = localAccumulator;
	}

	private static void AppendPaddedSegmentSequential(ref Vector128<byte> accumulator, in Vector128<byte> key, scoped ReadOnlySpan<byte> source, ref VectorBuffer16 finalBlock)
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

		finalBlock = default;
		remaining.CopyTo(finalBlock);
		ReadOnlySpan<byte> block = finalBlock;
		AppendSequential(ref accumulator, in key, block);
	}
}
