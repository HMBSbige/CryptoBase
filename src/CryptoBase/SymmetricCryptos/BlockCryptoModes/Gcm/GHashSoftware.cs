namespace CryptoBase.SymmetricCryptos.BlockCryptoModes.Gcm;

internal static partial class GHashSoftware
{
	private static int EightBitTableThreshold => (X86Base.X64.IsSupported ? 8 : 9) * GHash.BlockSizeInBytes;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void AppendPaddedSegments(ref VectorBuffer16 accumulator, in VectorBuffer16 key, scoped ReadOnlySpan<byte> first, scoped ReadOnlySpan<byte> second, scoped ReadOnlySpan<byte> third)
	{
		long totalPaddedLength = GHash.GetPaddedLength(first.Length) + GHash.GetPaddedLength(second.Length) + GHash.GetPaddedLength(third.Length);

		if (totalPaddedLength >= EightBitTableThreshold)
		{
			AppendPaddedSegments8(ref accumulator, in key, first, second, third);
		}
		else
		{
			AppendPaddedSegments4(ref accumulator, in key, first, second, third);
		}
	}

	[SkipLocalsInit]
	private static void AppendPaddedSegments4(ref VectorBuffer16 accumulator, in VectorBuffer16 key, scoped ReadOnlySpan<byte> first, scoped ReadOnlySpan<byte> second, scoped ReadOnlySpan<byte> third)
	{
		Unsafe.SkipInit(out GHashFourBitState state);
		Unsafe.SkipInit(out VectorBuffer16 finalBlock);

		try
		{
			state.Initialize(in key, in accumulator);
			state.AppendPaddedSegment(first, ref finalBlock);
			state.AppendPaddedSegment(second, ref finalBlock);
			state.AppendPaddedSegment(third, ref finalBlock);
			state.CopyAccumulatorTo(ref accumulator);
		}
		finally
		{
			state.ZeroMemory();
			finalBlock.ZeroMemory();
		}
	}

	[SkipLocalsInit]
	private static void AppendPaddedSegments8(ref VectorBuffer16 accumulator, in VectorBuffer16 key, scoped ReadOnlySpan<byte> first, scoped ReadOnlySpan<byte> second, scoped ReadOnlySpan<byte> third)
	{
		Unsafe.SkipInit(out GHashEightBitState state);
		Unsafe.SkipInit(out VectorBuffer16 finalBlock);

		try
		{
			state.Initialize(in key, in accumulator);
			state.AppendPaddedSegment(first, ref finalBlock);
			state.AppendPaddedSegment(second, ref finalBlock);
			state.AppendPaddedSegment(third, ref finalBlock);
			state.CopyAccumulatorTo(ref accumulator);
		}
		finally
		{
			state.ZeroMemory();
			finalBlock.ZeroMemory();
		}
	}
}
