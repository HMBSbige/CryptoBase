namespace CryptoBase.Ciphers.Modes.Gcm;

internal static partial class GHashSoftware
{
	private static int EightBitTableThreshold => (X86Base.X64.IsSupported ? 8 : 9) * GHash.BlockSizeInBytes;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void AppendPaddedSegments(ref Vector128<byte> accumulator, in Vector128<byte> key, scoped ReadOnlySpan<byte> first, scoped ReadOnlySpan<byte> second, scoped ReadOnlySpan<byte> third)
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
	private static void AppendPaddedSegments4(ref Vector128<byte> accumulator, in Vector128<byte> key, scoped ReadOnlySpan<byte> first, scoped ReadOnlySpan<byte> second, scoped ReadOnlySpan<byte> third)
	{
		Unsafe.SkipInit(out GHashFourBitState state);
		Unsafe.SkipInit(out Vector128<byte> finalBlock);

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
		}
	}

	[SkipLocalsInit]
	private static void AppendPaddedSegments8(ref Vector128<byte> accumulator, in Vector128<byte> key, scoped ReadOnlySpan<byte> first, scoped ReadOnlySpan<byte> second, scoped ReadOnlySpan<byte> third)
	{
		Unsafe.SkipInit(out GHashEightBitState state);
		Unsafe.SkipInit(out Vector128<byte> finalBlock);

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
		}
	}
}
