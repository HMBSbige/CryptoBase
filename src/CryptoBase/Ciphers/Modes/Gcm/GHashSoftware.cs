namespace CryptoBase.Ciphers.Modes.Gcm;

internal static partial class GHashSoftware
{
	private static int EightBitTableThreshold => (X86Base.X64.IsSupported ? 8 : 9) * GHash.BlockSizeInBytes;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void InitializeTable(ref ulong hh, ref ulong hl, ulong vh, ulong vl, int highBit)
	{
		hh = 0;
		hl = 0;
		Unsafe.Add(ref hl, highBit) = vl;
		Unsafe.Add(ref hh, highBit) = vh;

		int i = highBit >> 1;

		while (i > 0)
		{
			ulong t = (vl & 1) * 0xe1000000;
			vl = vh << 63 | vl >> 1;
			vh = vh >> 1 ^ t << 32;

			Unsafe.Add(ref hl, i) = vl;
			Unsafe.Add(ref hh, i) = vh;

			i >>= 1;
		}

		i = 2;

		while (i <= highBit)
		{
			vh = Unsafe.Add(ref hh, i);
			vl = Unsafe.Add(ref hl, i);

			for (int j = 1; j < i; ++j)
			{
				Unsafe.Add(ref hh, i + j) = vh ^ Unsafe.Add(ref hh, j);
				Unsafe.Add(ref hl, i + j) = vl ^ Unsafe.Add(ref hl, j);
			}

			i <<= 1;
		}
	}

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
