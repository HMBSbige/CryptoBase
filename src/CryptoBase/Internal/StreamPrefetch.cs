namespace CryptoBase.Internal;

internal static unsafe class StreamPrefetch
{
	// The hardware prefetchers on x86 stop at 4 KiB boundaries, so each new 4 KiB block would start with cache misses.
	internal const int Distance = 4096;

	private const int MinimumLength = 4 << 20;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static int Iterations(int count, int stride)
	{
		return count >= MinimumLength / stride ? count - Distance / stride : 0;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static int MinimumRemaining(int length, int stride)
	{
		return length >= MinimumLength ? Distance + stride : int.MaxValue;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Bytes<T>(ref T position, int byteCount)
	{
		Debug.Assert(byteCount is > 0 and <= 4 * 64);

		Line(ref position, 0);

		if (byteCount > 64)
		{
			Line(ref position, 64);
		}

		if (byteCount > 128)
		{
			Line(ref position, 128);
		}

		if (byteCount > 192)
		{
			Line(ref position, 192);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Line<T>(ref T position, nuint byteOffset)
	{
		if (Sse.IsSupported)
		{
			Sse.Prefetch0((byte*)Unsafe.AsPointer(ref position) + Distance + byteOffset);
		}
	}
}
