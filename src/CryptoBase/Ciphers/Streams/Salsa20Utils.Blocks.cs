namespace CryptoBase.Ciphers.Streams;

internal static partial class Salsa20Utils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static int XorBlocks(Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		bool useVectorizedPath = Sse2.IsSupported && source.Length >= 256
								|| AdvSimd.Arm64.IsSupported && source.Length >= 128;

		if (useVectorizedPath)
		{
			return XorCounterRegion(ref state.GetReference(), ref source.GetReference(), ref destination.GetReference(), source.Length);
		}

		return XorScalar(ref state.GetReference(), ref source.GetReference(), ref destination.GetReference(), source.Length);
	}

	// Keep counter-carry handling and vector-path register saves out of the scalar fast path.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static int XorCounterRegion(ref uint stateRef, ref byte input, ref byte output, int length)
	{
		ulong untilCarry = (1UL << 32) - Unsafe.Add(ref stateRef, 8);

		if ((uint)length >> 6 > untilCarry)
		{
			int prefix = (int)untilCarry * 64;
			XorCounterRegion(ref stateRef, ref input, ref output, prefix);
			return prefix + XorCounterRegion(ref stateRef, ref Unsafe.Add(ref input, prefix), ref Unsafe.Add(ref output, prefix), length - prefix);
		}

		return AdvSimd.Arm64.IsSupported
			? XorArm64(ref stateRef, ref input, ref output, length)
			: XorX86(ref stateRef, ref input, ref output, length);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static int XorArm64(ref uint stateRef, ref byte input, ref byte output, int length)
	{
		int processed = 0;
		int remaining = length;

		if (remaining >= 192)
		{
			int vectorized = XorVector128(ref stateRef, ref input, ref output, remaining);
			processed += vectorized;
			remaining -= vectorized;
		}

		if (remaining >= 128)
		{
			XorVector128Two(ref stateRef, ref Unsafe.Add(ref input, processed), ref Unsafe.Add(ref output, processed));
			processed += 128;
			remaining -= 128;
		}

		if (remaining >= 64)
		{
			processed += XorScalar(ref stateRef, ref Unsafe.Add(ref input, processed), ref Unsafe.Add(ref output, processed), remaining);
		}

		return processed;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static int XorX86(ref uint stateRef, ref byte input, ref byte output, int length)
	{
		int processed = 0;

		if (Vector512.IsHardwareAccelerated && length >= 1024)
		{
			processed = XorVector512(ref stateRef, ref input, ref output, length);
		}

		int remaining = length - processed;

		if (Vector256.IsHardwareAccelerated && remaining >= 512)
		{
			int vectorized = XorVector256(ref stateRef, ref Unsafe.Add(ref input, processed), ref Unsafe.Add(ref output, processed), remaining);
			processed += vectorized;
			remaining -= vectorized;
		}

		if (remaining >= 256)
		{
			int vectorized = XorVector128(ref stateRef, ref Unsafe.Add(ref input, processed), ref Unsafe.Add(ref output, processed), remaining);
			processed += vectorized;
			remaining -= vectorized;
		}

		if (remaining >= 64)
		{
			processed += XorScalar(ref stateRef, ref Unsafe.Add(ref input, processed), ref Unsafe.Add(ref output, processed), remaining);
		}

		return processed;
	}
}
