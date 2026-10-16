namespace CryptoBase.Ciphers.Streams;

internal static partial class ChaCha20Utils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static int XorBlocks(Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		bool useVectorizedPath = (Sse2.IsSupported || AdvSimd.Arm64.IsSupported) && source.Length >= 128;

		if (useVectorizedPath)
		{
			return XorCounterRegion(ref MemoryMarshal.GetReference(state), ref MemoryMarshal.GetReference(source), ref MemoryMarshal.GetReference(destination), source.Length);
		}

		return XorScalar(ref MemoryMarshal.GetReference(state), ref MemoryMarshal.GetReference(source), ref MemoryMarshal.GetReference(destination), source.Length);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static int XorCounterRegion(ref uint stateRef, ref byte input, ref byte output, int length)
	{
		ulong untilCarry = (1UL << 32) - Unsafe.Add(ref stateRef, 12);

		if ((uint)length >> 6 > untilCarry)
		{
			int prefix = (int)untilCarry * 64;
			XorCounterRegion(ref stateRef, ref input, ref output, prefix);
			return prefix + XorCounterRegion(ref stateRef, ref Unsafe.Add(ref input, prefix), ref Unsafe.Add(ref output, prefix), length - prefix);
		}

		// Whole batches use the widest kernel and the remaining blocks the narrowest kernel that covers them.
		return AdvSimd.Arm64.IsSupported
			? XorArm64(ref stateRef, ref input, ref output, length)
			: XorX86(ref stateRef, ref input, ref output, length);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static int XorArm64(ref uint stateRef, ref byte input, ref byte output, int length)
	{
		int blocks = length >> 6;
		int wholeBlocks = blocks & -8;

		if (wholeBlocks > 0)
		{
			XorNeon(ref stateRef, ref input, ref output, wholeBlocks);
		}

		if (blocks > wholeBlocks)
		{
			int offset = wholeBlocks * 64;
			XorPartialBatchArm64(ref stateRef, ref Unsafe.Add(ref input, offset), ref Unsafe.Add(ref output, offset), blocks - wholeBlocks);
		}

		return blocks * 64;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void XorPartialBatchArm64(ref uint stateRef, ref byte input, ref byte output, int blocks)
	{
		Debug.Assert(blocks is > 0 and < 8);

		if (blocks is 1)
		{
			XorScalar(ref stateRef, ref input, ref output, 64);
		}
		else if (blocks is 2)
		{
			XorVector128Two(ref stateRef, ref input, ref output);
		}
		else if (blocks <= 4)
		{
			XorVector128(ref stateRef, ref input, ref output, blocks);
		}
		else
		{
			XorNeon(ref stateRef, ref input, ref output, blocks);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static int XorX86(ref uint stateRef, ref byte input, ref byte output, int length)
	{
		int blocks = length >> 6;
		int wholeBlocks = blocks & -(Vector512.IsHardwareAccelerated ? 16 : Vector256.IsHardwareAccelerated ? 8 : 4);

		if (wholeBlocks > 0)
		{
			if (Vector512.IsHardwareAccelerated)
			{
				XorVector512(ref stateRef, ref input, ref output, wholeBlocks);
			}
			else if (Vector256.IsHardwareAccelerated)
			{
				XorVector256(ref stateRef, ref input, ref output, wholeBlocks);
			}
			else
			{
				XorVector128(ref stateRef, ref input, ref output, wholeBlocks);
			}
		}

		if (blocks > wholeBlocks)
		{
			int offset = wholeBlocks * 64;
			XorPartialBatchX86(ref stateRef, ref Unsafe.Add(ref input, offset), ref Unsafe.Add(ref output, offset), blocks - wholeBlocks);
		}

		return blocks * 64;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void XorPartialBatchX86(ref uint stateRef, ref byte input, ref byte output, int blocks)
	{
		Debug.Assert(blocks > 0);

		if (blocks is 1)
		{
			XorScalar(ref stateRef, ref input, ref output, 64);
			return;
		}

		if (!Vector256.IsHardwareAccelerated)
		{
			Debug.Assert(blocks < 4);

			if (blocks is 2)
			{
				XorVector128Two(ref stateRef, ref input, ref output);
			}
			else
			{
				XorVector128(ref stateRef, ref input, ref output, blocks);
			}

			return;
		}

		if (blocks is 2)
		{
			XorVector256Two(ref stateRef, ref input, ref output);
		}
		else if (blocks <= 4)
		{
			XorVector256Four(ref stateRef, ref input, ref output, blocks);
		}
		else if (!Vector512.IsHardwareAccelerated || blocks <= 8)
		{
			XorVector256(ref stateRef, ref input, ref output, blocks);
		}
		else
		{
			XorVector512(ref stateRef, ref input, ref output, blocks);
		}
	}
}
