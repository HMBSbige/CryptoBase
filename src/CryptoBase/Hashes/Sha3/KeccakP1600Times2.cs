using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.Hashes.Sha3;

// Two states in the 64-bit elements of 128-bit vectors.
// .NET does not expose the ARMv8.2 SHA3 instructions (EOR3, RAX1, XAR, BCAX), so ARM64 builds them from plain NEON.
internal readonly struct KeccakP1600Times2 : IKeccakP1600Kernel, IKeccakP1600Lanes<Vector128<ulong>>
{
	public static bool IsSupported => Sse2.IsSupported || AdvSimd.Arm64.IsSupported;

	public static int Lanes => 2;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Permute(ref ulong state)
	{
		KeccakP1600Interleaved.Permute<Vector128<ulong>, KeccakP1600Times2>(ref Unsafe.As<ulong, Vector128<ulong>>(ref state));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<ulong> Xor(Vector128<ulong> left, Vector128<ulong> right)
	{
		return left ^ right;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<ulong> Xor5(Vector128<ulong> a, Vector128<ulong> b, Vector128<ulong> c, Vector128<ulong> d, Vector128<ulong> e)
	{
		if (Avx512F.VL.IsSupported)
		{
			return Avx512F.VL.TernaryLogic(Avx512F.VL.TernaryLogic(a, b, c, 0x96), d, e, 0x96);
		}

		return a ^ b ^ (c ^ d) ^ e;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<ulong> XorAndNot(Vector128<ulong> value, Vector128<ulong> left, Vector128<ulong> right)
	{
		if (Avx512F.VL.IsSupported)
		{
			return Avx512F.VL.TernaryLogic(value, left, right, 0xD2);
		}

		return value ^ Vector128.AndNot(right, left);
	}

	// On ARM64, SLI inserts the left shift above the bits a USHR brought down, two instructions instead of three.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<ulong> RotateLeft(Vector128<ulong> value, [ConstantExpected(Min = 1, Max = 63)] byte offset)
	{
		if (Avx512F.VL.IsSupported)
		{
			return Avx512F.VL.RotateLeft(value, offset);
		}

		if (AdvSimd.IsSupported)
		{
#pragma warning disable CA1857
			// ReSharper disable once ConstantExpected
			return AdvSimd.ShiftLeftAndInsert(AdvSimd.ShiftRightLogical(value, (byte)(64 - offset)), value, offset);
#pragma warning restore CA1857
		}

		if (Ssse3.IsSupported && offset is 8 or 56)
		{
			return offset is 8
				? Ssse3.Shuffle(value.AsByte(), Vector128.Create((byte)7, 0, 1, 2, 3, 4, 5, 6, 15, 8, 9, 10, 11, 12, 13, 14)).AsUInt64()
				: Ssse3.Shuffle(value.AsByte(), Vector128.Create((byte)1, 2, 3, 4, 5, 6, 7, 0, 9, 10, 11, 12, 13, 14, 15, 8)).AsUInt64();
		}

		return offset is 1 ? value + value | value >>> 63 : value << offset | value >>> 64 - offset;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<ulong> Create(ulong value)
	{
		return Vector128.Create(value);
	}
}
