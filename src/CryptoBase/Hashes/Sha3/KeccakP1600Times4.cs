using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.Hashes.Sha3;

// Four states in the 64-bit elements of 256-bit vectors.
internal readonly struct KeccakP1600Times4 : IKeccakP1600Kernel, IKeccakP1600Lanes<Vector256<ulong>>
{
	public static bool IsSupported => Avx2.IsSupported;

	public static int Lanes => 4;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Permute(ref ulong state)
	{
		KeccakP1600Interleaved.Permute<Vector256<ulong>, KeccakP1600Times4>(ref state);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<ulong> Load(ref ulong state, int lane)
	{
		return Vector256.LoadUnsafe(ref state, (nuint)(lane * Lanes));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Store(ref ulong state, int lane, Vector256<ulong> value)
	{
		value.StoreUnsafe(ref state, (nuint)(lane * Lanes));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<ulong> Xor(Vector256<ulong> left, Vector256<ulong> right)
	{
		return left ^ right;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<ulong> Xor5(Vector256<ulong> a, Vector256<ulong> b, Vector256<ulong> c, Vector256<ulong> d, Vector256<ulong> e)
	{
		if (Avx512F.VL.IsSupported)
		{
			return Avx512F.VL.TernaryLogic(Avx512F.VL.TernaryLogic(a, b, c, 0x96), d, e, 0x96);
		}

		return a ^ b ^ (c ^ d) ^ e;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<ulong> RotateLeftBy1AndXor(Vector256<ulong> xor, Vector256<ulong> rotated)
	{
		return xor ^ RotateLeft(rotated, 1);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<ulong> XorRotateLeft(Vector256<ulong> left, Vector256<ulong> right, [ConstantExpected(Min = 1, Max = 63)] byte offset)
	{
		return RotateLeft(left ^ right, offset);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<ulong> XorAndNot(Vector256<ulong> value, Vector256<ulong> left, Vector256<ulong> right)
	{
		if (Avx512F.VL.IsSupported)
		{
			return Avx512F.VL.TernaryLogic(value, left, right, 0xD2);
		}

		return value ^ Vector256.AndNot(right, left);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<ulong> RotateLeft(Vector256<ulong> value, [ConstantExpected(Min = 1, Max = 63)] byte offset)
	{
#pragma warning disable CA1857
		// ReSharper disable once ConstantExpected
		return value.RotateRightUInt64((byte)(64 - offset));
#pragma warning restore CA1857
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<ulong> Create(ulong value)
	{
		return Vector256.Create(value);
	}
}
