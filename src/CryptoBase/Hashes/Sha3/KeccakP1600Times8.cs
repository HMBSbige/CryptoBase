using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.Hashes.Sha3;

// Eight states in the 64-bit elements of 512-bit vectors.
internal readonly struct KeccakP1600Times8 : IKeccakP1600Kernel, IKeccakP1600Lanes<Vector512<ulong>>
{
	public static bool IsSupported => KeccakP1600.IsAvx512Supported;

	public static int Lanes => 8;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Permute(ref ulong state)
	{
		KeccakP1600Interleaved.Permute<Vector512<ulong>, KeccakP1600Times8>(ref Unsafe.As<ulong, Vector512<ulong>>(ref state));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<ulong> Xor(Vector512<ulong> left, Vector512<ulong> right)
	{
		return left ^ right;
	}

	// 0x96 is a ^ b ^ c over the truth-table inputs 0xF0, 0xCC and 0xAA.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<ulong> Xor5(Vector512<ulong> a, Vector512<ulong> b, Vector512<ulong> c, Vector512<ulong> d, Vector512<ulong> e)
	{
		return Avx512F.TernaryLogic(Avx512F.TernaryLogic(a, b, c, 0x96), d, e, 0x96);
	}

	// 0xD2 is 0xF0 ^ (~0xCC & 0xAA).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<ulong> XorAndNot(Vector512<ulong> value, Vector512<ulong> left, Vector512<ulong> right)
	{
		return Avx512F.TernaryLogic(value, left, right, 0xD2);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<ulong> RotateLeft(Vector512<ulong> value, [ConstantExpected(Min = 1, Max = 63)] byte offset)
	{
		return Avx512F.RotateLeft(value, offset);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<ulong> Create(ulong value)
	{
		return Vector512.Create(value);
	}
}
