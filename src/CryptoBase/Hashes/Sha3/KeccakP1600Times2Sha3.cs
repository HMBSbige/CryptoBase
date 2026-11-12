#if NET11_0_OR_GREATER
using System.Diagnostics.CodeAnalysis;
using Sha3Arm = System.Runtime.Intrinsics.Arm.Sha3;

namespace CryptoBase.Hashes.Sha3;

// The lanes of KeccakP1600Times2, with each step of the round in one ARMv8.2 SHA3 instruction: EOR3 for each three-way XOR of θ, RAX1 for each D, XAR for θ and ρ of each lane, and BCAX for each lane of χ.
internal readonly struct KeccakP1600Times2Sha3 : IKeccakP1600Lanes<Vector128<ulong>>
{
	public static bool IsSupported => Sha3Arm.IsSupported;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<ulong> Load(ref ulong state, int lane)
	{
		return KeccakP1600Times2.Load(ref state, lane);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Store(ref ulong state, int lane, Vector128<ulong> value)
	{
		KeccakP1600Times2.Store(ref state, lane, value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<ulong> Xor(Vector128<ulong> left, Vector128<ulong> right)
	{
		return left ^ right;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<ulong> Xor5(Vector128<ulong> a, Vector128<ulong> b, Vector128<ulong> c, Vector128<ulong> d, Vector128<ulong> e)
	{
		return Sha3Arm.Xor(Sha3Arm.Xor(a, b, c), d, e);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<ulong> RotateLeftBy1AndXor(Vector128<ulong> xor, Vector128<ulong> rotated)
	{
		return Sha3Arm.BitwiseRotateLeftBy1AndXor(xor, rotated);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<ulong> XorRotateLeft(Vector128<ulong> left, Vector128<ulong> right, [ConstantExpected(Min = 1, Max = 63)] byte offset)
	{
#pragma warning disable CA1857
		// ReSharper disable once ConstantExpected
		return Sha3Arm.XorRotateRight(left, right, (byte)(64 - offset));
#pragma warning restore CA1857
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<ulong> XorAndNot(Vector128<ulong> value, Vector128<ulong> left, Vector128<ulong> right)
	{
		return Sha3Arm.BitwiseClearXor(value, right, left);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<ulong> Create(ulong value)
	{
		return Vector128.Create(value);
	}
}
#endif
