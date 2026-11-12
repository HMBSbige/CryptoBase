using System.Diagnostics.CodeAnalysis;
#if NET11_0_OR_GREATER
using Sha3Arm = System.Runtime.Intrinsics.Arm.Sha3;
#endif

namespace CryptoBase.Hashes.Sha3;

// Two states in the 64-bit elements of 128-bit vectors. Where CpuIdUtils.PreferArmSha3, Permute runs the round on KeccakP1600Times2Sha3 instead, which takes each step in one ARMv8.2 SHA3 instruction.
internal readonly struct KeccakP1600Times2 : IKeccakP1600Kernel, IKeccakP1600Lanes<Vector128<ulong>>
{
	public static bool IsSupported => Sse2.IsSupported || AdvSimd.Arm64.IsSupported;

	public static int Lanes => 2;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Permute(ref ulong state)
	{
#if NET11_0_OR_GREATER
		if (Sha3Arm.IsSupported && CpuIdUtils.PreferArmSha3)
		{
			KeccakP1600Interleaved.Permute<Vector128<ulong>, KeccakP1600Times2Sha3>(ref state);
			return;
		}
#endif

		KeccakP1600Interleaved.Permute<Vector128<ulong>, KeccakP1600Times2>(ref state);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<ulong> Load(ref ulong state, int lane)
	{
		return Vector128.LoadUnsafe(ref state, (nuint)(lane * Lanes));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Store(ref ulong state, int lane, Vector128<ulong> value)
	{
		value.StoreUnsafe(ref state, (nuint)(lane * Lanes));
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
	public static Vector128<ulong> RotateLeftBy1AndXor(Vector128<ulong> xor, Vector128<ulong> rotated)
	{
		return xor ^ RotateLeft(rotated, 1);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<ulong> XorRotateLeft(Vector128<ulong> left, Vector128<ulong> right, [ConstantExpected(Min = 1, Max = 63)] byte offset)
	{
		return RotateLeft(left ^ right, offset);
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
#pragma warning disable CA1857
		if (AdvSimd.IsSupported)
		{
			// ReSharper disable once ConstantExpected
			return AdvSimd.ShiftLeftAndInsert(AdvSimd.ShiftRightLogical(value, (byte)(64 - offset)), value, offset);
		}

		// ReSharper disable once ConstantExpected
		return value.RotateRightUInt64((byte)(64 - offset));
#pragma warning restore CA1857
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<ulong> Create(ulong value)
	{
		return Vector128.Create(value);
	}
}
