using System.Diagnostics.CodeAnalysis;
#if NET11_0_OR_GREATER
using Sha3Arm = System.Runtime.Intrinsics.Arm.Sha3;
#endif

namespace CryptoBase.Hashes.Sha3;

// One state with each lane in the low element of its own 128-bit vector, so that the 32 vector registers of AVX-512 or ARM64 hold nearly all of the round and VPTERNLOGQ, or an ARMv8.2 SHA3 instruction, takes each three-way XOR of θ and each lane of χ in one instruction. The round is KeccakP1600Times2's, or on ARM64 KeccakP1600Times2Sha3's, whose upper element is simply left unused: no lane is ever shuffled across vectors, which is what costs the single-state 512-bit kernel on cores that split 512-bit instructions in two.
internal readonly struct KeccakP1600Lane128 : IKeccakP1600Lanes<Vector128<ulong>>
{
	// Without AVX-512VL most rotations take three instructions where the scalar kernel takes one, and nothing else is cheaper than scalar on x64. 32-bit x86 takes it anyway: the scalar kernel splits each lane over two of its few general-purpose registers. ARM64 takes it where CpuIdUtils.PreferArmSha3: for each lane its instructions take the place of two of the scalar kernel, the EOR and ROR of θ and ρ, and the BIC and EOR of χ.
	public static bool IsSupported
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
#if NET11_0_OR_GREATER
		get => Avx512F.VL.IsSupported || Sse2.IsSupported && !X86Base.X64.IsSupported || Sha3Arm.IsSupported && CpuIdUtils.PreferArmSha3;
#else
		get => Avx512F.VL.IsSupported || Sse2.IsSupported && !X86Base.X64.IsSupported;
#endif
	}

	// ARM64 moves a lane between memory and a vector register directly, where a scalar load or store would pass it through a general-purpose register.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<ulong> Load(ref ulong state, int lane)
	{
		if (AdvSimd.IsSupported)
		{
			return Vector64.LoadUnsafe(ref state, (nuint)lane).ToVector128Unsafe();
		}

		return Vector128.CreateScalarUnsafe(Unsafe.Add(ref state, lane));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Store(ref ulong state, int lane, Vector128<ulong> value)
	{
		if (AdvSimd.IsSupported)
		{
			value.GetLower().StoreUnsafe(ref state, (nuint)lane);
			return;
		}

		Unsafe.Add(ref state, lane) = value.ToScalar();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<ulong> Xor(Vector128<ulong> left, Vector128<ulong> right)
	{
		return KeccakP1600Times2.Xor(left, right);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<ulong> Xor5(Vector128<ulong> a, Vector128<ulong> b, Vector128<ulong> c, Vector128<ulong> d, Vector128<ulong> e)
	{
#if NET11_0_OR_GREATER
		if (Sha3Arm.IsSupported)
		{
			return KeccakP1600Times2Sha3.Xor5(a, b, c, d, e);
		}
#endif

		return KeccakP1600Times2.Xor5(a, b, c, d, e);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<ulong> RotateLeftBy1AndXor(Vector128<ulong> xor, Vector128<ulong> rotated)
	{
#if NET11_0_OR_GREATER
		if (Sha3Arm.IsSupported)
		{
			return KeccakP1600Times2Sha3.RotateLeftBy1AndXor(xor, rotated);
		}
#endif

		return KeccakP1600Times2.RotateLeftBy1AndXor(xor, rotated);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<ulong> XorRotateLeft(Vector128<ulong> left, Vector128<ulong> right, [ConstantExpected(Min = 1, Max = 63)] byte offset)
	{
#if NET11_0_OR_GREATER
		if (Sha3Arm.IsSupported)
		{
			return KeccakP1600Times2Sha3.XorRotateLeft(left, right, offset);
		}
#endif

		return KeccakP1600Times2.XorRotateLeft(left, right, offset);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<ulong> XorAndNot(Vector128<ulong> value, Vector128<ulong> left, Vector128<ulong> right)
	{
#if NET11_0_OR_GREATER
		if (Sha3Arm.IsSupported)
		{
			return KeccakP1600Times2Sha3.XorAndNot(value, left, right);
		}
#endif

		return KeccakP1600Times2.XorAndNot(value, left, right);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<ulong> Create(ulong value)
	{
		return Vector128.CreateScalarUnsafe(value);
	}
}
