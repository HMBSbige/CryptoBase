using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.Hashes.Sha3;

// One state with each lane in the low element of its own 128-bit vector, so that the 32 AVX-512 vector registers hold nearly all of the round and VPTERNLOGQ takes each three-way XOR of θ and each lane of χ in one instruction. The round is KeccakP1600Times2's, whose upper element is simply left unused: no lane is ever shuffled across vectors, which is what costs the single-state 512-bit kernel on cores that split 512-bit instructions in two.
internal readonly struct KeccakP1600Lane128 : IKeccakP1600Lanes<Vector128<ulong>>
{
	// Without AVX-512VL most rotations take three instructions where the scalar kernel takes one, and nothing else is cheaper than scalar on x64. 32-bit x86 takes it anyway: the scalar kernel splits each lane over two of its few general-purpose registers.
	public static bool IsSupported
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => Avx512F.VL.IsSupported || Sse2.IsSupported && !X86Base.X64.IsSupported;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<ulong> Load(ref ulong state, int lane)
	{
		return Vector128.CreateScalarUnsafe(Unsafe.Add(ref state, lane));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Store(ref ulong state, int lane, Vector128<ulong> value)
	{
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
		return KeccakP1600Times2.Xor5(a, b, c, d, e);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<ulong> XorAndNot(Vector128<ulong> value, Vector128<ulong> left, Vector128<ulong> right)
	{
		return KeccakP1600Times2.XorAndNot(value, left, right);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<ulong> RotateLeft(Vector128<ulong> value, [ConstantExpected(Min = 1, Max = 63)] byte offset)
	{
		return KeccakP1600Times2.RotateLeft(value, offset);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<ulong> Create(ulong value)
	{
		return Vector128.CreateScalarUnsafe(value);
	}
}
