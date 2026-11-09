using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.Hashes.SM3;

// Sixteen lanes in AVX-512 vectors, which rotate and take three-input logic in one instruction each.
internal readonly struct SM3Vector512 : ISM3Lanes<Vector512<uint>>
{
	// AVX-512BW gives the byte shuffle that reverses the words in Store.
	public static bool IsSupported => Vector512.IsHardwareAccelerated && Avx512F.IsSupported && Avx512BW.IsSupported;

	public static int Lanes => 16;

	public static bool RotatesDirectly => true;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<uint> Create(uint value)
	{
		return Vector512.Create(value);
	}

	// Lane 4b + i takes block 4i + b, so that Store needs one permutation for each pair of blocks.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<uint> Counters(uint start)
	{
		return Vector512.Create(start) + Vector512.Create(0u, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<uint> Add(Vector512<uint> left, Vector512<uint> right)
	{
		return left + right;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<uint> Or(Vector512<uint> left, Vector512<uint> right)
	{
		return left | right;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<uint> Xor(Vector512<uint> left, Vector512<uint> right)
	{
		return left ^ right;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<uint> Xor(Vector512<uint> x, Vector512<uint> y, Vector512<uint> z)
	{
		return Avx512F.TernaryLogic(x, y, z, 0x96);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<uint> Choose(Vector512<uint> x, Vector512<uint> y, Vector512<uint> z)
	{
		return Vector512.ConditionalSelect(x, y, z);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<uint> Majority(Vector512<uint> x, Vector512<uint> y, Vector512<uint> z)
	{
		return Avx512F.TernaryLogic(x, y, z, 0xE8);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<uint> RotateLeft(Vector512<uint> value, [ConstantExpected(Min = 1, Max = 31)] byte count)
	{
		return Avx512F.RotateLeft(value, count);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<uint> ShiftLeft(Vector512<uint> value, int count)
	{
		return value << count;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<uint> ShiftRightLogical(Vector512<uint> value, int count)
	{
		return value >>> count;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<uint> RotateLeftByte(Vector512<uint> value)
	{
		return RotateLeft(value, 8);
	}

	// Within each 128-bit block b, the interleaves turn words 0 to 3 and 4 to 7 of the state into those of lane 4b + i in q[i] and q[4 + i]. One permutation of q[i] and q[4 + i] then gives lanes i and 4 + i, blocks 4i and 4i + 1, and another lanes 8 + i and 12 + i, blocks 4i + 2 and 4i + 3.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Store(Vector512<uint> s0, Vector512<uint> s1, Vector512<uint> s2, Vector512<uint> s3, Vector512<uint> s4, Vector512<uint> s5, Vector512<uint> s6, Vector512<uint> s7, ref byte destination)
	{
		s0 = s0.ReverseEndianness32();
		s1 = s1.ReverseEndianness32();
		s2 = s2.ReverseEndianness32();
		s3 = s3.ReverseEndianness32();
		s4 = s4.ReverseEndianness32();
		s5 = s5.ReverseEndianness32();
		s6 = s6.ReverseEndianness32();
		s7 = s7.ReverseEndianness32();
		Vector512<ulong> t0 = Avx512F.UnpackLow(s0, s1).AsUInt64();
		Vector512<ulong> t1 = Avx512F.UnpackHigh(s0, s1).AsUInt64();
		Vector512<ulong> t2 = Avx512F.UnpackLow(s2, s3).AsUInt64();
		Vector512<ulong> t3 = Avx512F.UnpackHigh(s2, s3).AsUInt64();
		Vector512<ulong> t4 = Avx512F.UnpackLow(s4, s5).AsUInt64();
		Vector512<ulong> t5 = Avx512F.UnpackHigh(s4, s5).AsUInt64();
		Vector512<ulong> t6 = Avx512F.UnpackLow(s6, s7).AsUInt64();
		Vector512<ulong> t7 = Avx512F.UnpackHigh(s6, s7).AsUInt64();
		Vector512<ulong> low = Vector512.Create(0ul, 1, 8, 9, 2, 3, 10, 11);
		Vector512<ulong> high = Vector512.Create(4ul, 5, 12, 13, 6, 7, 14, 15);
		StorePair(Avx512F.UnpackLow(t0, t2), Avx512F.UnpackLow(t4, t6), low, high, ref destination);
		StorePair(Avx512F.UnpackHigh(t0, t2), Avx512F.UnpackHigh(t4, t6), low, high, ref Unsafe.Add(ref destination, 4 * SM3Lanes<SM3Vector512, Vector512<uint>>.BlockLength));
		StorePair(Avx512F.UnpackLow(t1, t3), Avx512F.UnpackLow(t5, t7), low, high, ref Unsafe.Add(ref destination, 8 * SM3Lanes<SM3Vector512, Vector512<uint>>.BlockLength));
		StorePair(Avx512F.UnpackHigh(t1, t3), Avx512F.UnpackHigh(t5, t7), low, high, ref Unsafe.Add(ref destination, 12 * SM3Lanes<SM3Vector512, Vector512<uint>>.BlockLength));
	}

	// Blocks 4i to 4i + 3 from q[i] = words and q[4 + i] = rest, at destination.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void StorePair(Vector512<ulong> words, Vector512<ulong> rest, Vector512<ulong> low, Vector512<ulong> high, ref byte destination)
	{
		Avx512F.PermuteVar8x64x2(words, low, rest).StoreUnsafe(ref Unsafe.As<byte, ulong>(ref destination));
		Avx512F.PermuteVar8x64x2(words, high, rest).StoreUnsafe(ref Unsafe.As<byte, ulong>(ref destination), 8);
	}
}
