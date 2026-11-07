using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.Hashes.SM3;

// Eight lanes in AVX2 vectors. Without AVX-512, a rotation takes two shifts and an OR, but one by 8 takes a byte shuffle, so P0 and P1 rotate x ^ (x <<< 8) once rather than x twice.
internal readonly struct SM3Vector256 : ISM3Lanes<Vector256<uint>>
{
	public static bool IsSupported => Vector256.IsHardwareAccelerated && Avx2.IsSupported;

	public static int Lanes => 8;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<uint> Create(uint value)
	{
		return Vector256.Create(value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<uint> Counters(uint start)
	{
		return Vector256.Create(start) + Vector256<uint>.Indices;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<uint> Add(Vector256<uint> left, Vector256<uint> right)
	{
		return left + right;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<uint> Or(Vector256<uint> left, Vector256<uint> right)
	{
		return left | right;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<uint> Xor(Vector256<uint> left, Vector256<uint> right)
	{
		return left ^ right;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<uint> Xor(Vector256<uint> x, Vector256<uint> y, Vector256<uint> z)
	{
		return Avx512F.VL.IsSupported ? Avx512F.VL.TernaryLogic(x, y, z, 0x96) : x ^ y ^ z;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<uint> Choose(Vector256<uint> x, Vector256<uint> y, Vector256<uint> z)
	{
		return Vector256.ConditionalSelect(x, y, z);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<uint> Majority(Vector256<uint> x, Vector256<uint> y, Vector256<uint> z)
	{
		return Avx512F.VL.IsSupported ? Avx512F.VL.TernaryLogic(x, y, z, 0xE8) : Vector256.ConditionalSelect(x ^ y, z, y);
	}

	// Written out rather than through RotateLeftUInt32, whose layers of inlined calls would take the JIT over the number of locals it tracks in the rounds.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<uint> RotateLeft(Vector256<uint> value, [ConstantExpected(Min = 1, Max = 31)] byte count)
	{
		return Avx512F.VL.IsSupported ? Avx512F.VL.RotateLeft(value, count) : value << count | value >>> 32 - count;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<uint> ShiftLeft(Vector256<uint> value, int count)
	{
		return value << count;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<uint> ShiftRightLogical(Vector256<uint> value, int count)
	{
		return value >>> count;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<uint> P0(Vector256<uint> value)
	{
		if (Avx512F.VL.IsSupported)
		{
			return Xor(value, RotateLeft(value, 9), RotateLeft(value, 17));
		}

		return value ^ RotateLeft(value ^ RotateLeftByte(value), 9);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<uint> P1(Vector256<uint> value)
	{
		if (Avx512F.VL.IsSupported)
		{
			return Xor(value, RotateLeft(value, 15), RotateLeft(value, 23));
		}

		return value ^ RotateLeft(value ^ RotateLeftByte(value), 15);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<uint> RotateLeftByte(Vector256<uint> value)
	{
		Vector128<byte> indices = Vector128.Create((byte)3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14);
		return Avx2.Shuffle(value.AsByte(), Vector256.Create(indices, indices)).AsUInt32();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Store(Vector256<uint> s0, Vector256<uint> s1, Vector256<uint> s2, Vector256<uint> s3, Vector256<uint> s4, Vector256<uint> s5, Vector256<uint> s6, Vector256<uint> s7, ref byte destination)
	{
		Vector256<uint> x0 = s0.ReverseEndianness32();
		Vector256<uint> x1 = s1.ReverseEndianness32();
		Vector256<uint> x2 = s2.ReverseEndianness32();
		Vector256<uint> x3 = s3.ReverseEndianness32();
		Vector256<uint> x4 = s4.ReverseEndianness32();
		Vector256<uint> x5 = s5.ReverseEndianness32();
		Vector256<uint> x6 = s6.ReverseEndianness32();
		Vector256<uint> x7 = s7.ReverseEndianness32();
		VectorTranspose.Transpose(ref x0, ref x1, ref x2, ref x3, ref x4, ref x5, ref x6, ref x7);
		x0.StoreUnsafe(ref Unsafe.As<byte, uint>(ref destination));
		x1.StoreUnsafe(ref Unsafe.As<byte, uint>(ref destination), 8);
		x2.StoreUnsafe(ref Unsafe.As<byte, uint>(ref destination), 16);
		x3.StoreUnsafe(ref Unsafe.As<byte, uint>(ref destination), 24);
		x4.StoreUnsafe(ref Unsafe.As<byte, uint>(ref destination), 32);
		x5.StoreUnsafe(ref Unsafe.As<byte, uint>(ref destination), 40);
		x6.StoreUnsafe(ref Unsafe.As<byte, uint>(ref destination), 48);
		x7.StoreUnsafe(ref Unsafe.As<byte, uint>(ref destination), 56);
	}
}
