using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.Hashes.SM3;

// Four lanes in 128-bit vectors, on x64 and ARM64. Where a rotation by 8 takes one byte shuffle and others more, P0 and P1 rotate x ^ (x <<< 8) once rather than x twice.
internal readonly struct SM3Vector128 : ISM3Lanes<Vector128<uint>>
{
	public static bool IsSupported => Vector128.IsHardwareAccelerated && (Sse2.IsSupported || AdvSimd.Arm64.IsSupported);

	public static int Lanes => 4;

	// One instruction rotates by any amount, or none rotates by 8 in one.
	private static bool RotatesDirectly
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => Avx512F.VL.IsSupported || !Ssse3.IsSupported && !AdvSimd.IsSupported;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<uint> Create(uint value)
	{
		return Vector128.Create(value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<uint> Counters(uint start)
	{
		return Vector128.Create(start) + Vector128<uint>.Indices;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<uint> Add(Vector128<uint> left, Vector128<uint> right)
	{
		return left + right;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<uint> Or(Vector128<uint> left, Vector128<uint> right)
	{
		return left | right;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<uint> Xor(Vector128<uint> left, Vector128<uint> right)
	{
		return left ^ right;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<uint> Xor(Vector128<uint> x, Vector128<uint> y, Vector128<uint> z)
	{
		return Avx512F.VL.IsSupported ? Avx512F.VL.TernaryLogic(x, y, z, 0x96) : x ^ y ^ z;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<uint> Choose(Vector128<uint> x, Vector128<uint> y, Vector128<uint> z)
	{
		return Vector128.ConditionalSelect(x, y, z);
	}

	// Where the bits of x and y differ, z decides.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<uint> Majority(Vector128<uint> x, Vector128<uint> y, Vector128<uint> z)
	{
		return Avx512F.VL.IsSupported ? Avx512F.VL.TernaryLogic(x, y, z, 0xE8) : Vector128.ConditionalSelect(x ^ y, z, y);
	}

	// Written out rather than through RotateLeftUInt32, whose layers of inlined calls would take the JIT over the number of locals it tracks in the rounds.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<uint> RotateLeft(Vector128<uint> value, [ConstantExpected(Min = 1, Max = 31)] byte count)
	{
		if (Avx512F.VL.IsSupported)
		{
			return Avx512F.VL.RotateLeft(value, count);
		}

		if (AdvSimd.IsSupported)
		{
#pragma warning disable CA1857
			// ReSharper disable once ConstantExpected
			return AdvSimd.ShiftRightAndInsert(AdvSimd.ShiftLeftLogical(value, count), value, (byte)(32 - count));
#pragma warning restore CA1857
		}

		return value << count | value >>> 32 - count;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<uint> ShiftLeft(Vector128<uint> value, int count)
	{
		return value << count;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<uint> ShiftRightLogical(Vector128<uint> value, int count)
	{
		return value >>> count;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<uint> P0(Vector128<uint> value)
	{
		if (RotatesDirectly)
		{
			return Xor(value, RotateLeft(value, 9), RotateLeft(value, 17));
		}

		return value ^ RotateLeft(value ^ RotateLeftByte(value), 9);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<uint> P1(Vector128<uint> value)
	{
		if (RotatesDirectly)
		{
			return Xor(value, RotateLeft(value, 15), RotateLeft(value, 23));
		}

		return value ^ RotateLeft(value ^ RotateLeftByte(value), 15);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> RotateLeftByte(Vector128<uint> value)
	{
		return Vector128.Shuffle(value.AsByte(), Vector128.Create((byte)3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14)).AsUInt32();
	}

	// Transposes words 0 to 3 and 4 to 7 of the state into the two halves of each block.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Store(Vector128<uint> s0, Vector128<uint> s1, Vector128<uint> s2, Vector128<uint> s3, Vector128<uint> s4, Vector128<uint> s5, Vector128<uint> s6, Vector128<uint> s7, ref byte destination)
	{
		Vector128<uint> x0 = s0.ReverseEndianness32();
		Vector128<uint> x1 = s1.ReverseEndianness32();
		Vector128<uint> x2 = s2.ReverseEndianness32();
		Vector128<uint> x3 = s3.ReverseEndianness32();
		Vector128<uint> y0 = s4.ReverseEndianness32();
		Vector128<uint> y1 = s5.ReverseEndianness32();
		Vector128<uint> y2 = s6.ReverseEndianness32();
		Vector128<uint> y3 = s7.ReverseEndianness32();
		VectorTranspose.Transpose(ref x0, ref x1, ref x2, ref x3);
		VectorTranspose.Transpose(ref y0, ref y1, ref y2, ref y3);
		ref uint output = ref Unsafe.As<byte, uint>(ref destination);
		x0.StoreUnsafe(ref output);
		y0.StoreUnsafe(ref output, 4);
		x1.StoreUnsafe(ref output, 8);
		y1.StoreUnsafe(ref output, 12);
		x2.StoreUnsafe(ref output, 16);
		y2.StoreUnsafe(ref output, 20);
		x3.StoreUnsafe(ref output, 24);
		y3.StoreUnsafe(ref output, 28);
	}
}
