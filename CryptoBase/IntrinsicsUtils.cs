using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace CryptoBase;

internal static class IntrinsicsUtils
{
	private static readonly Vector256<byte> Rot8 = Vector256.Create((byte)3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14, 3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14);
	private static readonly Vector256<byte> Rot16 = Vector256.Create((byte)2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13, 2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13);
	private static readonly Vector128<byte> Rot8_128 = Vector128.Create((byte)3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14);
	private static readonly Vector128<byte> Rot16_128 = Vector128.Create((byte)2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13);
	private static readonly Vector128<byte> Rot24_128 = Vector128.Create((byte)1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12);
	private static readonly Vector128<byte> Reverse32 = Vector128.Create((byte)3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12);
	private static readonly Vector128<byte> Reverse_128 = Vector128.Create((byte)15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
	private static readonly Vector256<byte> Reverse32_256 = Vector256.Create((byte)3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12, 19, 18, 17, 16, 23, 22, 21, 20, 27, 26, 25, 24, 31, 30, 29, 28);

	/// <summary>
	/// But AMD is slow...
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static uint AndNot(uint left, uint right)
	{
		if (Bmi1.IsSupported)
		{
			return Bmi1.AndNot(left, right);
		}
		return ~left & right;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<uint> RotateLeftUInt32(this Vector256<uint> value, byte offset)
	{
		return Avx2.Or(Avx2.ShiftLeftLogical(value, offset), Avx2.ShiftRightLogical(value, (byte)(32 - offset)));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<uint> RotateLeftUInt32_8(this Vector256<uint> value)
	{
		return Avx2.Shuffle(value.AsByte(), Rot8).AsUInt32();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<uint> RotateLeftUInt32_16(this Vector256<uint> value)
	{
		return Avx2.Shuffle(value.AsByte(), Rot16).AsUInt32();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<uint> RotateLeftUInt32(this Vector128<uint> value, byte offset)
	{
		return Sse2.Or(Sse2.ShiftLeftLogical(value, offset), Sse2.ShiftRightLogical(value, (byte)(32 - offset)));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<uint> RotateLeftUInt32_8(this Vector128<uint> value)
	{
		return Ssse3.IsSupported ? Ssse3.Shuffle(value.AsByte(), Rot8_128).AsUInt32() : value.RotateLeftUInt32(8);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<uint> RotateLeftUInt32_16(this Vector128<uint> value)
	{
		return Ssse3.IsSupported ? Ssse3.Shuffle(value.AsByte(), Rot16_128).AsUInt32() : value.RotateLeftUInt32(16);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<byte> RotateLeftUInt32_8(this Vector128<byte> value)
	{
		return Ssse3.Shuffle(value, Rot8_128);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<byte> RotateLeftUInt32_16(this Vector128<byte> value)
	{
		return Ssse3.Shuffle(value, Rot16_128);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<byte> RotateLeftUInt32_24(this Vector128<byte> value)
	{
		return Ssse3.Shuffle(value, Rot24_128);
	}

	/// <summary>
	/// destination = source ^ stream
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static unsafe void Xor(byte* stream, byte* source, byte* destination, int length)
	{
		if (Avx.IsSupported && Avx2.IsSupported)
		{
			while (length >= 32)
			{
				var v0 = Avx.LoadVector256(stream);
				var v1 = Avx.LoadVector256(source);
				Avx.Store(destination, Avx2.Xor(v0, v1));

				stream += 32;
				source += 32;
				destination += 32;
				length -= 32;
			}
		}

		if (Sse2.IsSupported)
		{
			while (length >= 16)
			{
				var v0 = Sse2.LoadVector128(stream);
				var v1 = Sse2.LoadVector128(source);
				Sse2.Store(destination, Sse2.Xor(v0, v1));

				stream += 16;
				source += 16;
				destination += 16;
				length -= 16;
			}
		}

		FastUtils.Xor(stream, source, destination, length);
	}

	/// <summary>
	/// destination = source ^ stream
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static unsafe void Xor16(byte* stream, byte* source, byte* destination)
	{
		if (Sse2.IsSupported)
		{
			var v0 = Sse2.LoadVector128(stream);
			var v1 = Sse2.LoadVector128(source);
			Sse2.Store(destination, Sse2.Xor(v0, v1));
		}
		else
		{
			FastUtils.Xor16(stream, source, destination);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<byte> ReverseEndianness32(this Vector128<byte> value)
	{
		return Ssse3.Shuffle(value, Reverse32);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<byte> ReverseEndianness32(this Vector128<uint> value)
	{
		return Ssse3.Shuffle(value.AsByte(), Reverse32);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<byte> ReverseEndianness32(this Vector256<uint> value)
	{
		return Avx2.Shuffle(value.AsByte(), Reverse32_256);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<byte> Xor(this Vector128<byte> a, Vector128<byte> b)
	{
		return Sse2.Xor(a, b);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<byte> Reverse(this Vector128<byte> a)
	{
		return Ssse3.Shuffle(a, Reverse_128);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<ulong> Add(this Vector128<ulong> a, Vector128<ulong> b)
	{
		return Sse2.Add(a, b);
	}

	/// <summary>
	/// Vector128.Create(a, x, b, x)
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<uint> CreateTwoUInt(uint a, uint b)
	{
		if (Sse2.IsSupported)
		{
			var t1 = Vector128.CreateScalarUnsafe(a);
			var t2 = Vector128.CreateScalarUnsafe(b);

			return Sse2.UnpackLow(t1.AsUInt64(), t2.AsUInt64()).AsUInt32();
		}

		return Vector128.Create(a, 0, b, 0);
	}

	/// <summary>
	/// Vector128.Create(a, x, a, x)
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<uint> CreateTwoUInt(uint a)
	{
		if (Sse2.IsSupported)
		{
			var t1 = Vector128.CreateScalarUnsafe(a).AsUInt64();

			return Sse2.UnpackLow(t1, t1).AsUInt32();
		}

		return Vector128.Create(a, 0, a, 0);
	}

	/// <summary>
	/// Vector256.Create(a, x, b, x, c, x, d, x);
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<uint> Create4UInt(uint a, uint b, uint c, uint d)
	{
		if (Avx2.IsSupported)
		{
			var t0 = Avx2.UnpackLow(Vector256.CreateScalarUnsafe(a).AsUInt64(), Vector256.CreateScalarUnsafe(b).AsUInt64()).AsUInt32();
			var t1 = Avx2.UnpackLow(Vector256.CreateScalarUnsafe(c).AsUInt64(), Vector256.CreateScalarUnsafe(d).AsUInt64()).AsUInt32();

			return Avx2.Permute2x128(t0, t1, 0x20);
		}

		return Vector256.Create(a, 0, b, 0, c, 0, d, 0);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<uint> Multiply5(this Vector128<uint> a)
	{
		return Sse2.Add(Sse2.ShiftLeftLogical(a, 2), a);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<uint> Multiply5(this Vector256<uint> a)
	{
		return Avx2.Add(Avx2.ShiftLeftLogical(a, 2), a);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ulong Add2UInt64(this Vector128<ulong> v)
	{
		return v.Add(Sse2.ShiftRightLogical128BitLane(v, 8)).ToScalar();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ulong Add4UInt64(this Vector256<ulong> v)
	{
		v = Avx2.Add(v, Avx2.Permute4x64(v, 0b11_10_11_10));
		v = Avx2.Add(v, Avx2.ShiftRightLogical128BitLane(v, 8));
		return v.ToScalar();
	}
}
