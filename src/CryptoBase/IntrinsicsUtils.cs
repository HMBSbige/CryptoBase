using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace CryptoBase;

internal static partial class IntrinsicsUtils
{
	private static readonly Vector128<byte> Rot8 = Vector128.Create((byte)3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14);
	private static readonly Vector128<byte> Rot16 = Vector128.Create((byte)2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13);
	private static readonly Vector128<byte> Rot24 = Vector128.Create((byte)1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12);
	private static readonly Vector128<byte> Reverse32 = Vector128.Create((byte)3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12);
	private static readonly Vector128<byte> Reverse128 = Vector128.Create((byte)15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
	private static readonly Vector128<long> MinusOne128Le = Vector128.Create(-1, 0);

	private static readonly Vector256<byte> VRot8 = Vector256.Create((byte)3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14, 3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14);
	private static readonly Vector256<byte> VRot16 = Vector256.Create((byte)2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13, 2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13);
	private static readonly Vector256<byte> VRot24 = Vector256.Create((byte)1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12, 1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12);
	private static readonly Vector256<byte> VReverse32 = Vector256.Create((byte)3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12, 19, 18, 17, 16, 23, 22, 21, 20, 27, 26, 25, 24, 31, 30, 29, 28);
	private static readonly Vector256<byte> VReverse128 = Vector256.Create((byte)15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16);
	private static readonly Vector256<long> VMinusTwo128Le = Vector256.Create(-2, 0, -2, 0);
	private static readonly Vector256<long> VMinusUpper128Le = Vector256.Create(0, 0, -1, 0);

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
	public static Vector256<T> RotateLeftUInt32<T>(this Vector256<T> value, byte offset) where T : struct
	{
		return Avx2.Or(Avx2.ShiftLeftLogical(value.AsUInt32(), offset), Avx2.ShiftRightLogical(value.AsUInt32(), (byte)(32 - offset))).As<uint, T>();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<T> RotateLeftUInt32_8<T>(this Vector256<T> value) where T : struct
	{
		return Avx2.Shuffle(value.AsByte(), VRot8).As<byte, T>();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<T> RotateLeftUInt32_16<T>(this Vector256<T> value) where T : struct
	{
		return Avx2.Shuffle(value.AsByte(), VRot16).As<byte, T>();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<T> RotateLeftUInt32_24<T>(this Vector256<T> value) where T : struct
	{
		return Avx2.Shuffle(value.AsByte(), VRot24).As<byte, T>();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<T> RotateLeftUInt32<T>(this Vector128<T> value, byte offset) where T : struct
	{
		return Sse2.Or(Sse2.ShiftLeftLogical(value.AsUInt32(), offset), Sse2.ShiftRightLogical(value.AsUInt32(), (byte)(32 - offset))).As<uint, T>();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<T> RotateLeftUInt32_8<T>(this Vector128<T> value) where T : struct
	{
		return Ssse3.IsSupported ? Ssse3.Shuffle(value.AsByte(), Rot8).As<byte, T>() : value.RotateLeftUInt32(8);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<T> RotateLeftUInt32_16<T>(this Vector128<T> value) where T : struct
	{
		return Ssse3.IsSupported ? Ssse3.Shuffle(value.AsByte(), Rot16).As<byte, T>() : value.RotateLeftUInt32(16);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<T> RotateLeftUInt32_24<T>(this Vector128<T> value) where T : struct
	{
		return Ssse3.IsSupported ? Ssse3.Shuffle(value.AsByte(), Rot24).As<byte, T>() : value.RotateLeftUInt32(24);
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
				Vector256<byte> v0 = Avx.LoadVector256(stream);
				Vector256<byte> v1 = Avx.LoadVector256(source);
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
				Vector128<byte> v0 = Sse2.LoadVector128(stream);
				Vector128<byte> v1 = Sse2.LoadVector128(source);
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
			Vector128<byte> v0 = Sse2.LoadVector128(stream);
			Vector128<byte> v1 = Sse2.LoadVector128(source);
			Sse2.Store(destination, Sse2.Xor(v0, v1));
		}
		else
		{
			FastUtils.Xor16(stream, source, destination);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<T> ReverseEndianness128<T>(this Vector128<T> a) where T : struct
	{
		return Ssse3.Shuffle(a.AsByte(), Reverse128).As<byte, T>();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<T> ReverseEndianness128<T>(this Vector256<T> a) where T : struct
	{
		return Avx2.Shuffle(a.AsByte(), VReverse128).As<byte, T>();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<T> ReverseEndianness32<T>(this Vector128<T> value) where T : struct
	{
		return Ssse3.Shuffle(value.AsByte(), Reverse32).As<byte, T>();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<T> ReverseEndianness32<T>(this Vector256<T> value) where T : struct
	{
		return Avx2.Shuffle(value.AsByte(), VReverse32).As<byte, T>();
	}

	/// <summary>
	/// Vector128.Create(a, x, b, x)
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<uint> CreateTwoUInt(uint a, uint b)
	{
		if (Sse2.IsSupported)
		{
			Vector128<uint> t1 = Vector128.CreateScalarUnsafe(a);
			Vector128<uint> t2 = Vector128.CreateScalarUnsafe(b);

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
			Vector128<ulong> t1 = Vector128.CreateScalarUnsafe(a).AsUInt64();

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
			Vector256<uint> t0 = Avx2.UnpackLow(Vector256.CreateScalarUnsafe(a).AsUInt64(), Vector256.CreateScalarUnsafe(b).AsUInt64()).AsUInt32();
			Vector256<uint> t1 = Avx2.UnpackLow(Vector256.CreateScalarUnsafe(c).AsUInt64(), Vector256.CreateScalarUnsafe(d).AsUInt64()).AsUInt32();

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

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<T> Inc128Le<T>(this Vector128<T> nonce) where T : struct
	{
		Vector128<long> v = nonce.AsInt64();
		Vector128<long> t = Sse41.CompareEqual(v, MinusOne128Le);
		v = Sse2.Subtract(v, MinusOne128Le);
		t = Sse2.ShiftLeftLogical128BitLane(t, 8);
		return Sse2.Subtract(v, t).As<long, T>();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<T> AddTwo128Le<T>(this Vector256<T> nonce) where T : struct
	{
		Vector256<long> v = nonce.AsInt64();
		Vector256<long> t = Avx2.CompareEqual(v, VMinusTwo128Le);
		v = Avx2.Subtract(v, VMinusTwo128Le);
		t = Avx2.ShiftLeftLogical128BitLane(t, 8);
		return Avx2.Subtract(v, t).As<long, T>();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<T> IncUpper128Le<T>(this Vector256<T> nonce) where T : struct
	{
		Vector256<long> v = nonce.AsInt64();
		Vector256<long> t = Avx2.CompareEqual(v, VMinusUpper128Le);
		v = Avx2.Subtract(v, VMinusUpper128Le);
		t = Avx2.ShiftLeftLogical128BitLane(t, 8);
		return Avx2.Subtract(v, t).As<long, T>();
	}
}
