namespace CryptoBase;

internal static class IntrinsicsUtils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<T> RotateLeftUInt32<T>(this Vector512<T> value, [ConstantExpected(Min = 0, Max = 32)] byte offset)
	{
		return Avx512F.RotateLeft(value.AsUInt32(), offset).As<uint, T>();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<T> RotateLeftUInt32<T>(this Vector256<T> value, [ConstantExpected(Min = 0, Max = 32)] byte offset)
	{
		if (Avx512F.VL.IsSupported)
		{
			return Avx512F.VL.RotateLeft(value.AsUInt32(), offset).As<uint, T>();
		}

		return (value.AsUInt32() << offset | value.AsUInt32() >>> 32 - offset).As<uint, T>();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<T> RotateLeftUInt32_8<T>(this Vector256<T> value)
	{
		if (Avx512F.VL.IsSupported)
		{
			return Avx512F.VL.RotateLeft(value.AsUInt32(), 8).As<uint, T>();
		}

		Vector256<byte> vRot8 = Vector256.Create
		(
			(byte)3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14,
			3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14
		);
		return Avx2.Shuffle(value.AsByte(), vRot8).As<byte, T>();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<T> RotateLeftUInt32_16<T>(this Vector256<T> value)
	{
		if (Avx512F.VL.IsSupported)
		{
			return Avx512F.VL.RotateLeft(value.AsUInt32(), 16).As<uint, T>();
		}

		Vector256<byte> vRot16 = Vector256.Create
		(
			(byte)2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13,
			2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13
		);
		return Avx2.Shuffle(value.AsByte(), vRot16).As<byte, T>();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<T> RotateLeftUInt32_24<T>(this Vector256<T> value)
	{
		if (Avx512F.VL.IsSupported)
		{
			return Avx512F.VL.RotateLeft(value.AsUInt32(), 24).As<uint, T>();
		}

		Vector256<byte> vRot24 = Vector256.Create
		(
			(byte)1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12,
			1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12
		);
		return Avx2.Shuffle(value.AsByte(), vRot24).As<byte, T>();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<T> RotateLeftUInt32<T>(this Vector128<T> value, [ConstantExpected(Min = 0, Max = 32)] byte offset)
	{
		if (Avx512F.VL.IsSupported)
		{
			return Avx512F.VL.RotateLeft(value.AsUInt32(), offset).As<uint, T>();
		}

		return (value.AsUInt32() << offset | value.AsUInt32() >>> 32 - offset).As<uint, T>();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<T> RotateLeftUInt32_8<T>(this Vector128<T> value)
	{
		if (Avx512F.VL.IsSupported)
		{
			return Avx512F.VL.RotateLeft(value.AsUInt32(), 8).As<uint, T>();
		}

		if (Ssse3.IsSupported)
		{
			Vector128<byte> rot8 = Vector128.Create((byte)3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14);
			return Ssse3.Shuffle(value.AsByte(), rot8).As<byte, T>();
		}

		return value.RotateLeftUInt32(8);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<T> RotateLeftUInt32_16<T>(this Vector128<T> value)
	{
		if (Avx512F.VL.IsSupported)
		{
			return Avx512F.VL.RotateLeft(value.AsUInt32(), 16).As<uint, T>();
		}

		if (Ssse3.IsSupported)
		{
			Vector128<byte> rot16 = Vector128.Create((byte)2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13);
			return Ssse3.Shuffle(value.AsByte(), rot16).As<byte, T>();
		}

		return value.RotateLeftUInt32(16);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<T> RotateLeftUInt32_24<T>(this Vector128<T> value)
	{
		if (Avx512F.VL.IsSupported)
		{
			return Avx512F.VL.RotateLeft(value.AsUInt32(), 24).As<uint, T>();
		}

		if (Ssse3.IsSupported)
		{
			Vector128<byte> rot24 = Vector128.Create((byte)1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12);
			return Ssse3.Shuffle(value.AsByte(), rot24).As<byte, T>();
		}

		return value.RotateLeftUInt32(24);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<T> ReverseEndianness128<T>(this Vector128<T> a)
	{
		if (Ssse3.IsSupported)
		{
			Vector128<byte> reverse128 = Vector128.Create((byte)15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
			return Ssse3.Shuffle(a.AsByte(), reverse128).As<byte, T>();
		}

		Vector128<ushort> v = a.AsUInt16();
		v = v << 8 | v >>> 8;

		v = Sse2.ShuffleLow(v, 0b00_01_10_11);
		v = Sse2.ShuffleHigh(v, 0b00_01_10_11);

		return Sse2.Shuffle(v.AsUInt32(), 0b01_00_11_10).As<uint, T>();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<T> ReverseEndianness128<T>(this Vector256<T> a)
	{
		Vector256<byte> vReverse128 = Vector256.Create
		(
			(byte)15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
			15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
		);
		return Avx2.Shuffle(a.AsByte(), vReverse128).As<byte, T>();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<T> ReverseEndianness128<T>(this Vector512<T> a)
	{
		Vector512<byte> vReverse128 = Vector512.Create
		(
			(byte)15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
			15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
			15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
			15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
		);

		return Avx512BW.Shuffle(a.AsByte(), vReverse128).As<byte, T>();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<T> ReverseEndianness32<T>(this Vector128<T> value)
	{
		if (Ssse3.IsSupported)
		{
			Vector128<byte> reverse32 = Vector128.Create((byte)3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12);
			return Ssse3.Shuffle(value.AsByte(), reverse32).As<byte, T>();
		}

		Vector128<ushort> v = value.AsUInt16();
		v = v << 8 | v >>> 8;

		v = Sse2.ShuffleLow(v, 0b10_11_00_01);
		v = Sse2.ShuffleHigh(v, 0b10_11_00_01);

		return v.As<ushort, T>();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<T> ReverseEndianness32<T>(this Vector256<T> value)
	{
		Vector256<byte> vReverse32 = Vector256.Create
		(
			(byte)3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12,
			3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12
		);
		return Avx2.Shuffle(value.AsByte(), vReverse32).As<byte, T>();
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
	public static ulong Add2UInt64(this Vector128<ulong> v)
	{
		return (v + Sse2.ShiftRightLogical128BitLane(v, 8)).ToScalar();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ulong Add4UInt64(this Vector256<ulong> v)
	{
		v = Avx2.Add(v, Avx2.Permute4x64(v, 0b11_10_11_10));
		v = Avx2.Add(v, Avx2.ShiftRightLogical128BitLane(v, 8));
		return v.ToScalar();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<T> Inc128Le<T>(this Vector128<T> nonce)
	{
		Vector128<long> v = nonce.AsInt64();
		Vector128<long> m1 = Vector128.Create(-1L, 0L);

		Vector128<long> carry;

		if (Sse41.IsSupported)
		{
			carry = Sse41.CompareEqual(v, m1);
		}
		else
		{
			Vector128<int> eqFF32 = Sse2.CompareEqual(v.AsInt32(), Vector128<int>.AllBitsSet);
			Vector128<int> lowD0 = Sse2.Shuffle(eqFF32, 0x00);
			Vector128<int> lowD1 = Sse2.Shuffle(eqFF32, 0x55);
			carry = (lowD0 & lowD1).AsInt64();
		}

		carry = Sse2.ShiftLeftLogical128BitLane(carry, 8);

		v -= m1;
		v -= carry;

		return v.As<long, T>();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<T> AddTwo128Le<T>(this Vector256<T> nonce)
	{
		Vector256<long> v = nonce.AsInt64();
		Vector256<long> signBit = Vector256.Create(0x8000_0000_0000_0000UL).AsInt64();
		Vector256<long> thrX = Vector256.Create
		(
			ulong.MaxValue - 2UL ^ 0x8000_0000_0000_0000UL, ulong.MaxValue ^ 0x8000_0000_0000_0000UL,
			ulong.MaxValue - 2UL ^ 0x8000_0000_0000_0000UL, ulong.MaxValue ^ 0x8000_0000_0000_0000UL
		).AsInt64();

		Vector256<long> sum = v + Vector256.Create(2, 0, 2, 0);

		Vector256<long> vX = v ^ signBit;
		Vector256<long> carry = Avx2.CompareGreaterThan(vX, thrX);
		carry = Avx2.ShiftLeftLogical128BitLane(carry.AsByte(), 8).AsInt64();

		return (sum - carry).As<long, T>();
	}

	/// <summary>
	/// 高位 128-bit 小端整数加 1，注意仅适用于进位时低位不为0的情况
	/// 如果需要通用的：
	/// var carry = Avx2.CompareEqual(v, Vector256.Create(-1L)); carry &amp;= vMinusUpper128Le;
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<T> IncUpper128Le<T>(this Vector256<T> nonce)
	{
		Vector256<long> v = nonce.AsInt64();

		Vector256<long> vMinusUpper128Le = Vector256.Create(0, 0, -1, 0);
		Vector256<long> carry = Avx2.CompareEqual(v, vMinusUpper128Le);
		carry = Avx2.ShiftLeftLogical128BitLane(carry, 8);

		v -= vMinusUpper128Le;
		return (v - carry).As<long, T>();
	}

	/// <summary>
	/// [v0,v1,v2,v3] => [v0+4,v1+4,v2+4,v3+4]
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<T> AddFour128Le<T>(this Vector512<T> nonce)
	{
		Vector512<ulong> v = nonce.AsUInt64();
		Vector512<ulong> thr = Vector512.Create
		(
			ulong.MaxValue - 4UL, 0xFFFF_FFFF_FFFF_FFFFUL,
			ulong.MaxValue - 4UL, 0xFFFF_FFFF_FFFF_FFFFUL,
			ulong.MaxValue - 4UL, 0xFFFF_FFFF_FFFF_FFFFUL,
			ulong.MaxValue - 4UL, 0xFFFF_FFFF_FFFF_FFFFUL
		);

		Vector512<ulong> sum = v + Vector512.Create(4, 0, 4, 0, 4, 0, 4, 0).AsUInt64();

		Vector512<ulong> carry = Vector512.GreaterThan(v, thr);
		carry = Avx512BW.ShiftLeftLogical128BitLane(carry.AsByte(), 8).AsUInt64();

		return (sum - carry).As<ulong, T>();
	}

	/// <summary>
	/// [v0,v1,v2,v3] => [v0+0,v1+1,v2+2,v3+3]
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<T> Add128Le0123<T>(this Vector512<T> nonce)
	{
		Vector512<ulong> v = nonce.AsUInt64();
		Vector512<ulong> thr = Vector512.Create
		(
			ulong.MaxValue - 0UL, 0xFFFF_FFFF_FFFF_FFFFUL,
			ulong.MaxValue - 1UL, 0xFFFF_FFFF_FFFF_FFFFUL,
			ulong.MaxValue - 2UL, 0xFFFF_FFFF_FFFF_FFFFUL,
			ulong.MaxValue - 3UL, 0xFFFF_FFFF_FFFF_FFFFUL
		);

		Vector512<ulong> sum = v + Vector512.Create(0, 0, 1, 0, 2, 0, 3, 0).AsUInt64();

		Vector512<ulong> carry = Vector512.GreaterThan(v, thr);
		carry = Avx512BW.ShiftLeftLogical128BitLane(carry.AsByte(), 8).AsUInt64();

		return (sum - carry).As<ulong, T>();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Add<TLeft, TRight>(this ref Vector512X16<TLeft> left, in Vector512X16<TRight> right)
	{
		left.V0 += right.V0.As<TRight, TLeft>();
		left.V1 += right.V1.As<TRight, TLeft>();
		left.V2 += right.V2.As<TRight, TLeft>();
		left.V3 += right.V3.As<TRight, TLeft>();
		left.V4 += right.V4.As<TRight, TLeft>();
		left.V5 += right.V5.As<TRight, TLeft>();
		left.V6 += right.V6.As<TRight, TLeft>();
		left.V7 += right.V7.As<TRight, TLeft>();
		left.V8 += right.V8.As<TRight, TLeft>();
		left.V9 += right.V9.As<TRight, TLeft>();
		left.V10 += right.V10.As<TRight, TLeft>();
		left.V11 += right.V11.As<TRight, TLeft>();
		left.V12 += right.V12.As<TRight, TLeft>();
		left.V13 += right.V13.As<TRight, TLeft>();
		left.V14 += right.V14.As<TRight, TLeft>();
		left.V15 += right.V15.As<TRight, TLeft>();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Xor<TLeft, TRight>(this ref Vector512X16<TLeft> left, in Vector512X16<TRight> right)
	{
		left.V0 ^= right.V0.As<TRight, TLeft>();
		left.V1 ^= right.V1.As<TRight, TLeft>();
		left.V2 ^= right.V2.As<TRight, TLeft>();
		left.V3 ^= right.V3.As<TRight, TLeft>();
		left.V4 ^= right.V4.As<TRight, TLeft>();
		left.V5 ^= right.V5.As<TRight, TLeft>();
		left.V6 ^= right.V6.As<TRight, TLeft>();
		left.V7 ^= right.V7.As<TRight, TLeft>();
		left.V8 ^= right.V8.As<TRight, TLeft>();
		left.V9 ^= right.V9.As<TRight, TLeft>();
		left.V10 ^= right.V10.As<TRight, TLeft>();
		left.V11 ^= right.V11.As<TRight, TLeft>();
		left.V12 ^= right.V12.As<TRight, TLeft>();
		left.V13 ^= right.V13.As<TRight, TLeft>();
		left.V14 ^= right.V14.As<TRight, TLeft>();
		left.V15 ^= right.V15.As<TRight, TLeft>();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Transpose(this ref Vector512X16<uint> x)
	{
		Vector512<uint> a0 = Avx512F.UnpackLow(x.V0, x.V1);
		Vector512<uint> a1 = Avx512F.UnpackHigh(x.V0, x.V1);
		Vector512<uint> a2 = Avx512F.UnpackLow(x.V2, x.V3);
		Vector512<uint> a3 = Avx512F.UnpackHigh(x.V2, x.V3);
		Vector512<uint> a4 = Avx512F.UnpackLow(x.V4, x.V5);
		Vector512<uint> a5 = Avx512F.UnpackHigh(x.V4, x.V5);
		Vector512<uint> a6 = Avx512F.UnpackLow(x.V6, x.V7);
		Vector512<uint> a7 = Avx512F.UnpackHigh(x.V6, x.V7);
		Vector512<uint> a8 = Avx512F.UnpackLow(x.V8, x.V9);
		Vector512<uint> a9 = Avx512F.UnpackHigh(x.V8, x.V9);
		Vector512<uint> a10 = Avx512F.UnpackLow(x.V10, x.V11);
		Vector512<uint> a11 = Avx512F.UnpackHigh(x.V10, x.V11);
		Vector512<uint> a12 = Avx512F.UnpackLow(x.V12, x.V13);
		Vector512<uint> a13 = Avx512F.UnpackHigh(x.V12, x.V13);
		Vector512<uint> a14 = Avx512F.UnpackLow(x.V14, x.V15);
		Vector512<uint> a15 = Avx512F.UnpackHigh(x.V14, x.V15);

		x.V0 = Avx512F.UnpackLow(a0.AsUInt64(), a2.AsUInt64()).AsUInt32();
		x.V1 = Avx512F.UnpackHigh(a0.AsUInt64(), a2.AsUInt64()).AsUInt32();
		x.V2 = Avx512F.UnpackLow(a1.AsUInt64(), a3.AsUInt64()).AsUInt32();
		x.V3 = Avx512F.UnpackHigh(a1.AsUInt64(), a3.AsUInt64()).AsUInt32();
		x.V4 = Avx512F.UnpackLow(a4.AsUInt64(), a6.AsUInt64()).AsUInt32();
		x.V5 = Avx512F.UnpackHigh(a4.AsUInt64(), a6.AsUInt64()).AsUInt32();
		x.V6 = Avx512F.UnpackLow(a5.AsUInt64(), a7.AsUInt64()).AsUInt32();
		x.V7 = Avx512F.UnpackHigh(a5.AsUInt64(), a7.AsUInt64()).AsUInt32();
		x.V8 = Avx512F.UnpackLow(a8.AsUInt64(), a10.AsUInt64()).AsUInt32();
		x.V9 = Avx512F.UnpackHigh(a8.AsUInt64(), a10.AsUInt64()).AsUInt32();
		x.V10 = Avx512F.UnpackLow(a9.AsUInt64(), a11.AsUInt64()).AsUInt32();
		x.V11 = Avx512F.UnpackHigh(a9.AsUInt64(), a11.AsUInt64()).AsUInt32();
		x.V12 = Avx512F.UnpackLow(a12.AsUInt64(), a14.AsUInt64()).AsUInt32();
		x.V13 = Avx512F.UnpackHigh(a12.AsUInt64(), a14.AsUInt64()).AsUInt32();
		x.V14 = Avx512F.UnpackLow(a13.AsUInt64(), a15.AsUInt64()).AsUInt32();
		x.V15 = Avx512F.UnpackHigh(a13.AsUInt64(), a15.AsUInt64()).AsUInt32();

		a0 = Avx512F.Shuffle4x128(x.V0, x.V4, 0x88);
		a1 = Avx512F.Shuffle4x128(x.V1, x.V5, 0x88);
		a2 = Avx512F.Shuffle4x128(x.V2, x.V6, 0x88);
		a3 = Avx512F.Shuffle4x128(x.V3, x.V7, 0x88);
		a4 = Avx512F.Shuffle4x128(x.V0, x.V4, 0xDD);
		a5 = Avx512F.Shuffle4x128(x.V1, x.V5, 0xDD);
		a6 = Avx512F.Shuffle4x128(x.V2, x.V6, 0xDD);
		a7 = Avx512F.Shuffle4x128(x.V3, x.V7, 0xDD);
		a8 = Avx512F.Shuffle4x128(x.V8, x.V12, 0x88);
		a9 = Avx512F.Shuffle4x128(x.V9, x.V13, 0x88);
		a10 = Avx512F.Shuffle4x128(x.V10, x.V14, 0x88);
		a11 = Avx512F.Shuffle4x128(x.V11, x.V15, 0x88);
		a12 = Avx512F.Shuffle4x128(x.V8, x.V12, 0xDD);
		a13 = Avx512F.Shuffle4x128(x.V9, x.V13, 0xDD);
		a14 = Avx512F.Shuffle4x128(x.V10, x.V14, 0xDD);
		a15 = Avx512F.Shuffle4x128(x.V11, x.V15, 0xDD);

		x.V0 = Avx512F.Shuffle4x128(a0, a8, 0x88);
		x.V1 = Avx512F.Shuffle4x128(a1, a9, 0x88);
		x.V2 = Avx512F.Shuffle4x128(a2, a10, 0x88);
		x.V3 = Avx512F.Shuffle4x128(a3, a11, 0x88);
		x.V4 = Avx512F.Shuffle4x128(a4, a12, 0x88);
		x.V5 = Avx512F.Shuffle4x128(a5, a13, 0x88);
		x.V6 = Avx512F.Shuffle4x128(a6, a14, 0x88);
		x.V7 = Avx512F.Shuffle4x128(a7, a15, 0x88);
		x.V8 = Avx512F.Shuffle4x128(a0, a8, 0xDD);
		x.V9 = Avx512F.Shuffle4x128(a1, a9, 0xDD);
		x.V10 = Avx512F.Shuffle4x128(a2, a10, 0xDD);
		x.V11 = Avx512F.Shuffle4x128(a3, a11, 0xDD);
		x.V12 = Avx512F.Shuffle4x128(a4, a12, 0xDD);
		x.V13 = Avx512F.Shuffle4x128(a5, a13, 0xDD);
		x.V14 = Avx512F.Shuffle4x128(a6, a14, 0xDD);
		x.V15 = Avx512F.Shuffle4x128(a7, a15, 0xDD);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Add<TLeft, TRight>(this ref Vector256X16<TLeft> left, in Vector256X16<TRight> right)
	{
		left.V0 += right.V0.As<TRight, TLeft>();
		left.V1 += right.V1.As<TRight, TLeft>();
		left.V2 += right.V2.As<TRight, TLeft>();
		left.V3 += right.V3.As<TRight, TLeft>();
		left.V4 += right.V4.As<TRight, TLeft>();
		left.V5 += right.V5.As<TRight, TLeft>();
		left.V6 += right.V6.As<TRight, TLeft>();
		left.V7 += right.V7.As<TRight, TLeft>();
		left.V8 += right.V8.As<TRight, TLeft>();
		left.V9 += right.V9.As<TRight, TLeft>();
		left.V10 += right.V10.As<TRight, TLeft>();
		left.V11 += right.V11.As<TRight, TLeft>();
		left.V12 += right.V12.As<TRight, TLeft>();
		left.V13 += right.V13.As<TRight, TLeft>();
		left.V14 += right.V14.As<TRight, TLeft>();
		left.V15 += right.V15.As<TRight, TLeft>();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Xor<TLeft, TRight>(this ref Vector256X16<TLeft> left, in Vector256X16<TRight> right)
	{
		left.V0 ^= right.V0.As<TRight, TLeft>();
		left.V1 ^= right.V1.As<TRight, TLeft>();
		left.V2 ^= right.V2.As<TRight, TLeft>();
		left.V3 ^= right.V3.As<TRight, TLeft>();
		left.V4 ^= right.V4.As<TRight, TLeft>();
		left.V5 ^= right.V5.As<TRight, TLeft>();
		left.V6 ^= right.V6.As<TRight, TLeft>();
		left.V7 ^= right.V7.As<TRight, TLeft>();
		left.V8 ^= right.V8.As<TRight, TLeft>();
		left.V9 ^= right.V9.As<TRight, TLeft>();
		left.V10 ^= right.V10.As<TRight, TLeft>();
		left.V11 ^= right.V11.As<TRight, TLeft>();
		left.V12 ^= right.V12.As<TRight, TLeft>();
		left.V13 ^= right.V13.As<TRight, TLeft>();
		left.V14 ^= right.V14.As<TRight, TLeft>();
		left.V15 ^= right.V15.As<TRight, TLeft>();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Transpose(this ref Vector256X16<uint> x)
	{
		Transpose(ref x.V0, ref x.V1, ref x.V2, ref x.V3, ref x.V4, ref x.V5, ref x.V6, ref x.V7);
		Transpose(ref x.V8, ref x.V9, ref x.V10, ref x.V11, ref x.V12, ref x.V13, ref x.V14, ref x.V15);
		// 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
		// =>
		// 0 8 1 9 2 10 3 11 4 12 5 13 6 14 7 15
		Vector256X16<uint> t = x;
		x.V1 = t.V8;
		x.V2 = t.V1;
		x.V3 = t.V9;
		x.V4 = t.V2;
		x.V5 = t.V10;
		x.V6 = t.V3;
		x.V7 = t.V11;
		x.V8 = t.V4;
		x.V9 = t.V12;
		x.V10 = t.V5;
		x.V11 = t.V13;
		x.V12 = t.V6;
		x.V13 = t.V14;
		x.V14 = t.V7;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Transpose
	(
		ref Vector256<uint> x0, ref Vector256<uint> x1, ref Vector256<uint> x2, ref Vector256<uint> x3,
		ref Vector256<uint> x4, ref Vector256<uint> x5, ref Vector256<uint> x6, ref Vector256<uint> x7
	)
	{
		Vector256<uint> t0 = Avx2.UnpackLow(x0, x1);
		Vector256<uint> t1 = Avx2.UnpackLow(x2, x3);
		Vector256<uint> t2 = Avx2.UnpackHigh(x0, x1);
		Vector256<uint> t3 = Avx2.UnpackHigh(x2, x3);
		Vector256<uint> t4 = Avx2.UnpackLow(x4, x5);
		Vector256<uint> t5 = Avx2.UnpackLow(x6, x7);
		Vector256<uint> t6 = Avx2.UnpackHigh(x4, x5);
		Vector256<uint> t7 = Avx2.UnpackHigh(x6, x7);

		Vector256<uint> b0 = Avx2.UnpackLow(t0.AsUInt64(), t1.AsUInt64()).AsUInt32();
		Vector256<uint> b1 = Avx2.UnpackHigh(t0.AsUInt64(), t1.AsUInt64()).AsUInt32();
		Vector256<uint> b2 = Avx2.UnpackLow(t2.AsUInt64(), t3.AsUInt64()).AsUInt32();
		Vector256<uint> b3 = Avx2.UnpackHigh(t2.AsUInt64(), t3.AsUInt64()).AsUInt32();
		Vector256<uint> b4 = Avx2.UnpackLow(t4.AsUInt64(), t5.AsUInt64()).AsUInt32();
		Vector256<uint> b5 = Avx2.UnpackHigh(t4.AsUInt64(), t5.AsUInt64()).AsUInt32();
		Vector256<uint> b6 = Avx2.UnpackLow(t6.AsUInt64(), t7.AsUInt64()).AsUInt32();
		Vector256<uint> b7 = Avx2.UnpackHigh(t6.AsUInt64(), t7.AsUInt64()).AsUInt32();

		x0 = Avx2.Permute2x128(b0, b4, 0x20);
		x4 = Avx2.Permute2x128(b0, b4, 0x31);
		x1 = Avx2.Permute2x128(b1, b5, 0x20);
		x5 = Avx2.Permute2x128(b1, b5, 0x31);
		x2 = Avx2.Permute2x128(b2, b6, 0x20);
		x6 = Avx2.Permute2x128(b2, b6, 0x31);
		x3 = Avx2.Permute2x128(b3, b7, 0x20);
		x7 = Avx2.Permute2x128(b3, b7, 0x31);
	}
}
