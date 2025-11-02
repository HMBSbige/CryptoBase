namespace CryptoBase;

internal static class IntrinsicsUtils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<T> RotateLeftUInt32<T>(this Vector256<T> value, [ConstantExpected(Min = 0, Max = 32)] byte offset) where T : struct
	{
		return (value.AsUInt32() << offset | value.AsUInt32() >>> 32 - offset).As<uint, T>();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<T> RotateLeftUInt32_8<T>(this Vector256<T> value) where T : struct
	{
		Vector256<byte> vRot8 = Vector256.Create((byte)3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14, 3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14);
		return Avx2.Shuffle(value.AsByte(), vRot8).As<byte, T>();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<T> RotateLeftUInt32_16<T>(this Vector256<T> value) where T : struct
	{
		Vector256<byte> vRot16 = Vector256.Create((byte)2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13, 2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13);
		return Avx2.Shuffle(value.AsByte(), vRot16).As<byte, T>();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<T> RotateLeftUInt32_24<T>(this Vector256<T> value) where T : struct
	{
		Vector256<byte> vRot24 = Vector256.Create((byte)1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12, 1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12);
		return Avx2.Shuffle(value.AsByte(), vRot24).As<byte, T>();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<T> RotateLeftUInt32<T>(this Vector128<T> value, [ConstantExpected(Min = 0, Max = 32)] byte offset) where T : struct
	{
		return (value.AsUInt32() << offset | value.AsUInt32() >>> 32 - offset).As<uint, T>();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<T> RotateLeftUInt32_8<T>(this Vector128<T> value) where T : struct
	{
		Vector128<byte> rot8 = Vector128.Create((byte)3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14);
		return Ssse3.IsSupported ? Ssse3.Shuffle(value.AsByte(), rot8).As<byte, T>() : value.RotateLeftUInt32(8);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<T> RotateLeftUInt32_16<T>(this Vector128<T> value) where T : struct
	{
		Vector128<byte> rot16 = Vector128.Create((byte)2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13);
		return Ssse3.IsSupported ? Ssse3.Shuffle(value.AsByte(), rot16).As<byte, T>() : value.RotateLeftUInt32(16);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<T> RotateLeftUInt32_24<T>(this Vector128<T> value) where T : struct
	{
		Vector128<byte> rot24 = Vector128.Create((byte)1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12);
		return Ssse3.IsSupported ? Ssse3.Shuffle(value.AsByte(), rot24).As<byte, T>() : value.RotateLeftUInt32(24);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<T> ReverseEndianness128<T>(this Vector128<T> a) where T : struct
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
	public static Vector256<T> ReverseEndianness128<T>(this Vector256<T> a) where T : struct
	{
		Vector256<byte> vReverse128 = Vector256.Create((byte)15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16);
		return Avx2.Shuffle(a.AsByte(), vReverse128).As<byte, T>();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<T> ReverseEndianness32<T>(this Vector128<T> value) where T : struct
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
	public static Vector256<T> ReverseEndianness32<T>(this Vector256<T> value) where T : struct
	{
		Vector256<byte> vReverse32 = Vector256.Create((byte)3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12, 19, 18, 17, 16, 23, 22, 21, 20, 27, 26, 25, 24, 31, 30, 29, 28);
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
	public static Vector128<T> Inc128Le<T>(this Vector128<T> nonce) where T : struct
	{
		Vector128<long> v = nonce.AsInt64();
		// v += [1, 0]
		v += Vector128.CreateScalar(1L);

		Vector128<long> carry;

		if (Sse41.IsSupported)
		{
			carry = Sse41.CompareEqual(v, Vector128<long>.Zero);
		}
		else
		{
			Vector128<int> eqZero32 = Sse2.CompareEqual(v.AsInt32(), Vector128<int>.Zero);
			Vector128<int> lane0 = Sse2.Shuffle(eqZero32, 0x00);
			Vector128<int> lane1 = Sse2.Shuffle(eqZero32, 0x55);
			carry = Sse2.And(lane0, lane1).AsInt64();
		}

		carry = Sse2.ShiftLeftLogical128BitLane(carry, 8);
		v = Sse2.Subtract(v, carry);

		return v.As<long, T>();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<T> AddTwo128Le<T>(this Vector256<T> nonce) where T : struct
	{
		Vector256<long> v = nonce.AsInt64();

		Vector256<long> isMinus2 = Avx2.CompareEqual(v, Vector256.Create(-2, 0, -2, 0));
		Vector256<long> isMinus1 = Avx2.CompareEqual(v, Vector256.Create(-1, 0, -1, 0));
		Vector256<long> carry = isMinus2 | isMinus1;
		carry = Avx2.ShiftLeftLogical128BitLane(carry, 8);

		v -= Vector256.Create(-2, 0, -2, 0);
		return (v - carry).As<long, T>();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<T> IncUpper128Le<T>(this Vector256<T> nonce) where T : struct
	{
		Vector256<long> v = nonce.AsInt64();

		Vector256<long> vMinusUpper128Le = Vector256.Create(0, 0, -1, 0);
		Vector256<long> carry = Avx2.CompareEqual(v, vMinusUpper128Le);
		carry = Avx2.ShiftLeftLogical128BitLane(carry, 8);

		v -= vMinusUpper128Le;
		return (v - carry).As<long, T>();
	}
}
