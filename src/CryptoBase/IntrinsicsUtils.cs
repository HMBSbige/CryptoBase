namespace CryptoBase;

internal static class IntrinsicsUtils
{
	extension<T>(Vector512<T> value)
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector512<T> RotateLeftUInt32([ConstantExpected(Min = 0, Max = 32)] byte offset)
		{
			return Avx512F.RotateLeft(value.AsUInt32(), offset).As<uint, T>();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector512<T> ReverseEndianness128()
		{
			Vector512<byte> vReverse128 = Vector512.Create
			(
				(byte)15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
				15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
				15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
				15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
			);

			return Avx512BW.Shuffle(value.AsByte(), vReverse128).As<byte, T>();
		}
	}

	extension<T>(Vector256<T> value)
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector256<T> RotateLeftUInt32([ConstantExpected(Min = 0, Max = 32)] byte offset)
		{
			if (Avx512F.VL.IsSupported)
			{
				return Avx512F.VL.RotateLeft(value.AsUInt32(), offset).As<uint, T>();
			}

			return (value.AsUInt32() << offset | value.AsUInt32() >>> 32 - offset).As<uint, T>();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector256<T> RotateLeftUInt32_8()
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
		public Vector256<T> RotateLeftUInt32_16()
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
		public Vector256<T> RotateLeftUInt32_24()
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
		public Vector256<T> ReverseEndianness128()
		{
			Vector256<byte> vReverse128 = Vector256.Create
			(
				(byte)15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
				15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
			);
			return Avx2.Shuffle(value.AsByte(), vReverse128).As<byte, T>();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector256<T> ReverseEndianness32()
		{
			Vector256<byte> vReverse32 = Vector256.Create
			(
				(byte)3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12,
				3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12
			);
			return Avx2.Shuffle(value.AsByte(), vReverse32).As<byte, T>();
		}
	}

	extension<T>(Vector128<T> value)
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector128<T> RotateLeftUInt32([ConstantExpected(Min = 0, Max = 32)] byte offset)
		{
			if (Avx512F.VL.IsSupported)
			{
				return Avx512F.VL.RotateLeft(value.AsUInt32(), offset).As<uint, T>();
			}

			return (value.AsUInt32() << offset | value.AsUInt32() >>> 32 - offset).As<uint, T>();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector128<T> RotateLeftUInt32_8()
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
		public Vector128<T> RotateLeftUInt32_16()
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
		public Vector128<T> RotateLeftUInt32_24()
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
		public Vector128<T> ReverseEndianness128()
		{
			if (Ssse3.IsSupported)
			{
				Vector128<byte> reverse128 = Vector128.Create((byte)15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
				return Ssse3.Shuffle(value.AsByte(), reverse128).As<byte, T>();
			}

			Vector128<ushort> v = value.AsUInt16();
			v = v << 8 | v >>> 8;

			v = Sse2.ShuffleLow(v, 0b00_01_10_11);
			v = Sse2.ShuffleHigh(v, 0b00_01_10_11);

			return Sse2.Shuffle(v.AsUInt32(), 0b01_00_11_10).As<uint, T>();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector128<T> ReverseEndianness32()
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
		v += Avx2.Permute4x64(v, 0b11_10_11_10);
		v += Avx2.ShiftRightLogical128BitLane(v, 8);
		return v.ToScalar();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Transpose(this ref VectorBuffer1024 x)
	{
		Vector512<uint> a0 = Avx512F.UnpackLow(x.V512_0.AsUInt32(), x.V512_1.AsUInt32());
		Vector512<uint> a1 = Avx512F.UnpackHigh(x.V512_0.AsUInt32(), x.V512_1.AsUInt32());
		Vector512<uint> a2 = Avx512F.UnpackLow(x.V512_2.AsUInt32(), x.V512_3.AsUInt32());
		Vector512<uint> a3 = Avx512F.UnpackHigh(x.V512_2.AsUInt32(), x.V512_3.AsUInt32());
		Vector512<uint> a4 = Avx512F.UnpackLow(x.V512_4.AsUInt32(), x.V512_5.AsUInt32());
		Vector512<uint> a5 = Avx512F.UnpackHigh(x.V512_4.AsUInt32(), x.V512_5.AsUInt32());
		Vector512<uint> a6 = Avx512F.UnpackLow(x.V512_6.AsUInt32(), x.V512_7.AsUInt32());
		Vector512<uint> a7 = Avx512F.UnpackHigh(x.V512_6.AsUInt32(), x.V512_7.AsUInt32());
		Vector512<uint> a8 = Avx512F.UnpackLow(x.V512_8.AsUInt32(), x.V512_9.AsUInt32());
		Vector512<uint> a9 = Avx512F.UnpackHigh(x.V512_8.AsUInt32(), x.V512_9.AsUInt32());
		Vector512<uint> a10 = Avx512F.UnpackLow(x.V512_10.AsUInt32(), x.V512_11.AsUInt32());
		Vector512<uint> a11 = Avx512F.UnpackHigh(x.V512_10.AsUInt32(), x.V512_11.AsUInt32());
		Vector512<uint> a12 = Avx512F.UnpackLow(x.V512_12.AsUInt32(), x.V512_13.AsUInt32());
		Vector512<uint> a13 = Avx512F.UnpackHigh(x.V512_12.AsUInt32(), x.V512_13.AsUInt32());
		Vector512<uint> a14 = Avx512F.UnpackLow(x.V512_14.AsUInt32(), x.V512_15.AsUInt32());
		Vector512<uint> a15 = Avx512F.UnpackHigh(x.V512_14.AsUInt32(), x.V512_15.AsUInt32());

		x.V512_0 = Avx512F.UnpackLow(a0.AsUInt64(), a2.AsUInt64()).AsByte();
		x.V512_1 = Avx512F.UnpackHigh(a0.AsUInt64(), a2.AsUInt64()).AsByte();
		x.V512_2 = Avx512F.UnpackLow(a1.AsUInt64(), a3.AsUInt64()).AsByte();
		x.V512_3 = Avx512F.UnpackHigh(a1.AsUInt64(), a3.AsUInt64()).AsByte();
		x.V512_4 = Avx512F.UnpackLow(a4.AsUInt64(), a6.AsUInt64()).AsByte();
		x.V512_5 = Avx512F.UnpackHigh(a4.AsUInt64(), a6.AsUInt64()).AsByte();
		x.V512_6 = Avx512F.UnpackLow(a5.AsUInt64(), a7.AsUInt64()).AsByte();
		x.V512_7 = Avx512F.UnpackHigh(a5.AsUInt64(), a7.AsUInt64()).AsByte();
		x.V512_8 = Avx512F.UnpackLow(a8.AsUInt64(), a10.AsUInt64()).AsByte();
		x.V512_9 = Avx512F.UnpackHigh(a8.AsUInt64(), a10.AsUInt64()).AsByte();
		x.V512_10 = Avx512F.UnpackLow(a9.AsUInt64(), a11.AsUInt64()).AsByte();
		x.V512_11 = Avx512F.UnpackHigh(a9.AsUInt64(), a11.AsUInt64()).AsByte();
		x.V512_12 = Avx512F.UnpackLow(a12.AsUInt64(), a14.AsUInt64()).AsByte();
		x.V512_13 = Avx512F.UnpackHigh(a12.AsUInt64(), a14.AsUInt64()).AsByte();
		x.V512_14 = Avx512F.UnpackLow(a13.AsUInt64(), a15.AsUInt64()).AsByte();
		x.V512_15 = Avx512F.UnpackHigh(a13.AsUInt64(), a15.AsUInt64()).AsByte();

		a0 = Avx512F.Shuffle4x128(x.V512_0.AsUInt32(), x.V512_4.AsUInt32(), 0x88);
		a1 = Avx512F.Shuffle4x128(x.V512_1.AsUInt32(), x.V512_5.AsUInt32(), 0x88);
		a2 = Avx512F.Shuffle4x128(x.V512_2.AsUInt32(), x.V512_6.AsUInt32(), 0x88);
		a3 = Avx512F.Shuffle4x128(x.V512_3.AsUInt32(), x.V512_7.AsUInt32(), 0x88);
		a4 = Avx512F.Shuffle4x128(x.V512_0.AsUInt32(), x.V512_4.AsUInt32(), 0xDD);
		a5 = Avx512F.Shuffle4x128(x.V512_1.AsUInt32(), x.V512_5.AsUInt32(), 0xDD);
		a6 = Avx512F.Shuffle4x128(x.V512_2.AsUInt32(), x.V512_6.AsUInt32(), 0xDD);
		a7 = Avx512F.Shuffle4x128(x.V512_3.AsUInt32(), x.V512_7.AsUInt32(), 0xDD);
		a8 = Avx512F.Shuffle4x128(x.V512_8.AsUInt32(), x.V512_12.AsUInt32(), 0x88);
		a9 = Avx512F.Shuffle4x128(x.V512_9.AsUInt32(), x.V512_13.AsUInt32(), 0x88);
		a10 = Avx512F.Shuffle4x128(x.V512_10.AsUInt32(), x.V512_14.AsUInt32(), 0x88);
		a11 = Avx512F.Shuffle4x128(x.V512_11.AsUInt32(), x.V512_15.AsUInt32(), 0x88);
		a12 = Avx512F.Shuffle4x128(x.V512_8.AsUInt32(), x.V512_12.AsUInt32(), 0xDD);
		a13 = Avx512F.Shuffle4x128(x.V512_9.AsUInt32(), x.V512_13.AsUInt32(), 0xDD);
		a14 = Avx512F.Shuffle4x128(x.V512_10.AsUInt32(), x.V512_14.AsUInt32(), 0xDD);
		a15 = Avx512F.Shuffle4x128(x.V512_11.AsUInt32(), x.V512_15.AsUInt32(), 0xDD);

		x.V512_0 = Avx512F.Shuffle4x128(a0, a8, 0x88).AsByte();
		x.V512_1 = Avx512F.Shuffle4x128(a1, a9, 0x88).AsByte();
		x.V512_2 = Avx512F.Shuffle4x128(a2, a10, 0x88).AsByte();
		x.V512_3 = Avx512F.Shuffle4x128(a3, a11, 0x88).AsByte();
		x.V512_4 = Avx512F.Shuffle4x128(a4, a12, 0x88).AsByte();
		x.V512_5 = Avx512F.Shuffle4x128(a5, a13, 0x88).AsByte();
		x.V512_6 = Avx512F.Shuffle4x128(a6, a14, 0x88).AsByte();
		x.V512_7 = Avx512F.Shuffle4x128(a7, a15, 0x88).AsByte();
		x.V512_8 = Avx512F.Shuffle4x128(a0, a8, 0xDD).AsByte();
		x.V512_9 = Avx512F.Shuffle4x128(a1, a9, 0xDD).AsByte();
		x.V512_10 = Avx512F.Shuffle4x128(a2, a10, 0xDD).AsByte();
		x.V512_11 = Avx512F.Shuffle4x128(a3, a11, 0xDD).AsByte();
		x.V512_12 = Avx512F.Shuffle4x128(a4, a12, 0xDD).AsByte();
		x.V512_13 = Avx512F.Shuffle4x128(a5, a13, 0xDD).AsByte();
		x.V512_14 = Avx512F.Shuffle4x128(a6, a14, 0xDD).AsByte();
		x.V512_15 = Avx512F.Shuffle4x128(a7, a15, 0xDD).AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Transpose(this ref VectorBuffer512 x)
	{
		Transpose(ref x.V256_0, ref x.V256_1, ref x.V256_2, ref x.V256_3, ref x.V256_4, ref x.V256_5, ref x.V256_6, ref x.V256_7);
		Transpose(ref x.V256_8, ref x.V256_9, ref x.V256_10, ref x.V256_11, ref x.V256_12, ref x.V256_13, ref x.V256_14, ref x.V256_15);
		// 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
		// =>
		// 0 8 1 9 2 10 3 11 4 12 5 13 6 14 7 15
		VectorBuffer512 t = x;
		x.V256_1 = t.V256_8;
		x.V256_2 = t.V256_1;
		x.V256_3 = t.V256_9;
		x.V256_4 = t.V256_2;
		x.V256_5 = t.V256_10;
		x.V256_6 = t.V256_3;
		x.V256_7 = t.V256_11;
		x.V256_8 = t.V256_4;
		x.V256_9 = t.V256_12;
		x.V256_10 = t.V256_5;
		x.V256_11 = t.V256_13;
		x.V256_12 = t.V256_6;
		x.V256_13 = t.V256_14;
		x.V256_14 = t.V256_7;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Transpose
	(
		ref Vector256<byte> x0, ref Vector256<byte> x1, ref Vector256<byte> x2, ref Vector256<byte> x3,
		ref Vector256<byte> x4, ref Vector256<byte> x5, ref Vector256<byte> x6, ref Vector256<byte> x7
	)
	{
		Vector256<uint> t0 = Avx2.UnpackLow(x0.AsUInt32(), x1.AsUInt32());
		Vector256<uint> t1 = Avx2.UnpackLow(x2.AsUInt32(), x3.AsUInt32());
		Vector256<uint> t2 = Avx2.UnpackHigh(x0.AsUInt32(), x1.AsUInt32());
		Vector256<uint> t3 = Avx2.UnpackHigh(x2.AsUInt32(), x3.AsUInt32());
		Vector256<uint> t4 = Avx2.UnpackLow(x4.AsUInt32(), x5.AsUInt32());
		Vector256<uint> t5 = Avx2.UnpackLow(x6.AsUInt32(), x7.AsUInt32());
		Vector256<uint> t6 = Avx2.UnpackHigh(x4.AsUInt32(), x5.AsUInt32());
		Vector256<uint> t7 = Avx2.UnpackHigh(x6.AsUInt32(), x7.AsUInt32());

		Vector256<uint> b0 = Avx2.UnpackLow(t0.AsUInt64(), t1.AsUInt64()).AsUInt32();
		Vector256<uint> b1 = Avx2.UnpackHigh(t0.AsUInt64(), t1.AsUInt64()).AsUInt32();
		Vector256<uint> b2 = Avx2.UnpackLow(t2.AsUInt64(), t3.AsUInt64()).AsUInt32();
		Vector256<uint> b3 = Avx2.UnpackHigh(t2.AsUInt64(), t3.AsUInt64()).AsUInt32();
		Vector256<uint> b4 = Avx2.UnpackLow(t4.AsUInt64(), t5.AsUInt64()).AsUInt32();
		Vector256<uint> b5 = Avx2.UnpackHigh(t4.AsUInt64(), t5.AsUInt64()).AsUInt32();
		Vector256<uint> b6 = Avx2.UnpackLow(t6.AsUInt64(), t7.AsUInt64()).AsUInt32();
		Vector256<uint> b7 = Avx2.UnpackHigh(t6.AsUInt64(), t7.AsUInt64()).AsUInt32();

		x0 = Avx2.Permute2x128(b0, b4, 0x20).AsByte();
		x4 = Avx2.Permute2x128(b0, b4, 0x31).AsByte();
		x1 = Avx2.Permute2x128(b1, b5, 0x20).AsByte();
		x5 = Avx2.Permute2x128(b1, b5, 0x31).AsByte();
		x2 = Avx2.Permute2x128(b2, b6, 0x20).AsByte();
		x6 = Avx2.Permute2x128(b2, b6, 0x31).AsByte();
		x3 = Avx2.Permute2x128(b3, b7, 0x20).AsByte();
		x7 = Avx2.Permute2x128(b3, b7, 0x31).AsByte();
	}

	extension(Gfni)
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Vector128<byte> AesInverseMixColumns(Vector128<byte> s0)
		{
			Vector128<byte> s1 = s0.RotateLeftUInt32_24();
			Vector128<byte> s2 = s0.RotateLeftUInt32_16();
			Vector128<byte> s3 = s0.RotateLeftUInt32_8();

			Vector128<byte> m0 = Gfni.GaloisFieldMultiply(s0, Vector128.Create<byte>(14));
			Vector128<byte> m1 = Gfni.GaloisFieldMultiply(s1, Vector128.Create<byte>(11));
			Vector128<byte> m2 = Gfni.GaloisFieldMultiply(s2, Vector128.Create<byte>(13));
			Vector128<byte> m3 = Gfni.GaloisFieldMultiply(s3, Vector128.Create<byte>(9));

			return m0 ^ m1 ^ m2 ^ m3;
		}
	}
}
