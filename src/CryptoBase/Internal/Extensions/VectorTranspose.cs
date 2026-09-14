namespace CryptoBase.Internal.Extensions;

internal static class VectorTranspose
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Transpose(ref Vector512<byte> v0, ref Vector512<byte> v1, ref Vector512<byte> v2, ref Vector512<byte> v3, ref Vector512<byte> v4, ref Vector512<byte> v5, ref Vector512<byte> v6, ref Vector512<byte> v7, ref Vector512<byte> v8, ref Vector512<byte> v9, ref Vector512<byte> v10, ref Vector512<byte> v11, ref Vector512<byte> v12, ref Vector512<byte> v13, ref Vector512<byte> v14, ref Vector512<byte> v15)
	{
		Vector512<uint> a0 = Avx512F.UnpackLow(v0.AsUInt32(), v1.AsUInt32());
		Vector512<uint> a1 = Avx512F.UnpackHigh(v0.AsUInt32(), v1.AsUInt32());
		Vector512<uint> a2 = Avx512F.UnpackLow(v2.AsUInt32(), v3.AsUInt32());
		Vector512<uint> a3 = Avx512F.UnpackHigh(v2.AsUInt32(), v3.AsUInt32());
		Vector512<uint> a4 = Avx512F.UnpackLow(v4.AsUInt32(), v5.AsUInt32());
		Vector512<uint> a5 = Avx512F.UnpackHigh(v4.AsUInt32(), v5.AsUInt32());
		Vector512<uint> a6 = Avx512F.UnpackLow(v6.AsUInt32(), v7.AsUInt32());
		Vector512<uint> a7 = Avx512F.UnpackHigh(v6.AsUInt32(), v7.AsUInt32());
		Vector512<uint> a8 = Avx512F.UnpackLow(v8.AsUInt32(), v9.AsUInt32());
		Vector512<uint> a9 = Avx512F.UnpackHigh(v8.AsUInt32(), v9.AsUInt32());
		Vector512<uint> a10 = Avx512F.UnpackLow(v10.AsUInt32(), v11.AsUInt32());
		Vector512<uint> a11 = Avx512F.UnpackHigh(v10.AsUInt32(), v11.AsUInt32());
		Vector512<uint> a12 = Avx512F.UnpackLow(v12.AsUInt32(), v13.AsUInt32());
		Vector512<uint> a13 = Avx512F.UnpackHigh(v12.AsUInt32(), v13.AsUInt32());
		Vector512<uint> a14 = Avx512F.UnpackLow(v14.AsUInt32(), v15.AsUInt32());
		Vector512<uint> a15 = Avx512F.UnpackHigh(v14.AsUInt32(), v15.AsUInt32());

		v0 = Avx512F.UnpackLow(a0.AsUInt64(), a2.AsUInt64()).AsByte();
		v1 = Avx512F.UnpackHigh(a0.AsUInt64(), a2.AsUInt64()).AsByte();
		v2 = Avx512F.UnpackLow(a1.AsUInt64(), a3.AsUInt64()).AsByte();
		v3 = Avx512F.UnpackHigh(a1.AsUInt64(), a3.AsUInt64()).AsByte();
		v4 = Avx512F.UnpackLow(a4.AsUInt64(), a6.AsUInt64()).AsByte();
		v5 = Avx512F.UnpackHigh(a4.AsUInt64(), a6.AsUInt64()).AsByte();
		v6 = Avx512F.UnpackLow(a5.AsUInt64(), a7.AsUInt64()).AsByte();
		v7 = Avx512F.UnpackHigh(a5.AsUInt64(), a7.AsUInt64()).AsByte();
		v8 = Avx512F.UnpackLow(a8.AsUInt64(), a10.AsUInt64()).AsByte();
		v9 = Avx512F.UnpackHigh(a8.AsUInt64(), a10.AsUInt64()).AsByte();
		v10 = Avx512F.UnpackLow(a9.AsUInt64(), a11.AsUInt64()).AsByte();
		v11 = Avx512F.UnpackHigh(a9.AsUInt64(), a11.AsUInt64()).AsByte();
		v12 = Avx512F.UnpackLow(a12.AsUInt64(), a14.AsUInt64()).AsByte();
		v13 = Avx512F.UnpackHigh(a12.AsUInt64(), a14.AsUInt64()).AsByte();
		v14 = Avx512F.UnpackLow(a13.AsUInt64(), a15.AsUInt64()).AsByte();
		v15 = Avx512F.UnpackHigh(a13.AsUInt64(), a15.AsUInt64()).AsByte();

		a0 = Avx512F.Shuffle4x128(v0.AsUInt32(), v4.AsUInt32(), 0b10_00_10_00);
		a1 = Avx512F.Shuffle4x128(v1.AsUInt32(), v5.AsUInt32(), 0b10_00_10_00);
		a2 = Avx512F.Shuffle4x128(v2.AsUInt32(), v6.AsUInt32(), 0b10_00_10_00);
		a3 = Avx512F.Shuffle4x128(v3.AsUInt32(), v7.AsUInt32(), 0b10_00_10_00);
		a4 = Avx512F.Shuffle4x128(v0.AsUInt32(), v4.AsUInt32(), 0b11_01_11_01);
		a5 = Avx512F.Shuffle4x128(v1.AsUInt32(), v5.AsUInt32(), 0b11_01_11_01);
		a6 = Avx512F.Shuffle4x128(v2.AsUInt32(), v6.AsUInt32(), 0b11_01_11_01);
		a7 = Avx512F.Shuffle4x128(v3.AsUInt32(), v7.AsUInt32(), 0b11_01_11_01);
		a8 = Avx512F.Shuffle4x128(v8.AsUInt32(), v12.AsUInt32(), 0b10_00_10_00);
		a9 = Avx512F.Shuffle4x128(v9.AsUInt32(), v13.AsUInt32(), 0b10_00_10_00);
		a10 = Avx512F.Shuffle4x128(v10.AsUInt32(), v14.AsUInt32(), 0b10_00_10_00);
		a11 = Avx512F.Shuffle4x128(v11.AsUInt32(), v15.AsUInt32(), 0b10_00_10_00);
		a12 = Avx512F.Shuffle4x128(v8.AsUInt32(), v12.AsUInt32(), 0b11_01_11_01);
		a13 = Avx512F.Shuffle4x128(v9.AsUInt32(), v13.AsUInt32(), 0b11_01_11_01);
		a14 = Avx512F.Shuffle4x128(v10.AsUInt32(), v14.AsUInt32(), 0b11_01_11_01);
		a15 = Avx512F.Shuffle4x128(v11.AsUInt32(), v15.AsUInt32(), 0b11_01_11_01);

		v0 = Avx512F.Shuffle4x128(a0, a8, 0b10_00_10_00).AsByte();
		v1 = Avx512F.Shuffle4x128(a1, a9, 0b10_00_10_00).AsByte();
		v2 = Avx512F.Shuffle4x128(a2, a10, 0b10_00_10_00).AsByte();
		v3 = Avx512F.Shuffle4x128(a3, a11, 0b10_00_10_00).AsByte();
		v4 = Avx512F.Shuffle4x128(a4, a12, 0b10_00_10_00).AsByte();
		v5 = Avx512F.Shuffle4x128(a5, a13, 0b10_00_10_00).AsByte();
		v6 = Avx512F.Shuffle4x128(a6, a14, 0b10_00_10_00).AsByte();
		v7 = Avx512F.Shuffle4x128(a7, a15, 0b10_00_10_00).AsByte();
		v8 = Avx512F.Shuffle4x128(a0, a8, 0b11_01_11_01).AsByte();
		v9 = Avx512F.Shuffle4x128(a1, a9, 0b11_01_11_01).AsByte();
		v10 = Avx512F.Shuffle4x128(a2, a10, 0b11_01_11_01).AsByte();
		v11 = Avx512F.Shuffle4x128(a3, a11, 0b11_01_11_01).AsByte();
		v12 = Avx512F.Shuffle4x128(a4, a12, 0b11_01_11_01).AsByte();
		v13 = Avx512F.Shuffle4x128(a5, a13, 0b11_01_11_01).AsByte();
		v14 = Avx512F.Shuffle4x128(a6, a14, 0b11_01_11_01).AsByte();
		v15 = Avx512F.Shuffle4x128(a7, a15, 0b11_01_11_01).AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Transpose(ref Vector256<byte> v0, ref Vector256<byte> v1, ref Vector256<byte> v2, ref Vector256<byte> v3, ref Vector256<byte> v4, ref Vector256<byte> v5, ref Vector256<byte> v6, ref Vector256<byte> v7, ref Vector256<byte> v8, ref Vector256<byte> v9, ref Vector256<byte> v10, ref Vector256<byte> v11, ref Vector256<byte> v12, ref Vector256<byte> v13, ref Vector256<byte> v14, ref Vector256<byte> v15)
	{
		Transpose(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);
		Transpose(ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15);
		// 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
		// =>
		// 0 8 1 9 2 10 3 11 4 12 5 13 6 14 7 15
		Vector256<byte> original1 = v1;
		Vector256<byte> original2 = v2;
		Vector256<byte> original3 = v3;
		Vector256<byte> original4 = v4;
		Vector256<byte> original5 = v5;
		Vector256<byte> original6 = v6;
		Vector256<byte> original7 = v7;
		Vector256<byte> original8 = v8;
		Vector256<byte> original9 = v9;
		Vector256<byte> original10 = v10;
		Vector256<byte> original11 = v11;
		Vector256<byte> original12 = v12;
		Vector256<byte> original13 = v13;
		Vector256<byte> original14 = v14;
		v1 = original8;
		v2 = original1;
		v3 = original9;
		v4 = original2;
		v5 = original10;
		v6 = original3;
		v7 = original11;
		v8 = original4;
		v9 = original12;
		v10 = original5;
		v11 = original13;
		v12 = original6;
		v13 = original14;
		v14 = original7;
	}

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
}
