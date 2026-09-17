using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.Internal.Extensions;

internal static class VectorTranspose
{
	extension(Vector128<uint> value)
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector128<uint> RotateWordsLeft([ConstantExpected(Min = 1, Max = 3)] byte count)
		{
			if (AdvSimd.Arm64.IsSupported)
			{
				return AdvSimd.ExtractVector128(value, value, count);
			}

			return count switch
			{
				1 => Vector128.Shuffle(value, Vector128.Create(1u, 2, 3, 0)),
				2 => Vector128.Shuffle(value, Vector128.Create(2u, 3, 0, 1)),
				_ => Vector128.Shuffle(value, Vector128.Create(3u, 0, 1, 2))
			};
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<uint> ZipLow(Vector128<uint> left, Vector128<uint> right)
	{
		return Sse2.IsSupported ? Sse2.UnpackLow(left, right) : AdvSimd.Arm64.ZipLow(left, right);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<uint> ZipHigh(Vector128<uint> left, Vector128<uint> right)
	{
		return Sse2.IsSupported ? Sse2.UnpackHigh(left, right) : AdvSimd.Arm64.ZipHigh(left, right);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<ulong> ZipLow(Vector128<ulong> left, Vector128<ulong> right)
	{
		return Sse2.IsSupported ? Sse2.UnpackLow(left, right) : AdvSimd.Arm64.ZipLow(left, right);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<ulong> ZipHigh(Vector128<ulong> left, Vector128<ulong> right)
	{
		return Sse2.IsSupported ? Sse2.UnpackHigh(left, right) : AdvSimd.Arm64.ZipHigh(left, right);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Transpose
	(
		ref Vector512<uint> v0, ref Vector512<uint> v1, ref Vector512<uint> v2, ref Vector512<uint> v3,
		ref Vector512<uint> v4, ref Vector512<uint> v5, ref Vector512<uint> v6, ref Vector512<uint> v7,
		ref Vector512<uint> v8, ref Vector512<uint> v9, ref Vector512<uint> v10, ref Vector512<uint> v11,
		ref Vector512<uint> v12, ref Vector512<uint> v13, ref Vector512<uint> v14, ref Vector512<uint> v15
	)
	{
		Vector512<uint> a0 = Avx512F.UnpackLow(v0, v1);
		Vector512<uint> a1 = Avx512F.UnpackHigh(v0, v1);
		Vector512<uint> a2 = Avx512F.UnpackLow(v2, v3);
		Vector512<uint> a3 = Avx512F.UnpackHigh(v2, v3);
		Vector512<uint> a4 = Avx512F.UnpackLow(v4, v5);
		Vector512<uint> a5 = Avx512F.UnpackHigh(v4, v5);
		Vector512<uint> a6 = Avx512F.UnpackLow(v6, v7);
		Vector512<uint> a7 = Avx512F.UnpackHigh(v6, v7);
		Vector512<uint> a8 = Avx512F.UnpackLow(v8, v9);
		Vector512<uint> a9 = Avx512F.UnpackHigh(v8, v9);
		Vector512<uint> a10 = Avx512F.UnpackLow(v10, v11);
		Vector512<uint> a11 = Avx512F.UnpackHigh(v10, v11);
		Vector512<uint> a12 = Avx512F.UnpackLow(v12, v13);
		Vector512<uint> a13 = Avx512F.UnpackHigh(v12, v13);
		Vector512<uint> a14 = Avx512F.UnpackLow(v14, v15);
		Vector512<uint> a15 = Avx512F.UnpackHigh(v14, v15);

		v0 = Avx512F.UnpackLow(a0.AsUInt64(), a2.AsUInt64()).AsUInt32();
		v1 = Avx512F.UnpackHigh(a0.AsUInt64(), a2.AsUInt64()).AsUInt32();
		v2 = Avx512F.UnpackLow(a1.AsUInt64(), a3.AsUInt64()).AsUInt32();
		v3 = Avx512F.UnpackHigh(a1.AsUInt64(), a3.AsUInt64()).AsUInt32();
		v4 = Avx512F.UnpackLow(a4.AsUInt64(), a6.AsUInt64()).AsUInt32();
		v5 = Avx512F.UnpackHigh(a4.AsUInt64(), a6.AsUInt64()).AsUInt32();
		v6 = Avx512F.UnpackLow(a5.AsUInt64(), a7.AsUInt64()).AsUInt32();
		v7 = Avx512F.UnpackHigh(a5.AsUInt64(), a7.AsUInt64()).AsUInt32();
		v8 = Avx512F.UnpackLow(a8.AsUInt64(), a10.AsUInt64()).AsUInt32();
		v9 = Avx512F.UnpackHigh(a8.AsUInt64(), a10.AsUInt64()).AsUInt32();
		v10 = Avx512F.UnpackLow(a9.AsUInt64(), a11.AsUInt64()).AsUInt32();
		v11 = Avx512F.UnpackHigh(a9.AsUInt64(), a11.AsUInt64()).AsUInt32();
		v12 = Avx512F.UnpackLow(a12.AsUInt64(), a14.AsUInt64()).AsUInt32();
		v13 = Avx512F.UnpackHigh(a12.AsUInt64(), a14.AsUInt64()).AsUInt32();
		v14 = Avx512F.UnpackLow(a13.AsUInt64(), a15.AsUInt64()).AsUInt32();
		v15 = Avx512F.UnpackHigh(a13.AsUInt64(), a15.AsUInt64()).AsUInt32();

		a0 = Avx512F.Shuffle4x128(v0, v4, 0b10_00_10_00);
		a1 = Avx512F.Shuffle4x128(v1, v5, 0b10_00_10_00);
		a2 = Avx512F.Shuffle4x128(v2, v6, 0b10_00_10_00);
		a3 = Avx512F.Shuffle4x128(v3, v7, 0b10_00_10_00);
		a4 = Avx512F.Shuffle4x128(v0, v4, 0b11_01_11_01);
		a5 = Avx512F.Shuffle4x128(v1, v5, 0b11_01_11_01);
		a6 = Avx512F.Shuffle4x128(v2, v6, 0b11_01_11_01);
		a7 = Avx512F.Shuffle4x128(v3, v7, 0b11_01_11_01);
		a8 = Avx512F.Shuffle4x128(v8, v12, 0b10_00_10_00);
		a9 = Avx512F.Shuffle4x128(v9, v13, 0b10_00_10_00);
		a10 = Avx512F.Shuffle4x128(v10, v14, 0b10_00_10_00);
		a11 = Avx512F.Shuffle4x128(v11, v15, 0b10_00_10_00);
		a12 = Avx512F.Shuffle4x128(v8, v12, 0b11_01_11_01);
		a13 = Avx512F.Shuffle4x128(v9, v13, 0b11_01_11_01);
		a14 = Avx512F.Shuffle4x128(v10, v14, 0b11_01_11_01);
		a15 = Avx512F.Shuffle4x128(v11, v15, 0b11_01_11_01);

		v0 = Avx512F.Shuffle4x128(a0, a8, 0b10_00_10_00);
		v1 = Avx512F.Shuffle4x128(a1, a9, 0b10_00_10_00);
		v2 = Avx512F.Shuffle4x128(a2, a10, 0b10_00_10_00);
		v3 = Avx512F.Shuffle4x128(a3, a11, 0b10_00_10_00);
		v4 = Avx512F.Shuffle4x128(a4, a12, 0b10_00_10_00);
		v5 = Avx512F.Shuffle4x128(a5, a13, 0b10_00_10_00);
		v6 = Avx512F.Shuffle4x128(a6, a14, 0b10_00_10_00);
		v7 = Avx512F.Shuffle4x128(a7, a15, 0b10_00_10_00);
		v8 = Avx512F.Shuffle4x128(a0, a8, 0b11_01_11_01);
		v9 = Avx512F.Shuffle4x128(a1, a9, 0b11_01_11_01);
		v10 = Avx512F.Shuffle4x128(a2, a10, 0b11_01_11_01);
		v11 = Avx512F.Shuffle4x128(a3, a11, 0b11_01_11_01);
		v12 = Avx512F.Shuffle4x128(a4, a12, 0b11_01_11_01);
		v13 = Avx512F.Shuffle4x128(a5, a13, 0b11_01_11_01);
		v14 = Avx512F.Shuffle4x128(a6, a14, 0b11_01_11_01);
		v15 = Avx512F.Shuffle4x128(a7, a15, 0b11_01_11_01);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Transpose
	(
		ref Vector256<uint> v0, ref Vector256<uint> v1, ref Vector256<uint> v2, ref Vector256<uint> v3,
		ref Vector256<uint> v4, ref Vector256<uint> v5, ref Vector256<uint> v6, ref Vector256<uint> v7,
		ref Vector256<uint> v8, ref Vector256<uint> v9, ref Vector256<uint> v10, ref Vector256<uint> v11,
		ref Vector256<uint> v12, ref Vector256<uint> v13, ref Vector256<uint> v14, ref Vector256<uint> v15
	)
	{
		Transpose(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);
		Transpose(ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15);
		// 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
		// =>
		// 0 8 1 9 2 10 3 11 4 12 5 13 6 14 7 15
		Vector256<uint> original1 = v1;
		Vector256<uint> original2 = v2;
		Vector256<uint> original3 = v3;
		Vector256<uint> original4 = v4;
		Vector256<uint> original5 = v5;
		Vector256<uint> original6 = v6;
		Vector256<uint> original7 = v7;
		Vector256<uint> original8 = v8;
		Vector256<uint> original9 = v9;
		Vector256<uint> original10 = v10;
		Vector256<uint> original11 = v11;
		Vector256<uint> original12 = v12;
		Vector256<uint> original13 = v13;
		Vector256<uint> original14 = v14;
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

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Transpose
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

	// Transpose four word-major vectors into one 16-byte chunk per stream block.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void TransposeXorStore(Vector128<uint> a, Vector128<uint> b, Vector128<uint> c, Vector128<uint> d, ref byte input, ref byte output, nuint offset, bool storeFourthBlock)
	{
		Vector128<uint> t0 = ZipLow(a, b);
		Vector128<uint> t1 = ZipLow(c, d);
		Vector128<uint> t2 = ZipHigh(a, b);
		Vector128<uint> t3 = ZipHigh(c, d);
		(ZipLow(t0.AsUInt64(), t1.AsUInt64()).AsByte() ^ Vector128.LoadUnsafe(ref input, offset)).StoreUnsafe(ref output, offset);
		(ZipHigh(t0.AsUInt64(), t1.AsUInt64()).AsByte() ^ Vector128.LoadUnsafe(ref input, offset + 64u)).StoreUnsafe(ref output, offset + 64u);
		(ZipLow(t2.AsUInt64(), t3.AsUInt64()).AsByte() ^ Vector128.LoadUnsafe(ref input, offset + 128u)).StoreUnsafe(ref output, offset + 128u);

		if (storeFourthBlock)
		{
			(ZipHigh(t2.AsUInt64(), t3.AsUInt64()).AsByte() ^ Vector128.LoadUnsafe(ref input, offset + 192u)).StoreUnsafe(ref output, offset + 192u);
		}
	}
}
