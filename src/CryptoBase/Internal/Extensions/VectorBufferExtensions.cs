namespace CryptoBase.Internal.Extensions;

internal static class VectorBufferExtensions
{
	extension(ref VectorBuffer1024 value)
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Transpose()
		{
			Vector512<uint> a0 = Avx512F.UnpackLow(value.V512_0.AsUInt32(), value.V512_1.AsUInt32());
			Vector512<uint> a1 = Avx512F.UnpackHigh(value.V512_0.AsUInt32(), value.V512_1.AsUInt32());
			Vector512<uint> a2 = Avx512F.UnpackLow(value.V512_2.AsUInt32(), value.V512_3.AsUInt32());
			Vector512<uint> a3 = Avx512F.UnpackHigh(value.V512_2.AsUInt32(), value.V512_3.AsUInt32());
			Vector512<uint> a4 = Avx512F.UnpackLow(value.V512_4.AsUInt32(), value.V512_5.AsUInt32());
			Vector512<uint> a5 = Avx512F.UnpackHigh(value.V512_4.AsUInt32(), value.V512_5.AsUInt32());
			Vector512<uint> a6 = Avx512F.UnpackLow(value.V512_6.AsUInt32(), value.V512_7.AsUInt32());
			Vector512<uint> a7 = Avx512F.UnpackHigh(value.V512_6.AsUInt32(), value.V512_7.AsUInt32());
			Vector512<uint> a8 = Avx512F.UnpackLow(value.V512_8.AsUInt32(), value.V512_9.AsUInt32());
			Vector512<uint> a9 = Avx512F.UnpackHigh(value.V512_8.AsUInt32(), value.V512_9.AsUInt32());
			Vector512<uint> a10 = Avx512F.UnpackLow(value.V512_10.AsUInt32(), value.V512_11.AsUInt32());
			Vector512<uint> a11 = Avx512F.UnpackHigh(value.V512_10.AsUInt32(), value.V512_11.AsUInt32());
			Vector512<uint> a12 = Avx512F.UnpackLow(value.V512_12.AsUInt32(), value.V512_13.AsUInt32());
			Vector512<uint> a13 = Avx512F.UnpackHigh(value.V512_12.AsUInt32(), value.V512_13.AsUInt32());
			Vector512<uint> a14 = Avx512F.UnpackLow(value.V512_14.AsUInt32(), value.V512_15.AsUInt32());
			Vector512<uint> a15 = Avx512F.UnpackHigh(value.V512_14.AsUInt32(), value.V512_15.AsUInt32());

			value.V512_0 = Avx512F.UnpackLow(a0.AsUInt64(), a2.AsUInt64()).AsByte();
			value.V512_1 = Avx512F.UnpackHigh(a0.AsUInt64(), a2.AsUInt64()).AsByte();
			value.V512_2 = Avx512F.UnpackLow(a1.AsUInt64(), a3.AsUInt64()).AsByte();
			value.V512_3 = Avx512F.UnpackHigh(a1.AsUInt64(), a3.AsUInt64()).AsByte();
			value.V512_4 = Avx512F.UnpackLow(a4.AsUInt64(), a6.AsUInt64()).AsByte();
			value.V512_5 = Avx512F.UnpackHigh(a4.AsUInt64(), a6.AsUInt64()).AsByte();
			value.V512_6 = Avx512F.UnpackLow(a5.AsUInt64(), a7.AsUInt64()).AsByte();
			value.V512_7 = Avx512F.UnpackHigh(a5.AsUInt64(), a7.AsUInt64()).AsByte();
			value.V512_8 = Avx512F.UnpackLow(a8.AsUInt64(), a10.AsUInt64()).AsByte();
			value.V512_9 = Avx512F.UnpackHigh(a8.AsUInt64(), a10.AsUInt64()).AsByte();
			value.V512_10 = Avx512F.UnpackLow(a9.AsUInt64(), a11.AsUInt64()).AsByte();
			value.V512_11 = Avx512F.UnpackHigh(a9.AsUInt64(), a11.AsUInt64()).AsByte();
			value.V512_12 = Avx512F.UnpackLow(a12.AsUInt64(), a14.AsUInt64()).AsByte();
			value.V512_13 = Avx512F.UnpackHigh(a12.AsUInt64(), a14.AsUInt64()).AsByte();
			value.V512_14 = Avx512F.UnpackLow(a13.AsUInt64(), a15.AsUInt64()).AsByte();
			value.V512_15 = Avx512F.UnpackHigh(a13.AsUInt64(), a15.AsUInt64()).AsByte();

			a0 = Avx512F.Shuffle4x128(value.V512_0.AsUInt32(), value.V512_4.AsUInt32(), 0x88);
			a1 = Avx512F.Shuffle4x128(value.V512_1.AsUInt32(), value.V512_5.AsUInt32(), 0x88);
			a2 = Avx512F.Shuffle4x128(value.V512_2.AsUInt32(), value.V512_6.AsUInt32(), 0x88);
			a3 = Avx512F.Shuffle4x128(value.V512_3.AsUInt32(), value.V512_7.AsUInt32(), 0x88);
			a4 = Avx512F.Shuffle4x128(value.V512_0.AsUInt32(), value.V512_4.AsUInt32(), 0xDD);
			a5 = Avx512F.Shuffle4x128(value.V512_1.AsUInt32(), value.V512_5.AsUInt32(), 0xDD);
			a6 = Avx512F.Shuffle4x128(value.V512_2.AsUInt32(), value.V512_6.AsUInt32(), 0xDD);
			a7 = Avx512F.Shuffle4x128(value.V512_3.AsUInt32(), value.V512_7.AsUInt32(), 0xDD);
			a8 = Avx512F.Shuffle4x128(value.V512_8.AsUInt32(), value.V512_12.AsUInt32(), 0x88);
			a9 = Avx512F.Shuffle4x128(value.V512_9.AsUInt32(), value.V512_13.AsUInt32(), 0x88);
			a10 = Avx512F.Shuffle4x128(value.V512_10.AsUInt32(), value.V512_14.AsUInt32(), 0x88);
			a11 = Avx512F.Shuffle4x128(value.V512_11.AsUInt32(), value.V512_15.AsUInt32(), 0x88);
			a12 = Avx512F.Shuffle4x128(value.V512_8.AsUInt32(), value.V512_12.AsUInt32(), 0xDD);
			a13 = Avx512F.Shuffle4x128(value.V512_9.AsUInt32(), value.V512_13.AsUInt32(), 0xDD);
			a14 = Avx512F.Shuffle4x128(value.V512_10.AsUInt32(), value.V512_14.AsUInt32(), 0xDD);
			a15 = Avx512F.Shuffle4x128(value.V512_11.AsUInt32(), value.V512_15.AsUInt32(), 0xDD);

			value.V512_0 = Avx512F.Shuffle4x128(a0, a8, 0x88).AsByte();
			value.V512_1 = Avx512F.Shuffle4x128(a1, a9, 0x88).AsByte();
			value.V512_2 = Avx512F.Shuffle4x128(a2, a10, 0x88).AsByte();
			value.V512_3 = Avx512F.Shuffle4x128(a3, a11, 0x88).AsByte();
			value.V512_4 = Avx512F.Shuffle4x128(a4, a12, 0x88).AsByte();
			value.V512_5 = Avx512F.Shuffle4x128(a5, a13, 0x88).AsByte();
			value.V512_6 = Avx512F.Shuffle4x128(a6, a14, 0x88).AsByte();
			value.V512_7 = Avx512F.Shuffle4x128(a7, a15, 0x88).AsByte();
			value.V512_8 = Avx512F.Shuffle4x128(a0, a8, 0xDD).AsByte();
			value.V512_9 = Avx512F.Shuffle4x128(a1, a9, 0xDD).AsByte();
			value.V512_10 = Avx512F.Shuffle4x128(a2, a10, 0xDD).AsByte();
			value.V512_11 = Avx512F.Shuffle4x128(a3, a11, 0xDD).AsByte();
			value.V512_12 = Avx512F.Shuffle4x128(a4, a12, 0xDD).AsByte();
			value.V512_13 = Avx512F.Shuffle4x128(a5, a13, 0xDD).AsByte();
			value.V512_14 = Avx512F.Shuffle4x128(a6, a14, 0xDD).AsByte();
			value.V512_15 = Avx512F.Shuffle4x128(a7, a15, 0xDD).AsByte();
		}
	}

	extension(ref VectorBuffer512 value)
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void Transpose()
		{
			Transpose(ref value.V256_0, ref value.V256_1, ref value.V256_2, ref value.V256_3, ref value.V256_4, ref value.V256_5, ref value.V256_6, ref value.V256_7);
			Transpose(ref value.V256_8, ref value.V256_9, ref value.V256_10, ref value.V256_11, ref value.V256_12, ref value.V256_13, ref value.V256_14, ref value.V256_15);
			// 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
			// =>
			// 0 8 1 9 2 10 3 11 4 12 5 13 6 14 7 15
			VectorBuffer512 original = value;
			value.V256_1 = original.V256_8;
			value.V256_2 = original.V256_1;
			value.V256_3 = original.V256_9;
			value.V256_4 = original.V256_2;
			value.V256_5 = original.V256_10;
			value.V256_6 = original.V256_3;
			value.V256_7 = original.V256_11;
			value.V256_8 = original.V256_4;
			value.V256_9 = original.V256_12;
			value.V256_10 = original.V256_5;
			value.V256_11 = original.V256_13;
			value.V256_12 = original.V256_6;
			value.V256_13 = original.V256_14;
			value.V256_14 = original.V256_7;
		}
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
