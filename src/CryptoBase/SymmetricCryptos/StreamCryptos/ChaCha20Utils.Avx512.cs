namespace CryptoBase.SymmetricCryptos.StreamCryptos;

internal static partial class ChaCha20Utils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void QuarterRound(ref Vector512<uint> a, ref Vector512<uint> b, ref Vector512<uint> c, ref Vector512<uint> d)
	{
		a += b;
		d = (a ^ d).RotateLeftUInt32(16);

		c += d;
		b = (b ^ c).RotateLeftUInt32(12);

		a += b;
		d = (a ^ d).RotateLeftUInt32(8);

		c += d;
		b = (b ^ c).RotateLeftUInt32(7);
	}

	public static int ChaChaCoreSoA1024Avx512(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		int offset = 0;
		int length = source.Length;

		const int sizeOfVector = 64;
		ref uint stateRef = ref state.GetReference();
		ref byte sourceRef = ref source.GetReference();
		ref byte dstRef = ref destination.GetReference();

		ref uint counter = ref Unsafe.Add(ref stateRef, 12);

		Vector512<uint> o0 = Vector512.Create(Unsafe.Add(ref stateRef, 0));
		Vector512<uint> o1 = Vector512.Create(Unsafe.Add(ref stateRef, 1));
		Vector512<uint> o2 = Vector512.Create(Unsafe.Add(ref stateRef, 2));
		Vector512<uint> o3 = Vector512.Create(Unsafe.Add(ref stateRef, 3));
		Vector512<uint> o4 = Vector512.Create(Unsafe.Add(ref stateRef, 4));
		Vector512<uint> o5 = Vector512.Create(Unsafe.Add(ref stateRef, 5));
		Vector512<uint> o6 = Vector512.Create(Unsafe.Add(ref stateRef, 6));
		Vector512<uint> o7 = Vector512.Create(Unsafe.Add(ref stateRef, 7));
		Vector512<uint> o8 = Vector512.Create(Unsafe.Add(ref stateRef, 8));
		Vector512<uint> o9 = Vector512.Create(Unsafe.Add(ref stateRef, 9));
		Vector512<uint> o10 = Vector512.Create(Unsafe.Add(ref stateRef, 10));
		Vector512<uint> o11 = Vector512.Create(Unsafe.Add(ref stateRef, 11));
		// 12
		Vector512<uint> o13 = Vector512.Create(Unsafe.Add(ref stateRef, 13));
		Vector512<uint> o14 = Vector512.Create(Unsafe.Add(ref stateRef, 14));
		Vector512<uint> o15 = Vector512.Create(Unsafe.Add(ref stateRef, 15));

		while (length >= 1024)
		{
			Vector512<uint> o12 = Vector512.Create(counter) + Vector512.CreateSequence<uint>(0, 1);

			ref readonly Vector512<byte> s0 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 0 * sizeOfVector));
			ref readonly Vector512<byte> s1 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 1 * sizeOfVector));
			ref readonly Vector512<byte> s2 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 2 * sizeOfVector));
			ref readonly Vector512<byte> s3 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 3 * sizeOfVector));
			ref readonly Vector512<byte> s4 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 4 * sizeOfVector));
			ref readonly Vector512<byte> s5 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 5 * sizeOfVector));
			ref readonly Vector512<byte> s6 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 6 * sizeOfVector));
			ref readonly Vector512<byte> s7 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 7 * sizeOfVector));
			ref readonly Vector512<byte> s8 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 8 * sizeOfVector));
			ref readonly Vector512<byte> s9 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 9 * sizeOfVector));
			ref readonly Vector512<byte> s10 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 10 * sizeOfVector));
			ref readonly Vector512<byte> s11 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 11 * sizeOfVector));
			ref readonly Vector512<byte> s12 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 12 * sizeOfVector));
			ref readonly Vector512<byte> s13 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 13 * sizeOfVector));
			ref readonly Vector512<byte> s14 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 14 * sizeOfVector));
			ref readonly Vector512<byte> s15 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 15 * sizeOfVector));

			Vector512<uint> x0 = o0;
			Vector512<uint> x1 = o1;
			Vector512<uint> x2 = o2;
			Vector512<uint> x3 = o3;
			Vector512<uint> x4 = o4;
			Vector512<uint> x5 = o5;
			Vector512<uint> x6 = o6;
			Vector512<uint> x7 = o7;
			Vector512<uint> x8 = o8;
			Vector512<uint> x9 = o9;
			Vector512<uint> x10 = o10;
			Vector512<uint> x11 = o11;
			Vector512<uint> x12 = o12;
			Vector512<uint> x13 = o13;
			Vector512<uint> x14 = o14;
			Vector512<uint> x15 = o15;

			for (int i = 0; i < rounds; i += 2)
			{
				QuarterRound(ref x0, ref x4, ref x8, ref x12);
				QuarterRound(ref x1, ref x5, ref x9, ref x13);
				QuarterRound(ref x2, ref x6, ref x10, ref x14);
				QuarterRound(ref x3, ref x7, ref x11, ref x15);
				QuarterRound(ref x0, ref x5, ref x10, ref x15);
				QuarterRound(ref x1, ref x6, ref x11, ref x12);
				QuarterRound(ref x2, ref x7, ref x8, ref x13);
				QuarterRound(ref x3, ref x4, ref x9, ref x14);
			}

			// x += o
			x0 += o0;
			x1 += o1;
			x2 += o2;
			x3 += o3;
			x4 += o4;
			x5 += o5;
			x6 += o6;
			x7 += o7;
			x8 += o8;
			x9 += o9;
			x10 += o10;
			x11 += o11;
			x12 += o12;
			x13 += o13;
			x14 += o14;
			x15 += o15;

			// Transpose
			Vector512<uint> a0 = Avx512F.UnpackLow(x0, x1);
			Vector512<uint> a1 = Avx512F.UnpackHigh(x0, x1);
			Vector512<uint> a2 = Avx512F.UnpackLow(x2, x3);
			Vector512<uint> a3 = Avx512F.UnpackHigh(x2, x3);
			Vector512<uint> a4 = Avx512F.UnpackLow(x4, x5);
			Vector512<uint> a5 = Avx512F.UnpackHigh(x4, x5);
			Vector512<uint> a6 = Avx512F.UnpackLow(x6, x7);
			Vector512<uint> a7 = Avx512F.UnpackHigh(x6, x7);
			Vector512<uint> a8 = Avx512F.UnpackLow(x8, x9);
			Vector512<uint> a9 = Avx512F.UnpackHigh(x8, x9);
			Vector512<uint> a10 = Avx512F.UnpackLow(x10, x11);
			Vector512<uint> a11 = Avx512F.UnpackHigh(x10, x11);
			Vector512<uint> a12 = Avx512F.UnpackLow(x12, x13);
			Vector512<uint> a13 = Avx512F.UnpackHigh(x12, x13);
			Vector512<uint> a14 = Avx512F.UnpackLow(x14, x15);
			Vector512<uint> a15 = Avx512F.UnpackHigh(x14, x15);

			Vector512<uint> b0 = Avx512F.UnpackLow(a0.AsUInt64(), a2.AsUInt64()).AsUInt32();
			Vector512<uint> b1 = Avx512F.UnpackHigh(a0.AsUInt64(), a2.AsUInt64()).AsUInt32();
			Vector512<uint> b2 = Avx512F.UnpackLow(a1.AsUInt64(), a3.AsUInt64()).AsUInt32();
			Vector512<uint> b3 = Avx512F.UnpackHigh(a1.AsUInt64(), a3.AsUInt64()).AsUInt32();
			Vector512<uint> b4 = Avx512F.UnpackLow(a4.AsUInt64(), a6.AsUInt64()).AsUInt32();
			Vector512<uint> b5 = Avx512F.UnpackHigh(a4.AsUInt64(), a6.AsUInt64()).AsUInt32();
			Vector512<uint> b6 = Avx512F.UnpackLow(a5.AsUInt64(), a7.AsUInt64()).AsUInt32();
			Vector512<uint> b7 = Avx512F.UnpackHigh(a5.AsUInt64(), a7.AsUInt64()).AsUInt32();
			Vector512<uint> b8 = Avx512F.UnpackLow(a8.AsUInt64(), a10.AsUInt64()).AsUInt32();
			Vector512<uint> b9 = Avx512F.UnpackHigh(a8.AsUInt64(), a10.AsUInt64()).AsUInt32();
			Vector512<uint> b10 = Avx512F.UnpackLow(a9.AsUInt64(), a11.AsUInt64()).AsUInt32();
			Vector512<uint> b11 = Avx512F.UnpackHigh(a9.AsUInt64(), a11.AsUInt64()).AsUInt32();
			Vector512<uint> b12 = Avx512F.UnpackLow(a12.AsUInt64(), a14.AsUInt64()).AsUInt32();
			Vector512<uint> b13 = Avx512F.UnpackHigh(a12.AsUInt64(), a14.AsUInt64()).AsUInt32();
			Vector512<uint> b14 = Avx512F.UnpackLow(a13.AsUInt64(), a15.AsUInt64()).AsUInt32();
			Vector512<uint> b15 = Avx512F.UnpackHigh(a13.AsUInt64(), a15.AsUInt64()).AsUInt32();

			Vector512<uint> c0 = Avx512F.Shuffle4x128(b0, b4, 0x88);
			Vector512<uint> c1 = Avx512F.Shuffle4x128(b1, b5, 0x88);
			Vector512<uint> c2 = Avx512F.Shuffle4x128(b2, b6, 0x88);
			Vector512<uint> c3 = Avx512F.Shuffle4x128(b3, b7, 0x88);
			Vector512<uint> c4 = Avx512F.Shuffle4x128(b0, b4, 0xDD);
			Vector512<uint> c5 = Avx512F.Shuffle4x128(b1, b5, 0xDD);
			Vector512<uint> c6 = Avx512F.Shuffle4x128(b2, b6, 0xDD);
			Vector512<uint> c7 = Avx512F.Shuffle4x128(b3, b7, 0xDD);
			Vector512<uint> c8 = Avx512F.Shuffle4x128(b8, b12, 0x88);
			Vector512<uint> c9 = Avx512F.Shuffle4x128(b9, b13, 0x88);
			Vector512<uint> c10 = Avx512F.Shuffle4x128(b10, b14, 0x88);
			Vector512<uint> c11 = Avx512F.Shuffle4x128(b11, b15, 0x88);
			Vector512<uint> c12 = Avx512F.Shuffle4x128(b8, b12, 0xDD);
			Vector512<uint> c13 = Avx512F.Shuffle4x128(b9, b13, 0xDD);
			Vector512<uint> c14 = Avx512F.Shuffle4x128(b10, b14, 0xDD);
			Vector512<uint> c15 = Avx512F.Shuffle4x128(b11, b15, 0xDD);

			x0 = Avx512F.Shuffle4x128(c0, c8, 0x88);
			x1 = Avx512F.Shuffle4x128(c1, c9, 0x88);
			x2 = Avx512F.Shuffle4x128(c2, c10, 0x88);
			x3 = Avx512F.Shuffle4x128(c3, c11, 0x88);
			x4 = Avx512F.Shuffle4x128(c4, c12, 0x88);
			x5 = Avx512F.Shuffle4x128(c5, c13, 0x88);
			x6 = Avx512F.Shuffle4x128(c6, c14, 0x88);
			x7 = Avx512F.Shuffle4x128(c7, c15, 0x88);
			x8 = Avx512F.Shuffle4x128(c0, c8, 0xDD);
			x9 = Avx512F.Shuffle4x128(c1, c9, 0xDD);
			x10 = Avx512F.Shuffle4x128(c2, c10, 0xDD);
			x11 = Avx512F.Shuffle4x128(c3, c11, 0xDD);
			x12 = Avx512F.Shuffle4x128(c4, c12, 0xDD);
			x13 = Avx512F.Shuffle4x128(c5, c13, 0xDD);
			x14 = Avx512F.Shuffle4x128(c6, c14, 0xDD);
			x15 = Avx512F.Shuffle4x128(c7, c15, 0xDD);

			// Xor
			Vector512<byte> v0 = x0.AsByte() ^ s0;
			Vector512<byte> v1 = x1.AsByte() ^ s1;
			Vector512<byte> v2 = x2.AsByte() ^ s2;
			Vector512<byte> v3 = x3.AsByte() ^ s3;
			Vector512<byte> v4 = x4.AsByte() ^ s4;
			Vector512<byte> v5 = x5.AsByte() ^ s5;
			Vector512<byte> v6 = x6.AsByte() ^ s6;
			Vector512<byte> v7 = x7.AsByte() ^ s7;
			Vector512<byte> v8 = x8.AsByte() ^ s8;
			Vector512<byte> v9 = x9.AsByte() ^ s9;
			Vector512<byte> v10 = x10.AsByte() ^ s10;
			Vector512<byte> v11 = x11.AsByte() ^ s11;
			Vector512<byte> v12 = x12.AsByte() ^ s12;
			Vector512<byte> v13 = x13.AsByte() ^ s13;
			Vector512<byte> v14 = x14.AsByte() ^ s14;
			Vector512<byte> v15 = x15.AsByte() ^ s15;

			Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, 0 * sizeOfVector), v0);
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, 1 * sizeOfVector), v1);
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, 2 * sizeOfVector), v2);
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, 3 * sizeOfVector), v3);
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, 4 * sizeOfVector), v4);
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, 5 * sizeOfVector), v5);
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, 6 * sizeOfVector), v6);
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, 7 * sizeOfVector), v7);
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, 8 * sizeOfVector), v8);
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, 9 * sizeOfVector), v9);
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, 10 * sizeOfVector), v10);
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, 11 * sizeOfVector), v11);
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, 12 * sizeOfVector), v12);
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, 13 * sizeOfVector), v13);
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, 14 * sizeOfVector), v14);
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, 15 * sizeOfVector), v15);

			counter += 16;
			sourceRef = ref Unsafe.Add(ref sourceRef, 1024);
			dstRef = ref Unsafe.Add(ref dstRef, 1024);
			offset += 1024;
			length -= 1024;
		}

		return offset;
	}
}
