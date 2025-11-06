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

	/// <summary>
	/// 4 5 6 7
	/// 8 9 10 11
	/// 12 13 14 15
	/// =>
	/// 5 6 7 4
	/// 10 11 8 9
	/// 15 12 13 14
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Shuffle(ref Vector512<uint> a, ref Vector512<uint> b, ref Vector512<uint> c)
	{
		a = Avx512F.Shuffle(a, 0b00_11_10_01);
		b = Avx512F.Shuffle(b, 0b01_00_11_10);
		c = Avx512F.Shuffle(c, 0b10_01_00_11);
	}

	/// <summary>
	/// 5 6 7 4
	/// 10 11 8 9
	/// 15 12 13 14
	/// =>
	/// 4 5 6 7
	/// 8 9 10 11
	/// 12 13 14 15
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Shuffle1(ref Vector512<uint> a, ref Vector512<uint> b, ref Vector512<uint> c)
	{
		a = Avx512F.Shuffle(a, 0b10_01_00_11);
		b = Avx512F.Shuffle(b, 0b01_00_11_10);
		c = Avx512F.Shuffle(c, 0b00_11_10_01);
	}

	/// <summary>
	/// 0 1 2 3 16 17 18 19 32 33 34 35 48 49 50 51
	/// 4 5 6 7 20 21 22 23 36 37 38 39 52 53 54 55
	/// 8 9 10 11 24 25 26 27 40 41 42 43 56 57 58 59
	/// 12 13 14 15 28 29 30 31 44 45 46 47 60 61 62 63
	/// =>
	/// 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
	/// 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31
	/// 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47
	/// 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Shuffle(ref Vector512<uint> a, ref Vector512<uint> b, ref Vector512<uint> c, ref Vector512<uint> d)
	{
		// ab_lo = [a0, a1, b0, b1], ab_hi = [a2, a3, b2, b3]
		Vector512<uint> ab_lo = Avx512F.Shuffle4x128(a, b, 0x44);
		Vector512<uint> ab_hi = Avx512F.Shuffle4x128(a, b, 0xEE);
		// cd_lo = [c0, c1, d0, d1], cd_hi = [c2, c3, d2, d3]
		Vector512<uint> cd_lo = Avx512F.Shuffle4x128(c, d, 0x44);
		Vector512<uint> cd_hi = Avx512F.Shuffle4x128(c, d, 0xEE);

		a = Avx512F.Shuffle4x128(ab_lo, cd_lo, 0x88); // [a0, b0, c0, d0]
		b = Avx512F.Shuffle4x128(ab_lo, cd_lo, 0xDD); // [a1, b1, c1, d1]
		c = Avx512F.Shuffle4x128(ab_hi, cd_hi, 0x88); // [a2, b2, c2, d2]
		d = Avx512F.Shuffle4x128(ab_hi, cd_hi, 0xDD); // [a3, b3, c3, d3]
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ChaChaCoreAoS1024Avx512(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		const int sizeOfVector = 64;
		ref uint stateRef = ref state.GetReference();
		ref byte sourceRef = ref source.GetReference();
		ref byte destRef = ref destination.GetReference();

		ref readonly Vector512<byte> src0 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 0 * sizeOfVector));
		ref readonly Vector512<byte> src1 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 1 * sizeOfVector));
		ref readonly Vector512<byte> src2 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 2 * sizeOfVector));
		ref readonly Vector512<byte> src3 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 3 * sizeOfVector));
		ref readonly Vector512<byte> src4 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 4 * sizeOfVector));
		ref readonly Vector512<byte> src5 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 5 * sizeOfVector));
		ref readonly Vector512<byte> src6 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 6 * sizeOfVector));
		ref readonly Vector512<byte> src7 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 7 * sizeOfVector));
		ref readonly Vector512<byte> src8 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 8 * sizeOfVector));
		ref readonly Vector512<byte> src9 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 9 * sizeOfVector));
		ref readonly Vector512<byte> src10 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 10 * sizeOfVector));
		ref readonly Vector512<byte> src11 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 11 * sizeOfVector));
		ref readonly Vector512<byte> src12 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 12 * sizeOfVector));
		ref readonly Vector512<byte> src13 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 13 * sizeOfVector));
		ref readonly Vector512<byte> src14 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 14 * sizeOfVector));
		ref readonly Vector512<byte> src15 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 15 * sizeOfVector));

		ref readonly Vector512<uint> vState = ref Unsafe.As<uint, Vector512<uint>>(ref Unsafe.Add(ref stateRef, 0));

		Vector512<uint> x0 = FastUtils.BroadcastVector128ToVector512(ref Unsafe.Add(ref stateRef, 0 * sizeof(uint)));
		Vector512<uint> x1 = FastUtils.BroadcastVector128ToVector512(ref Unsafe.Add(ref stateRef, 1 * sizeof(uint)));
		Vector512<uint> x2 = FastUtils.BroadcastVector128ToVector512(ref Unsafe.Add(ref stateRef, 2 * sizeof(uint)));
		Vector512<uint> x3 = FastUtils.BroadcastVector128ToVector512(ref Unsafe.Add(ref stateRef, 3 * sizeof(uint)));

		Vector512<uint> y0 = x0;
		Vector512<uint> y1 = x1;
		Vector512<uint> y2 = x2;
		Vector512<uint> y3 = x3;

		Vector512<uint> a0 = x0;
		Vector512<uint> a1 = x1;
		Vector512<uint> a2 = x2;
		Vector512<uint> a3 = x3;

		Vector512<uint> b0 = x0;
		Vector512<uint> b1 = x1;
		Vector512<uint> b2 = x2;
		Vector512<uint> b3 = x3;

		x3 += Vector512.Create(0u, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0);
		y3 += Vector512.Create(4u, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0);
		a3 += Vector512.Create(8u, 0, 0, 0, 9, 0, 0, 0, 10, 0, 0, 0, 11, 0, 0, 0);
		b3 += Vector512.Create(12u, 0, 0, 0, 13, 0, 0, 0, 14, 0, 0, 0, 15, 0, 0, 0);

		for (int i = 0; i < rounds; i += 2)
		{
			QuarterRound(ref x0, ref x1, ref x2, ref x3);
			Shuffle(ref x1, ref x2, ref x3);

			QuarterRound(ref y0, ref y1, ref y2, ref y3);
			Shuffle(ref y1, ref y2, ref y3);

			QuarterRound(ref a0, ref a1, ref a2, ref a3);
			Shuffle(ref a1, ref a2, ref a3);

			QuarterRound(ref b0, ref b1, ref b2, ref b3);
			Shuffle(ref b1, ref b2, ref b3);

			QuarterRound(ref x0, ref x1, ref x2, ref x3);
			Shuffle1(ref x1, ref x2, ref x3);

			QuarterRound(ref y0, ref y1, ref y2, ref y3);
			Shuffle1(ref y1, ref y2, ref y3);

			QuarterRound(ref a0, ref a1, ref a2, ref a3);
			Shuffle1(ref a1, ref a2, ref a3);

			QuarterRound(ref b0, ref b1, ref b2, ref b3);
			Shuffle1(ref b1, ref b2, ref b3);
		}

		Shuffle(ref x0, ref x1, ref x2, ref x3);
		Shuffle(ref y0, ref y1, ref y2, ref y3);
		Shuffle(ref a0, ref a1, ref a2, ref a3);
		Shuffle(ref b0, ref b1, ref b2, ref b3);

		x0 += vState;
		x1 += vState;
		x2 += vState;
		x3 += vState;
		y0 += vState;
		y1 += vState;
		y2 += vState;
		y3 += vState;
		a0 += vState;
		a1 += vState;
		a2 += vState;
		a3 += vState;
		b0 += vState;
		b1 += vState;
		b2 += vState;
		b3 += vState;

		x1 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0);
		x2 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0);
		x3 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0);
		y0 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0);
		y1 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0);
		y2 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0);
		y3 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0);
		a0 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0);
		a1 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0);
		a2 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0);
		a3 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, 0, 0, 0);
		b0 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0);
		b1 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13, 0, 0, 0);
		b2 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 14, 0, 0, 0);
		b3 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15, 0, 0, 0);

		Vector512<byte> v0 = x0.AsByte() ^ src0;
		Vector512<byte> v1 = x1.AsByte() ^ src1;
		Vector512<byte> v2 = x2.AsByte() ^ src2;
		Vector512<byte> v3 = x3.AsByte() ^ src3;
		Vector512<byte> v4 = y0.AsByte() ^ src4;
		Vector512<byte> v5 = y1.AsByte() ^ src5;
		Vector512<byte> v6 = y2.AsByte() ^ src6;
		Vector512<byte> v7 = y3.AsByte() ^ src7;
		Vector512<byte> v8 = a0.AsByte() ^ src8;
		Vector512<byte> v9 = a1.AsByte() ^ src9;
		Vector512<byte> v10 = a2.AsByte() ^ src10;
		Vector512<byte> v11 = a3.AsByte() ^ src11;
		Vector512<byte> v12 = b0.AsByte() ^ src12;
		Vector512<byte> v13 = b1.AsByte() ^ src13;
		Vector512<byte> v14 = b2.AsByte() ^ src14;
		Vector512<byte> v15 = b3.AsByte() ^ src15;

		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 0 * sizeOfVector), v0);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 1 * sizeOfVector), v1);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 2 * sizeOfVector), v2);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 3 * sizeOfVector), v3);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 4 * sizeOfVector), v4);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 5 * sizeOfVector), v5);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 6 * sizeOfVector), v6);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 7 * sizeOfVector), v7);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 8 * sizeOfVector), v8);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 9 * sizeOfVector), v9);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 10 * sizeOfVector), v10);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 11 * sizeOfVector), v11);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 12 * sizeOfVector), v12);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 13 * sizeOfVector), v13);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 14 * sizeOfVector), v14);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 15 * sizeOfVector), v15);

		GetCounter(ref stateRef) += 16;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ChaChaCoreAoS2048Avx512(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		const int sizeOfVector = 64;
		ref uint stateRef = ref state.GetReference();
		ref byte sourceRef = ref source.GetReference();
		ref byte destRef = ref destination.GetReference();

		ref readonly Vector512<byte> src0 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 0 * sizeOfVector));
		ref readonly Vector512<byte> src1 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 1 * sizeOfVector));
		ref readonly Vector512<byte> src2 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 2 * sizeOfVector));
		ref readonly Vector512<byte> src3 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 3 * sizeOfVector));
		ref readonly Vector512<byte> src4 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 4 * sizeOfVector));
		ref readonly Vector512<byte> src5 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 5 * sizeOfVector));
		ref readonly Vector512<byte> src6 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 6 * sizeOfVector));
		ref readonly Vector512<byte> src7 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 7 * sizeOfVector));
		ref readonly Vector512<byte> src8 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 8 * sizeOfVector));
		ref readonly Vector512<byte> src9 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 9 * sizeOfVector));
		ref readonly Vector512<byte> src10 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 10 * sizeOfVector));
		ref readonly Vector512<byte> src11 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 11 * sizeOfVector));
		ref readonly Vector512<byte> src12 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 12 * sizeOfVector));
		ref readonly Vector512<byte> src13 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 13 * sizeOfVector));
		ref readonly Vector512<byte> src14 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 14 * sizeOfVector));
		ref readonly Vector512<byte> src15 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 15 * sizeOfVector));
		ref readonly Vector512<byte> src16 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 16 * sizeOfVector));
		ref readonly Vector512<byte> src17 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 17 * sizeOfVector));
		ref readonly Vector512<byte> src18 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 18 * sizeOfVector));
		ref readonly Vector512<byte> src19 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 19 * sizeOfVector));
		ref readonly Vector512<byte> src20 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 20 * sizeOfVector));
		ref readonly Vector512<byte> src21 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 21 * sizeOfVector));
		ref readonly Vector512<byte> src22 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 22 * sizeOfVector));
		ref readonly Vector512<byte> src23 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 23 * sizeOfVector));
		ref readonly Vector512<byte> src24 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 24 * sizeOfVector));
		ref readonly Vector512<byte> src25 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 25 * sizeOfVector));
		ref readonly Vector512<byte> src26 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 26 * sizeOfVector));
		ref readonly Vector512<byte> src27 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 27 * sizeOfVector));
		ref readonly Vector512<byte> src28 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 28 * sizeOfVector));
		ref readonly Vector512<byte> src29 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 29 * sizeOfVector));
		ref readonly Vector512<byte> src30 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 30 * sizeOfVector));
		ref readonly Vector512<byte> src31 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, 31 * sizeOfVector));

		ref readonly Vector512<uint> vState = ref Unsafe.As<uint, Vector512<uint>>(ref Unsafe.Add(ref stateRef, 0));

		Vector512<uint> x0 = FastUtils.BroadcastVector128ToVector512(ref Unsafe.Add(ref stateRef, 0 * sizeof(uint)));
		Vector512<uint> x1 = FastUtils.BroadcastVector128ToVector512(ref Unsafe.Add(ref stateRef, 1 * sizeof(uint)));
		Vector512<uint> x2 = FastUtils.BroadcastVector128ToVector512(ref Unsafe.Add(ref stateRef, 2 * sizeof(uint)));
		Vector512<uint> x3 = FastUtils.BroadcastVector128ToVector512(ref Unsafe.Add(ref stateRef, 3 * sizeof(uint)));

		Vector512<uint> y0 = x0;
		Vector512<uint> y1 = x1;
		Vector512<uint> y2 = x2;
		Vector512<uint> y3 = x3;

		Vector512<uint> a0 = x0;
		Vector512<uint> a1 = x1;
		Vector512<uint> a2 = x2;
		Vector512<uint> a3 = x3;

		Vector512<uint> b0 = x0;
		Vector512<uint> b1 = x1;
		Vector512<uint> b2 = x2;
		Vector512<uint> b3 = x3;

		Vector512<uint> c0 = x0;
		Vector512<uint> c1 = x1;
		Vector512<uint> c2 = x2;
		Vector512<uint> c3 = x3;

		Vector512<uint> d0 = x0;
		Vector512<uint> d1 = x1;
		Vector512<uint> d2 = x2;
		Vector512<uint> d3 = x3;

		Vector512<uint> e0 = x0;
		Vector512<uint> e1 = x1;
		Vector512<uint> e2 = x2;
		Vector512<uint> e3 = x3;

		Vector512<uint> f0 = x0;
		Vector512<uint> f1 = x1;
		Vector512<uint> f2 = x2;
		Vector512<uint> f3 = x3;

		x3 += Vector512.Create(0u, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0);
		y3 += Vector512.Create(4u, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0);
		a3 += Vector512.Create(8u, 0, 0, 0, 9, 0, 0, 0, 10, 0, 0, 0, 11, 0, 0, 0);
		b3 += Vector512.Create(12u, 0, 0, 0, 13, 0, 0, 0, 14, 0, 0, 0, 15, 0, 0, 0);
		c3 += Vector512.Create(16u, 0, 0, 0, 17, 0, 0, 0, 18, 0, 0, 0, 19, 0, 0, 0);
		d3 += Vector512.Create(20u, 0, 0, 0, 21, 0, 0, 0, 22, 0, 0, 0, 23, 0, 0, 0);
		e3 += Vector512.Create(24u, 0, 0, 0, 25, 0, 0, 0, 26, 0, 0, 0, 27, 0, 0, 0);
		f3 += Vector512.Create(28u, 0, 0, 0, 29, 0, 0, 0, 30, 0, 0, 0, 31, 0, 0, 0);

		for (int i = 0; i < rounds; i += 2)
		{
			QuarterRound(ref x0, ref x1, ref x2, ref x3);
			Shuffle(ref x1, ref x2, ref x3);

			QuarterRound(ref y0, ref y1, ref y2, ref y3);
			Shuffle(ref y1, ref y2, ref y3);

			QuarterRound(ref a0, ref a1, ref a2, ref a3);
			Shuffle(ref a1, ref a2, ref a3);

			QuarterRound(ref b0, ref b1, ref b2, ref b3);
			Shuffle(ref b1, ref b2, ref b3);

			QuarterRound(ref c0, ref c1, ref c2, ref c3);
			Shuffle(ref c1, ref c2, ref c3);

			QuarterRound(ref d0, ref d1, ref d2, ref d3);
			Shuffle(ref d1, ref d2, ref d3);

			QuarterRound(ref e0, ref e1, ref e2, ref e3);
			Shuffle(ref e1, ref e2, ref e3);

			QuarterRound(ref f0, ref f1, ref f2, ref f3);
			Shuffle(ref f1, ref f2, ref f3);

			QuarterRound(ref x0, ref x1, ref x2, ref x3);
			Shuffle1(ref x1, ref x2, ref x3);

			QuarterRound(ref y0, ref y1, ref y2, ref y3);
			Shuffle1(ref y1, ref y2, ref y3);

			QuarterRound(ref a0, ref a1, ref a2, ref a3);
			Shuffle1(ref a1, ref a2, ref a3);

			QuarterRound(ref b0, ref b1, ref b2, ref b3);
			Shuffle1(ref b1, ref b2, ref b3);

			QuarterRound(ref c0, ref c1, ref c2, ref c3);
			Shuffle1(ref c1, ref c2, ref c3);

			QuarterRound(ref d0, ref d1, ref d2, ref d3);
			Shuffle1(ref d1, ref d2, ref d3);

			QuarterRound(ref e0, ref e1, ref e2, ref e3);
			Shuffle1(ref e1, ref e2, ref e3);

			QuarterRound(ref f0, ref f1, ref f2, ref f3);
			Shuffle1(ref f1, ref f2, ref f3);
		}

		Shuffle(ref x0, ref x1, ref x2, ref x3);
		Shuffle(ref y0, ref y1, ref y2, ref y3);
		Shuffle(ref a0, ref a1, ref a2, ref a3);
		Shuffle(ref b0, ref b1, ref b2, ref b3);
		Shuffle(ref c0, ref c1, ref c2, ref c3);
		Shuffle(ref d0, ref d1, ref d2, ref d3);
		Shuffle(ref e0, ref e1, ref e2, ref e3);
		Shuffle(ref f0, ref f1, ref f2, ref f3);

		x0 += vState;
		x1 += vState;
		x2 += vState;
		x3 += vState;
		y0 += vState;
		y1 += vState;
		y2 += vState;
		y3 += vState;
		a0 += vState;
		a1 += vState;
		a2 += vState;
		a3 += vState;
		b0 += vState;
		b1 += vState;
		b2 += vState;
		b3 += vState;
		c0 += vState;
		c1 += vState;
		c2 += vState;
		c3 += vState;
		d0 += vState;
		d1 += vState;
		d2 += vState;
		d3 += vState;
		e0 += vState;
		e1 += vState;
		e2 += vState;
		e3 += vState;
		f0 += vState;
		f1 += vState;
		f2 += vState;
		f3 += vState;

		x1 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0);
		x2 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0);
		x3 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0);
		y0 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0);
		y1 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0);
		y2 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0);
		y3 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0);
		a0 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0);
		a1 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0);
		a2 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0);
		a3 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, 0, 0, 0);
		b0 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0);
		b1 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13, 0, 0, 0);
		b2 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 14, 0, 0, 0);
		b3 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15, 0, 0, 0);
		c0 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0);
		c1 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0);
		c2 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 0, 0, 0);
		c3 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 19, 0, 0, 0);
		d0 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0);
		d1 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 21, 0, 0, 0);
		d2 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 22, 0, 0, 0);
		d3 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 23, 0, 0, 0);
		e0 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 0, 0, 0);
		e1 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 25, 0, 0, 0);
		e2 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 26, 0, 0, 0);
		e3 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 27, 0, 0, 0);
		f0 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 28, 0, 0, 0);
		f1 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 29, 0, 0, 0);
		f2 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 30, 0, 0, 0);
		f3 += Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 31, 0, 0, 0);

		Vector512<byte> v0 = x0.AsByte() ^ src0;
		Vector512<byte> v1 = x1.AsByte() ^ src1;
		Vector512<byte> v2 = x2.AsByte() ^ src2;
		Vector512<byte> v3 = x3.AsByte() ^ src3;
		Vector512<byte> v4 = y0.AsByte() ^ src4;
		Vector512<byte> v5 = y1.AsByte() ^ src5;
		Vector512<byte> v6 = y2.AsByte() ^ src6;
		Vector512<byte> v7 = y3.AsByte() ^ src7;
		Vector512<byte> v8 = a0.AsByte() ^ src8;
		Vector512<byte> v9 = a1.AsByte() ^ src9;
		Vector512<byte> v10 = a2.AsByte() ^ src10;
		Vector512<byte> v11 = a3.AsByte() ^ src11;
		Vector512<byte> v12 = b0.AsByte() ^ src12;
		Vector512<byte> v13 = b1.AsByte() ^ src13;
		Vector512<byte> v14 = b2.AsByte() ^ src14;
		Vector512<byte> v15 = b3.AsByte() ^ src15;
		Vector512<byte> v16 = c0.AsByte() ^ src16;
		Vector512<byte> v17 = c1.AsByte() ^ src17;
		Vector512<byte> v18 = c2.AsByte() ^ src18;
		Vector512<byte> v19 = c3.AsByte() ^ src19;
		Vector512<byte> v20 = d0.AsByte() ^ src20;
		Vector512<byte> v21 = d1.AsByte() ^ src21;
		Vector512<byte> v22 = d2.AsByte() ^ src22;
		Vector512<byte> v23 = d3.AsByte() ^ src23;
		Vector512<byte> v24 = e0.AsByte() ^ src24;
		Vector512<byte> v25 = e1.AsByte() ^ src25;
		Vector512<byte> v26 = e2.AsByte() ^ src26;
		Vector512<byte> v27 = e3.AsByte() ^ src27;
		Vector512<byte> v28 = f0.AsByte() ^ src28;
		Vector512<byte> v29 = f1.AsByte() ^ src29;
		Vector512<byte> v30 = f2.AsByte() ^ src30;
		Vector512<byte> v31 = f3.AsByte() ^ src31;

		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 0 * sizeOfVector), v0);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 1 * sizeOfVector), v1);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 2 * sizeOfVector), v2);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 3 * sizeOfVector), v3);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 4 * sizeOfVector), v4);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 5 * sizeOfVector), v5);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 6 * sizeOfVector), v6);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 7 * sizeOfVector), v7);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 8 * sizeOfVector), v8);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 9 * sizeOfVector), v9);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 10 * sizeOfVector), v10);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 11 * sizeOfVector), v11);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 12 * sizeOfVector), v12);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 13 * sizeOfVector), v13);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 14 * sizeOfVector), v14);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 15 * sizeOfVector), v15);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 16 * sizeOfVector), v16);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 17 * sizeOfVector), v17);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 18 * sizeOfVector), v18);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 19 * sizeOfVector), v19);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 20 * sizeOfVector), v20);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 21 * sizeOfVector), v21);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 22 * sizeOfVector), v22);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 23 * sizeOfVector), v23);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 24 * sizeOfVector), v24);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 25 * sizeOfVector), v25);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 26 * sizeOfVector), v26);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 27 * sizeOfVector), v27);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 28 * sizeOfVector), v28);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 29 * sizeOfVector), v29);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 30 * sizeOfVector), v30);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 31 * sizeOfVector), v31);

		GetCounter(ref stateRef) += 32;
	}
}
