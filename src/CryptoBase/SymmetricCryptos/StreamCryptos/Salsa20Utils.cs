using CryptoBase.Abstractions.SymmetricCryptos;

namespace CryptoBase.SymmetricCryptos.StreamCryptos;

public static class Salsa20Utils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void UpdateKeyStream(int rounds, uint[] state, byte[] keyStream)
	{
		var x = ArrayPool<uint>.Shared.Rent(SnuffleCryptoBase.StateSize);
		try
		{
			state.AsSpan().CopyTo(x);

			SalsaRound(rounds, x);

			for (var i = 0; i < SnuffleCryptoBase.StateSize; i += 4)
			{
				x[i] += state[i];
				x[i + 1] += state[i + 1];
				x[i + 2] += state[i + 2];
				x[i + 3] += state[i + 3];
			}

			var span = MemoryMarshal.Cast<byte, uint>(keyStream.AsSpan(0, 64));
			x.AsSpan(0, SnuffleCryptoBase.StateSize).CopyTo(span);
		}
		finally
		{
			ArrayPool<uint>.Shared.Return(x);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void SalsaRound(int rounds, uint[] x)
	{
		for (var i = 0; i < rounds; i += 2)
		{
			QuarterRound(x, 4, 0, 12, 8);
			QuarterRound(x, 9, 5, 1, 13);
			QuarterRound(x, 14, 10, 6, 2);
			QuarterRound(x, 3, 15, 11, 7);

			QuarterRound(x, 1, 0, 3, 2);
			QuarterRound(x, 6, 5, 4, 7);
			QuarterRound(x, 11, 10, 9, 8);
			QuarterRound(x, 12, 15, 14, 13);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void QuarterRound(uint[] x, int a, int b, int c, int d)
	{
		Step(ref x[a], x[b], x[c], 7);
		Step(ref x[d], x[a], x[b], 9);
		Step(ref x[c], x[d], x[a], 13);
		Step(ref x[b], x[c], x[d], 18);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Step(ref uint a, uint b, uint c, byte i)
	{
		a ^= (b + c).RotateLeft(i);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void QuarterRound(ref Vector128<uint> a, ref Vector128<uint> b, ref Vector128<uint> c, ref Vector128<uint> d)
	{
		a = Sse2.Xor(a, Sse2.Add(b, c).RotateLeftUInt32(7));
		d = Sse2.Xor(d, Sse2.Add(a, b).RotateLeftUInt32(9));
		c = Sse2.Xor(c, Sse2.Add(d, a).RotateLeftUInt32(13));
		b = Sse2.Xor(b, Sse2.Add(c, d).RotateLeftUInt32(18));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void QuarterRound(ref Vector256<uint> a, ref Vector256<uint> b, ref Vector256<uint> c, ref Vector256<uint> d)
	{
		a = Avx2.Xor(a, Avx2.Add(b, c).RotateLeftUInt32(7));
		d = Avx2.Xor(d, Avx2.Add(a, b).RotateLeftUInt32(9));
		c = Avx2.Xor(c, Avx2.Add(d, a).RotateLeftUInt32(13));
		b = Avx2.Xor(b, Avx2.Add(c, d).RotateLeftUInt32(18));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static unsafe void UpdateKeyStream(uint* state, byte* stream, byte rounds)
	{
		var s0 = Sse2.LoadVector128(state);
		var s1 = Sse2.LoadVector128(state + 4);
		var s2 = Sse2.LoadVector128(state + 8);
		var s3 = Sse2.LoadVector128(state + 12);

		var x0 = Vector128.Create(*(state + 4), *(state + 9), *(state + 14), *(state + 3));  // 4 9 14 3
		var x1 = Vector128.Create(*(state + 0), *(state + 5), *(state + 10), *(state + 15)); // 0 5 10 15
		var x2 = Vector128.Create(*(state + 12), *(state + 1), *(state + 6), *(state + 11)); // 12 1 6 11
		var x3 = Vector128.Create(*(state + 8), *(state + 13), *(state + 2), *(state + 7));  // 8 13 2 7

		for (var i = 0; i < rounds; i += 2)
		{
			QuarterRound(ref x0, ref x1, ref x2, ref x3);
			Shuffle(ref x0, ref x2, ref x3);

			QuarterRound(ref x0, ref x1, ref x2, ref x3);
			Shuffle(ref x0, ref x2, ref x3);
		}

		Shuffle(ref x0, ref x1, ref x2, ref x3);

		x0 = Sse2.Add(x0, s0);
		x1 = Sse2.Add(x1, s1);
		x2 = Sse2.Add(x2, s2);
		x3 = Sse2.Add(x3, s3);

		Sse2.Store(stream, x0.AsByte());
		Sse2.Store(stream + 16, x1.AsByte());
		Sse2.Store(stream + 32, x2.AsByte());
		Sse2.Store(stream + 48, x3.AsByte());
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static unsafe void SalsaRound(uint* state, byte rounds)
	{
		var x0 = Vector128.Create(*(state + 4), *(state + 9), *(state + 14), *(state + 3));  // 4 9 14 3
		var x1 = Vector128.Create(*(state + 0), *(state + 5), *(state + 10), *(state + 15)); // 0 5 10 15
		var x2 = Vector128.Create(*(state + 12), *(state + 1), *(state + 6), *(state + 11)); // 12 1 6 11
		var x3 = Vector128.Create(*(state + 8), *(state + 13), *(state + 2), *(state + 7));  // 8 13 2 7

		for (var i = 0; i < rounds; i += 2)
		{
			QuarterRound(ref x0, ref x1, ref x2, ref x3);
			Shuffle(ref x0, ref x2, ref x3);

			QuarterRound(ref x0, ref x1, ref x2, ref x3);
			Shuffle(ref x0, ref x2, ref x3);
		}

		if (Avx.IsSupported && Avx2.IsSupported)
		{
			Shuffle(ref x0, ref x1, ref x2, ref x3, out var a, out var b);

			Avx.Store(state, a);
			Avx.Store(state + 8, b);
		}
		else
		{
			Shuffle(ref x0, ref x1, ref x2, ref x3);

			Sse2.Store(state, x0);
			Sse2.Store(state + 4, x1);
			Sse2.Store(state + 8, x2);
			Sse2.Store(state + 12, x3);
		}
	}

	/// <summary>
	/// 0 1 2 3
	/// 4 5 6 7
	/// 8 9 10 11
	/// =>
	/// 5 6 7 4
	/// 3 0 1 2
	/// 10 11 8 9
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Shuffle(ref Vector128<uint> a, ref Vector128<uint> b, ref Vector128<uint> c)
	{
		(a, b) = (b, a);
		a = Sse2.Shuffle(a, 0b00_11_10_01);
		b = Sse2.Shuffle(b, 0b10_01_00_11);
		c = Sse2.Shuffle(c, 0b01_00_11_10);
	}

	/// <summary>
	/// 4 9 14 3
	/// 0 5 10 15
	/// 12 1 6 11
	/// 8 13 2 7
	/// =>
	/// 0 1 2 3
	/// 4 5 6 7
	/// 8 9 10 11
	/// 12 13 14 15
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Shuffle(ref Vector128<uint> a, ref Vector128<uint> b, ref Vector128<uint> c, ref Vector128<uint> d)
	{
		a = Sse2.Shuffle(a, 0b10_01_00_11); // 4 9 14 3 => 3 4 9 14
											// 0 5 10 15
		c = Sse2.Shuffle(c, 0b00_11_10_01); // 12 1 6 11 => 1 6 11 12
		d = Sse2.Shuffle(d, 0b01_00_11_10); // 8 13 2 7 => 2 7 8 13

		var t0 = Sse2.UnpackLow(b, c);  // 0 1 5 6
		var t1 = Sse2.UnpackLow(d, a);  // 2 3 7 4
		var t2 = Sse2.UnpackHigh(b, c); // 10 11 15 12
		var t3 = Sse2.UnpackHigh(d, a); // 8 9 13 14

		a = Sse2.UnpackLow(t0.AsUInt64(), t1.AsUInt64()).AsUInt32(); // 0 1 2 3
		b = Sse2.Shuffle(Sse2.UnpackHigh(t0, t1), 0b01_10_00_11);    // 5 7 6 4 => 4 5 6 7
		c = Sse2.UnpackLow(t3.AsUInt64(), t2.AsUInt64()).AsUInt32(); // 8 9 10 11
		d = Sse2.Shuffle(Sse2.UnpackHigh(t2, t3), 0b00_11_01_10);    // 15 13 12 14 => 12 13 14 15
	}

	#region Avx

	private static readonly Vector256<uint> Permute0 = Vector256.Create(4, 3, 1, 6, 0, 5, 2, 7).AsUInt32();
	private static readonly Vector256<uint> Permute1 = Vector256.Create(1, 6, 4, 3, 2, 7, 0, 5).AsUInt32();
	private static readonly Vector256<uint> Permute2 = Vector256.Create(0, 1, 3, 2, 4, 6, 5, 7).AsUInt32();
	private static readonly Vector256<uint> Permute3 = Vector256.Create(1, 0, 2, 3, 5, 7, 4, 6).AsUInt32();
	private static readonly Vector256<uint> Permute4 = Vector256.Create(1, 2, 3, 0, 5, 6, 7, 4).AsUInt32();
	private static readonly Vector256<uint> Permute5 = Vector256.Create(3, 0, 1, 2, 7, 4, 5, 6).AsUInt32();
	private static readonly Vector256<uint> Permute6 = Vector256.Create(2, 3, 0, 1, 6, 7, 4, 5).AsUInt32();
	private static readonly Vector256<uint> Permute7 = Vector256.Create(3, 7, 1, 5, 0, 4, 2, 6).AsUInt32();
	private static readonly Vector256<uint> Permute8 = Vector256.Create(0, 4, 2, 6, 1, 5, 3, 7).AsUInt32();
	private static readonly Vector256<uint> Permute9 = Vector256.Create(1, 5, 3, 7, 2, 6, 0, 4).AsUInt32();
	private static readonly Vector256<uint> Permute10 = Vector256.Create(2, 6, 0, 4, 3, 7, 1, 5).AsUInt32();
	private static readonly Vector256<uint> Permute11 = Vector256.Create(2, 1, 3, 0, 4, 6, 5, 7).AsUInt32();
	private static readonly Vector256<uint> Permute12 = Vector256.Create(3, 0, 2, 1, 5, 7, 4, 6).AsUInt32();

	/// <summary>
	/// 4 9 14 3
	/// 0 5 10 15
	/// 12 1 6 11
	/// 8 13 2 7
	/// =>
	/// 0 1 2 3 4 5 6 7
	/// 8 9 10 11 12 13 14 15
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Shuffle(
		ref Vector128<uint> a, ref Vector128<uint> b, ref Vector128<uint> c, ref Vector128<uint> d,
		out Vector256<uint> x0, out Vector256<uint> x1)
	{
		x0 = Vector256.Create(a, b); // 4 9 14 3 0 5 10 15
		x1 = Vector256.Create(c, d); // 12 1 6 11 8 13 2 7

		x0 = Avx2.PermuteVar8x32(x0, Permute0); // 0 3 9 10 4 5 14 15
		x1 = Avx2.PermuteVar8x32(x1, Permute1); // 1 2 8 11 6 7 12 13

		var t = Avx2.UnpackLow(x0, x1); // 0 1 3 2 4 6 5 7
		x1 = Avx2.UnpackHigh(x0, x1);   // 9 8 10 11 14 12 15 13

		x0 = Avx2.PermuteVar8x32(t, Permute2);  // 0 1 2 3 4 5 6 7
		x1 = Avx2.PermuteVar8x32(x1, Permute3); // 8 9 10 11 12 13 14 15
	}

	/// <summary>
	/// 0 1 2 3 12 13 14 15
	/// 4 5 6 7 16 17 18 19
	/// 8 9 10 11 20 21 22 23
	/// =>
	/// 5 6 7 4 17 18 19 16
	/// 3 0 1 2 15 12 13 14
	/// 10 11 8 9 22 23 20 21
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Shuffle(ref Vector256<uint> a, ref Vector256<uint> b, ref Vector256<uint> c)
	{
		(a, b) = (b, a);
		a = Avx2.PermuteVar8x32(a, Permute4);
		b = Avx2.PermuteVar8x32(b, Permute5);
		c = Avx2.PermuteVar8x32(c, Permute6);
	}

	/// <summary>
	/// 4 9 14 3 20 25 30 19
	/// 0 5 10 15 16 21 26 31
	/// 12 1 6 11 28 17 22 27
	/// 8 13 2 7 24 29 18 23
	/// =>
	/// 0 1 2 3 4 5 6 7
	/// 8 9 10 11 12 13 14 15
	/// 16 17 18 19 20 21 22 23
	/// 24 25 26 27 28 29 30 31
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Shuffle(ref Vector256<uint> a, ref Vector256<uint> b, ref Vector256<uint> c, ref Vector256<uint> d)
	{
		a = Avx2.PermuteVar8x32(a, Permute7);  // 3 19 9 25 4 20 14 30
		b = Avx2.PermuteVar8x32(b, Permute8);  // 0 16 10 26 5 21 15 31
		c = Avx2.PermuteVar8x32(c, Permute9);  // 1 17 11 27 6 22 12 28
		d = Avx2.PermuteVar8x32(d, Permute10); // 2 18 8 24 7 23 13 29

		var t0 = Avx2.UnpackLow(a, b);  // 3 0 19 16 4 5 20 21
		var t1 = Avx2.UnpackLow(c, d);  // 1 2 17 18 6 7 22 23
		var t2 = Avx2.UnpackHigh(a, b); // 9 10 25 26 14 15 30 31
		var t3 = Avx2.UnpackHigh(c, d); // 11 8 27 24 12 13 28 29

		a = Avx2.UnpackLow(t0, t1);  // 3 1 0 2 4 6 5 7
		b = Avx2.UnpackLow(t2, t3);  // 9 11 10 8 14 12 15 13
		c = Avx2.UnpackHigh(t0, t1); // 19 17 16 18 20 22 21 23
		d = Avx2.UnpackHigh(t2, t3); // 25 27 26 24 30 28 31 29

		a = Avx2.PermuteVar8x32(a, Permute11); // 0 1 2 3 4 5 6 7
		b = Avx2.PermuteVar8x32(b, Permute12); // 8 9 10 11 12 13 14 15
		c = Avx2.PermuteVar8x32(c, Permute11); // 16 17 18 19 20 21 22 23
		d = Avx2.PermuteVar8x32(d, Permute12); // 24 25 26 27 28 29 30 31
	}

	#endregion

	/// <summary>
	/// 处理 64 bytes
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static unsafe void SalsaCore64(byte rounds, uint* state, byte* source, byte* destination)
	{
		var s0 = Sse2.LoadVector128(state);
		var s1 = Sse2.LoadVector128(state + 4);
		var s2 = Sse2.LoadVector128(state + 8);
		var s3 = Sse2.LoadVector128(state + 12);

		var x0 = Vector128.Create(*(state + 4), *(state + 9), *(state + 14), *(state + 3));  // 4 9 14 3
		var x1 = Vector128.Create(*(state + 0), *(state + 5), *(state + 10), *(state + 15)); // 0 5 10 15
		var x2 = Vector128.Create(*(state + 12), *(state + 1), *(state + 6), *(state + 11)); // 12 1 6 11
		var x3 = Vector128.Create(*(state + 8), *(state + 13), *(state + 2), *(state + 7));  // 8 13 2 7

		for (var i = 0; i < rounds; i += 2)
		{
			QuarterRound(ref x0, ref x1, ref x2, ref x3);
			Shuffle(ref x0, ref x2, ref x3);

			QuarterRound(ref x0, ref x1, ref x2, ref x3);
			Shuffle(ref x0, ref x2, ref x3);
		}

		Shuffle(ref x0, ref x1, ref x2, ref x3);

		x0 = Sse2.Add(x0, s0);
		x1 = Sse2.Add(x1, s1);
		x2 = Sse2.Add(x2, s2);
		x3 = Sse2.Add(x3, s3);

		var v0 = Sse2.Xor(x0.AsByte(), Sse2.LoadVector128(source));
		var v1 = Sse2.Xor(x1.AsByte(), Sse2.LoadVector128(source + 16));
		var v2 = Sse2.Xor(x2.AsByte(), Sse2.LoadVector128(source + 32));
		var v3 = Sse2.Xor(x3.AsByte(), Sse2.LoadVector128(source + 48));

		Sse2.Store(destination, v0);
		Sse2.Store(destination + 16, v1);
		Sse2.Store(destination + 32, v2);
		Sse2.Store(destination + 48, v3);

		if (++*(state + 8) == 0)
		{
			++*(state + 9);
		}
	}

	/// <summary>
	/// 处理 128 bytes
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static unsafe void SalsaCore128(byte rounds, uint* state, byte* source, byte* destination)
	{
		var t8 = *(state + 8);
		var t9 = *(state + 9);

		var s1 = Avx.LoadVector256(state + 8); // 8 9 10 11 12 13 14 15

		if (++*(state + 8) == 0)
		{
			++*(state + 9);
		}

		// 4 9 14 3
		var x0 = Vector256.Create(
			*(state + 4), t9, *(state + 14), *(state + 3),
			*(state + 4), *(state + 9), *(state + 14), *(state + 3));
		// 0 5 10 15
		var x1 = Vector256.Create(
			*(state + 0), *(state + 5), *(state + 10), *(state + 15),
			*(state + 0), *(state + 5), *(state + 10), *(state + 15));
		// 12 1 6 11
		var x2 = Vector256.Create(
			*(state + 12), *(state + 1), *(state + 6), *(state + 11),
			*(state + 12), *(state + 1), *(state + 6), *(state + 11));
		// 8 13 2 7
		var x3 = Vector256.Create(
			t8, *(state + 13), *(state + 2), *(state + 7),
			*(state + 8), *(state + 13), *(state + 2), *(state + 7)
		);

		for (var i = 0; i < rounds; i += 2)
		{
			QuarterRound(ref x0, ref x1, ref x2, ref x3);
			Shuffle(ref x0, ref x2, ref x3);

			QuarterRound(ref x0, ref x1, ref x2, ref x3);
			Shuffle(ref x0, ref x2, ref x3);
		}

		Shuffle(ref x0, ref x1, ref x2, ref x3);

		var s0 = Avx.LoadVector256(state); // 0 1 2 3 4 5 6 7

		x0 = Avx2.Add(x0, s0);
		x1 = Avx2.Add(x1, s1);
		x2 = Avx2.Add(x2, s0);
		x3 = Avx2.Add(x3, Avx.LoadVector256(state + 8));

		var v0 = Avx2.Xor(x0.AsByte(), Avx.LoadVector256(source));
		var v1 = Avx2.Xor(x1.AsByte(), Avx.LoadVector256(source + 32));
		var v2 = Avx2.Xor(x2.AsByte(), Avx.LoadVector256(source + 64));
		var v3 = Avx2.Xor(x3.AsByte(), Avx.LoadVector256(source + 96));

		Avx.Store(destination, v0);
		Avx.Store(destination + 32, v1);
		Avx.Store(destination + 64, v2);
		Avx.Store(destination + 96, v3);

		if (++*(state + 8) == 0)
		{
			++*(state + 9);
		}
	}

	#region 处理 256*n bytes

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static unsafe void SalsaCore256(byte rounds, uint* state, ref byte* source, ref byte* destination, ref int length)
	{
		#region s

		var s0 = Vector128.Create(*(state + 0));
		var s1 = Vector128.Create(*(state + 1));
		var s2 = Vector128.Create(*(state + 2));
		var s3 = Vector128.Create(*(state + 3));
		var s4 = Vector128.Create(*(state + 4));
		var s5 = Vector128.Create(*(state + 5));
		var s6 = Vector128.Create(*(state + 6));
		var s7 = Vector128.Create(*(state + 7));
		// s8
		// s9
		var s10 = Vector128.Create(*(state + 10));
		var s11 = Vector128.Create(*(state + 11));
		var s12 = Vector128.Create(*(state + 12));
		var s13 = Vector128.Create(*(state + 13));
		var s14 = Vector128.Create(*(state + 14));
		var s15 = Vector128.Create(*(state + 15));

		#endregion

		while (length >= 256)
		{
			#region x

			var x0 = s0;
			var x1 = s1;
			var x2 = s2;
			var x3 = s3;
			var x4 = s4;
			var x5 = s5;
			var x6 = s6;
			var x7 = s7;
			var x10 = s10;
			var x11 = s11;
			var x12 = s12;
			var x13 = s13;
			var x14 = s14;
			var x15 = s15;

			#endregion

			#region 8 9 位分别加 0 1 2 3

			var o = *(state + 8) | (ulong)*(state + 9) << 32;
			var vo = Vector128.Create(o);

			var x8 = Sse2.Add(ChaCha20Utils.IncCounter01, vo).AsUInt32();
			var x9 = Sse2.Add(ChaCha20Utils.IncCounter23, vo).AsUInt32();

			var t8 = Sse2.UnpackLow(x8, x9);
			var t9 = Sse2.UnpackHigh(x8, x9);

			x8 = Sse2.UnpackLow(t8, t9);
			x9 = Sse2.UnpackHigh(t8, t9);

			var s8 = x8;
			var s9 = x9;

			o += 4;
			*(state + 8) = (uint)(o & 0xFFFFFFFF);
			*(state + 9) = (uint)(o >> 32 & 0xFFFFFFFF);

			#endregion

			for (var i = 0; i < rounds; i += 2)
			{
				QuarterRound(ref x4, ref x0, ref x12, ref x8);
				QuarterRound(ref x9, ref x5, ref x1, ref x13);
				QuarterRound(ref x14, ref x10, ref x6, ref x2);
				QuarterRound(ref x3, ref x15, ref x11, ref x7);

				QuarterRound(ref x1, ref x0, ref x3, ref x2);
				QuarterRound(ref x6, ref x5, ref x4, ref x7);
				QuarterRound(ref x11, ref x10, ref x9, ref x8);
				QuarterRound(ref x12, ref x15, ref x14, ref x13);
			}

			ChaCha20Utils.AddTransposeXor(ref x0, ref x1, ref x2, ref x3, ref s0, ref s1, ref s2, ref s3, source, destination);
			ChaCha20Utils.AddTransposeXor(ref x4, ref x5, ref x6, ref x7, ref s4, ref s5, ref s6, ref s7, source + 16, destination + 16);
			ChaCha20Utils.AddTransposeXor(ref x8, ref x9, ref x10, ref x11, ref s8, ref s9, ref s10, ref s11, source + 32, destination + 32);
			ChaCha20Utils.AddTransposeXor(ref x12, ref x13, ref x14, ref x15, ref s12, ref s13, ref s14, ref s15, source + 48, destination + 48);

			source += 256;
			destination += 256;
			length -= 256;
		}
	}

	#endregion

	#region 处理 512*n bytes

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static unsafe void SalsaCore512(byte rounds, uint* state, ref byte* source, ref byte* destination, ref int length)
	{
		var o0 = Vector256.Create(*(state + 0));
		var o1 = Vector256.Create(*(state + 1));
		var o2 = Vector256.Create(*(state + 2));
		var o3 = Vector256.Create(*(state + 3));
		var o4 = Vector256.Create(*(state + 4));
		var o5 = Vector256.Create(*(state + 5));
		var o6 = Vector256.Create(*(state + 6));
		var o7 = Vector256.Create(*(state + 7));
		var o10 = Vector256.Create(*(state + 10));
		var o11 = Vector256.Create(*(state + 11));
		var o12 = Vector256.Create(*(state + 12));
		var o13 = Vector256.Create(*(state + 13));
		var o14 = Vector256.Create(*(state + 14));
		var o15 = Vector256.Create(*(state + 15));

		while (length >= 512)
		{
			var x0 = o0;
			var x1 = o1;
			var x2 = o2;
			var x3 = o3;
			var x4 = o4;
			var x5 = o5;
			var x6 = o6;
			var x7 = o7;
			var x10 = o10;
			var x11 = o11;
			var x12 = o12;
			var x13 = o13;
			var x14 = o14;
			var x15 = o15;

			var counter = *(state + 8) | (ulong)*(state + 9) << 32;
			var x8 = Vector256.Create(counter).AsUInt32();
			var x9 = x8;

			var t0 = Avx2.Add(ChaCha20Utils.IncCounter0123, x8.AsUInt64()).AsUInt32();
			var t1 = Avx2.Add(ChaCha20Utils.IncCounter4567, x9.AsUInt64()).AsUInt32();

			x8 = Avx2.UnpackLow(t0, t1);
			x9 = Avx2.UnpackHigh(t0, t1);

			t0 = Avx2.UnpackLow(x8, x9);
			t1 = Avx2.UnpackHigh(x8, x9);

			x8 = Avx2.PermuteVar8x32(t0, ChaCha20Utils.Permute3);
			x9 = Avx2.PermuteVar8x32(t1, ChaCha20Utils.Permute3);

			var o8 = x8;
			var o9 = x9;

			counter += 8;

			*(state + 8) = (uint)(counter & 0xFFFFFFFF);
			*(state + 9) = (uint)(counter >> 32 & 0xFFFFFFFF);

			for (var i = 0; i < rounds; i += 2)
			{
				QuarterRound(ref x4, ref x0, ref x12, ref x8);
				QuarterRound(ref x9, ref x5, ref x1, ref x13);
				QuarterRound(ref x14, ref x10, ref x6, ref x2);
				QuarterRound(ref x3, ref x15, ref x11, ref x7);

				QuarterRound(ref x1, ref x0, ref x3, ref x2);
				QuarterRound(ref x6, ref x5, ref x4, ref x7);
				QuarterRound(ref x11, ref x10, ref x9, ref x8);
				QuarterRound(ref x12, ref x15, ref x14, ref x13);
			}

			ChaCha20Utils.AddTransposeXor(
				ref x0, ref x1, ref x2, ref x3,
				ref x4, ref x5, ref x6, ref x7,
				ref o0, ref o1, ref o2, ref o3,
				ref o4, ref o5, ref o6, ref o7,
				source, destination);

			ChaCha20Utils.AddTransposeXor(
				ref x8, ref x9, ref x10, ref x11,
				ref x12, ref x13, ref x14, ref x15,
				ref o8, ref o9, ref o10, ref o11,
				ref o12, ref o13, ref o14, ref o15,
				source + 32, destination + 32);

			length -= 512;
			destination += 512;
			source += 512;
		}
	}

	#endregion
}
