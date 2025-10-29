using CryptoBase.Abstractions.SymmetricCryptos;

namespace CryptoBase.SymmetricCryptos.StreamCryptos;

public static class Salsa20Utils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void UpdateKeyStream(int rounds, uint[] state, byte[] keyStream)
	{
		uint[] x = ArrayPool<uint>.Shared.Rent(SnuffleCryptoBase.StateSize);

		try
		{
			state.AsSpan(0, SnuffleCryptoBase.StateSize).CopyTo(x);

			SalsaRound(rounds, x);

			for (int i = 0; i < SnuffleCryptoBase.StateSize; i += 4)
			{
				x[i] += state[i];
				x[i + 1] += state[i + 1];
				x[i + 2] += state[i + 2];
				x[i + 3] += state[i + 3];
			}

			Span<uint> span = MemoryMarshal.Cast<byte, uint>(keyStream.AsSpan(0, SnuffleCryptoBase.StateSize * sizeof(uint)));
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
		for (int i = 0; i < rounds; i += 2)
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
	public static void UpdateKeyStream(Span<uint> state, Span<byte> stream, byte rounds)
	{
		ref uint stateRef = ref state.GetReference();
		ref byte streamRef = ref stream.GetReference();

		Vector128<uint> x0 = Vector128.Create(Unsafe.Add(ref stateRef, 4), Unsafe.Add(ref stateRef, 9), Unsafe.Add(ref stateRef, 14), Unsafe.Add(ref stateRef, 3));// 4 9 14 3
		Vector128<uint> x1 = Vector128.Create(Unsafe.Add(ref stateRef, 0), Unsafe.Add(ref stateRef, 5), Unsafe.Add(ref stateRef, 10), Unsafe.Add(ref stateRef, 15));// 0 5 10 15
		Vector128<uint> x2 = Vector128.Create(Unsafe.Add(ref stateRef, 12), Unsafe.Add(ref stateRef, 1), Unsafe.Add(ref stateRef, 6), Unsafe.Add(ref stateRef, 11));// 12 1 6 11
		Vector128<uint> x3 = Vector128.Create(Unsafe.Add(ref stateRef, 8), Unsafe.Add(ref stateRef, 13), Unsafe.Add(ref stateRef, 2), Unsafe.Add(ref stateRef, 7));// 8 13 2 7

		ref Vector128<uint> s0 = ref Unsafe.As<uint, Vector128<uint>>(ref Unsafe.Add(ref stateRef, 0 * 4));
		ref Vector128<uint> s1 = ref Unsafe.As<uint, Vector128<uint>>(ref Unsafe.Add(ref stateRef, 1 * 4));
		ref Vector128<uint> s2 = ref Unsafe.As<uint, Vector128<uint>>(ref Unsafe.Add(ref stateRef, 2 * 4));
		ref Vector128<uint> s3 = ref Unsafe.As<uint, Vector128<uint>>(ref Unsafe.Add(ref stateRef, 3 * 4));

		for (int i = 0; i < rounds; i += 2)
		{
			QuarterRound(ref x0, ref x1, ref x2, ref x3);
			Shuffle(ref x0, ref x2, ref x3);

			QuarterRound(ref x0, ref x1, ref x2, ref x3);
			Shuffle(ref x0, ref x2, ref x3);
		}

		Shuffle(ref x0, ref x1, ref x2, ref x3);

		x0 += s0;
		x1 += s1;
		x2 += s2;
		x3 += s3;

		Unsafe.WriteUnaligned(ref Unsafe.Add(ref streamRef, 0 * 16), x0.AsByte());
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref streamRef, 1 * 16), x1.AsByte());
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref streamRef, 2 * 16), x2.AsByte());
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref streamRef, 3 * 16), x3.AsByte());
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void SalsaRound(Span<uint> state, byte rounds)
	{
		ref uint stateRef = ref state.GetReference();

		Vector128<uint> x0 = Vector128.Create(Unsafe.Add(ref stateRef, 4), Unsafe.Add(ref stateRef, 9), Unsafe.Add(ref stateRef, 14), Unsafe.Add(ref stateRef, 3));// 4 9 14 3
		Vector128<uint> x1 = Vector128.Create(Unsafe.Add(ref stateRef, 0), Unsafe.Add(ref stateRef, 5), Unsafe.Add(ref stateRef, 10), Unsafe.Add(ref stateRef, 15));// 0 5 10 15
		Vector128<uint> x2 = Vector128.Create(Unsafe.Add(ref stateRef, 12), Unsafe.Add(ref stateRef, 1), Unsafe.Add(ref stateRef, 6), Unsafe.Add(ref stateRef, 11));// 12 1 6 11
		Vector128<uint> x3 = Vector128.Create(Unsafe.Add(ref stateRef, 8), Unsafe.Add(ref stateRef, 13), Unsafe.Add(ref stateRef, 2), Unsafe.Add(ref stateRef, 7));// 8 13 2 7

		for (int i = 0; i < rounds; i += 2)
		{
			QuarterRound(ref x0, ref x1, ref x2, ref x3);
			Shuffle(ref x0, ref x2, ref x3);

			QuarterRound(ref x0, ref x1, ref x2, ref x3);
			Shuffle(ref x0, ref x2, ref x3);
		}

		if (Avx2.IsSupported)
		{
			Shuffle(ref x0, ref x1, ref x2, ref x3, out Vector256<uint> a, out Vector256<uint> b);

			Unsafe.WriteUnaligned(ref Unsafe.As<uint, byte>(ref Unsafe.Add(ref stateRef, 0)), a);
			Unsafe.WriteUnaligned(ref Unsafe.As<uint, byte>(ref Unsafe.Add(ref stateRef, 8)), b);
		}
		else
		{
			Shuffle(ref x0, ref x1, ref x2, ref x3);

			Unsafe.WriteUnaligned(ref Unsafe.As<uint, byte>(ref Unsafe.Add(ref stateRef, 0 * 4)), x0);
			Unsafe.WriteUnaligned(ref Unsafe.As<uint, byte>(ref Unsafe.Add(ref stateRef, 1 * 4)), x1);
			Unsafe.WriteUnaligned(ref Unsafe.As<uint, byte>(ref Unsafe.Add(ref stateRef, 2 * 4)), x2);
			Unsafe.WriteUnaligned(ref Unsafe.As<uint, byte>(ref Unsafe.Add(ref stateRef, 3 * 4)), x3);
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
		a = Sse2.Shuffle(a, 0b10_01_00_11);// 4 9 14 3 => 3 4 9 14
										   // 0 5 10 15
		c = Sse2.Shuffle(c, 0b00_11_10_01);// 12 1 6 11 => 1 6 11 12
		d = Sse2.Shuffle(d, 0b01_00_11_10);// 8 13 2 7 => 2 7 8 13

		Vector128<uint> t0 = Sse2.UnpackLow(b, c);// 0 1 5 6
		Vector128<uint> t1 = Sse2.UnpackLow(d, a);// 2 3 7 4
		Vector128<uint> t2 = Sse2.UnpackHigh(b, c);// 10 11 15 12
		Vector128<uint> t3 = Sse2.UnpackHigh(d, a);// 8 9 13 14

		a = Sse2.UnpackLow(t0.AsUInt64(), t1.AsUInt64()).AsUInt32();// 0 1 2 3
		b = Sse2.Shuffle(Sse2.UnpackHigh(t0, t1), 0b01_10_00_11);// 5 7 6 4 => 4 5 6 7
		c = Sse2.UnpackLow(t3.AsUInt64(), t2.AsUInt64()).AsUInt32();// 8 9 10 11
		d = Sse2.Shuffle(Sse2.UnpackHigh(t2, t3), 0b00_11_01_10);// 15 13 12 14 => 12 13 14 15
	}

	#region Avx

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
		Vector256<uint> permute0 = Vector256.Create(4u, 3, 1, 6, 0, 5, 2, 7);
		Vector256<uint> permute1 = Vector256.Create(1u, 6, 4, 3, 2, 7, 0, 5);
		Vector256<uint> permute2 = Vector256.Create(0u, 1, 3, 2, 4, 6, 5, 7);
		Vector256<uint> permute3 = Vector256.Create(1u, 0, 2, 3, 5, 7, 4, 6);
		x0 = Vector256.Create(a, b);// 4 9 14 3 0 5 10 15
		x1 = Vector256.Create(c, d);// 12 1 6 11 8 13 2 7

		x0 = Avx2.PermuteVar8x32(x0, permute0);// 0 3 9 10 4 5 14 15
		x1 = Avx2.PermuteVar8x32(x1, permute1);// 1 2 8 11 6 7 12 13

		Vector256<uint> t = Avx2.UnpackLow(x0, x1);// 0 1 3 2 4 6 5 7
		x1 = Avx2.UnpackHigh(x0, x1);// 9 8 10 11 14 12 15 13

		x0 = Avx2.PermuteVar8x32(t, permute2);// 0 1 2 3 4 5 6 7
		x1 = Avx2.PermuteVar8x32(x1, permute3);// 8 9 10 11 12 13 14 15
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
		Vector256<uint> permute4 = Vector256.Create(1u, 2, 3, 0, 5, 6, 7, 4);
		Vector256<uint> permute5 = Vector256.Create(3u, 0, 1, 2, 7, 4, 5, 6);
		Vector256<uint> permute6 = Vector256.Create(2u, 3, 0, 1, 6, 7, 4, 5);
		(a, b) = (b, a);
		a = Avx2.PermuteVar8x32(a, permute4);
		b = Avx2.PermuteVar8x32(b, permute5);
		c = Avx2.PermuteVar8x32(c, permute6);
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
		Vector256<uint> permute7 = Vector256.Create(3u, 7, 1, 5, 0, 4, 2, 6);
		Vector256<uint> permute8 = Vector256.Create(0u, 4, 2, 6, 1, 5, 3, 7);
		Vector256<uint> permute9 = Vector256.Create(1u, 5, 3, 7, 2, 6, 0, 4);
		Vector256<uint> permute10 = Vector256.Create(2u, 6, 0, 4, 3, 7, 1, 5);
		Vector256<uint> permute11 = Vector256.Create(2u, 1, 3, 0, 4, 6, 5, 7);
		Vector256<uint> permute12 = Vector256.Create(3u, 0, 2, 1, 5, 7, 4, 6);
		a = Avx2.PermuteVar8x32(a, permute7);// 3 19 9 25 4 20 14 30
		b = Avx2.PermuteVar8x32(b, permute8);// 0 16 10 26 5 21 15 31
		c = Avx2.PermuteVar8x32(c, permute9);// 1 17 11 27 6 22 12 28
		d = Avx2.PermuteVar8x32(d, permute10);// 2 18 8 24 7 23 13 29

		Vector256<uint> t0 = Avx2.UnpackLow(a, b);// 3 0 19 16 4 5 20 21
		Vector256<uint> t1 = Avx2.UnpackLow(c, d);// 1 2 17 18 6 7 22 23
		Vector256<uint> t2 = Avx2.UnpackHigh(a, b);// 9 10 25 26 14 15 30 31
		Vector256<uint> t3 = Avx2.UnpackHigh(c, d);// 11 8 27 24 12 13 28 29

		a = Avx2.UnpackLow(t0, t1);// 3 1 0 2 4 6 5 7
		b = Avx2.UnpackLow(t2, t3);// 9 11 10 8 14 12 15 13
		c = Avx2.UnpackHigh(t0, t1);// 19 17 16 18 20 22 21 23
		d = Avx2.UnpackHigh(t2, t3);// 25 27 26 24 30 28 31 29

		a = Avx2.PermuteVar8x32(a, permute11);// 0 1 2 3 4 5 6 7
		b = Avx2.PermuteVar8x32(b, permute12);// 8 9 10 11 12 13 14 15
		c = Avx2.PermuteVar8x32(c, permute11);// 16 17 18 19 20 21 22 23
		d = Avx2.PermuteVar8x32(d, permute12);// 24 25 26 27 28 29 30 31
	}

	#endregion

	/// <summary>
	/// 处理 64 bytes
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void SalsaCore64(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ref uint stateRef = ref state.GetReference();
		ref byte sourceRef = ref source.GetReference();
		ref byte destRef = ref destination.GetReference();

		ref Vector128<uint> s0 = ref Unsafe.As<uint, Vector128<uint>>(ref Unsafe.Add(ref stateRef, 0 * 4));
		ref Vector128<uint> s1 = ref Unsafe.As<uint, Vector128<uint>>(ref Unsafe.Add(ref stateRef, 1 * 4));
		ref Vector128<uint> s2 = ref Unsafe.As<uint, Vector128<uint>>(ref Unsafe.Add(ref stateRef, 2 * 4));
		ref Vector128<uint> s3 = ref Unsafe.As<uint, Vector128<uint>>(ref Unsafe.Add(ref stateRef, 3 * 4));
		ref Vector128<byte> src0 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref sourceRef, 0 * 16));
		ref Vector128<byte> src1 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref sourceRef, 1 * 16));
		ref Vector128<byte> src2 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref sourceRef, 2 * 16));
		ref Vector128<byte> src3 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref sourceRef, 3 * 16));

		Vector128<uint> x0 = Vector128.Create(Unsafe.Add(ref stateRef, 4), Unsafe.Add(ref stateRef, 9), Unsafe.Add(ref stateRef, 14), Unsafe.Add(ref stateRef, 3));// 4 9 14 3
		Vector128<uint> x1 = Vector128.Create(Unsafe.Add(ref stateRef, 0), Unsafe.Add(ref stateRef, 5), Unsafe.Add(ref stateRef, 10), Unsafe.Add(ref stateRef, 15));// 0 5 10 15
		Vector128<uint> x2 = Vector128.Create(Unsafe.Add(ref stateRef, 12), Unsafe.Add(ref stateRef, 1), Unsafe.Add(ref stateRef, 6), Unsafe.Add(ref stateRef, 11));// 12 1 6 11
		Vector128<uint> x3 = Vector128.Create(Unsafe.Add(ref stateRef, 8), Unsafe.Add(ref stateRef, 13), Unsafe.Add(ref stateRef, 2), Unsafe.Add(ref stateRef, 7));// 8 13 2 7

		for (int i = 0; i < rounds; i += 2)
		{
			QuarterRound(ref x0, ref x1, ref x2, ref x3);
			Shuffle(ref x0, ref x2, ref x3);

			QuarterRound(ref x0, ref x1, ref x2, ref x3);
			Shuffle(ref x0, ref x2, ref x3);
		}

		Shuffle(ref x0, ref x1, ref x2, ref x3);

		x0 += s0;
		x1 += s1;
		x2 += s2;
		x3 += s3;

		Vector128<byte> v0 = src0 ^ x0.AsByte();
		Vector128<byte> v1 = src1 ^ x1.AsByte();
		Vector128<byte> v2 = src2 ^ x2.AsByte();
		Vector128<byte> v3 = src3 ^ x3.AsByte();

		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 0 * 16), v0);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 1 * 16), v1);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 2 * 16), v2);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 3 * 16), v3);

		ref ulong counter = ref Unsafe.As<uint, ulong>(ref Unsafe.Add(ref stateRef, 8));
		++counter;
	}

	/// <summary>
	/// 处理 128 bytes
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void SalsaCore128(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ref uint stateRef = ref state.GetReference();
		ref byte sourceRef = ref source.GetReference();
		ref byte destRef = ref destination.GetReference();

		ref Vector256<byte> src0 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref sourceRef, 0 * 32));
		ref Vector256<byte> src1 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref sourceRef, 1 * 32));
		ref Vector256<byte> src2 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref sourceRef, 2 * 32));
		ref Vector256<byte> src3 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref sourceRef, 3 * 32));

		ref Vector256<uint> s0 = ref Unsafe.As<uint, Vector256<uint>>(ref Unsafe.Add(ref stateRef, 0));// 0 1 2 3 4 5 6 7
		ref Vector256<uint> s1 = ref Unsafe.As<uint, Vector256<uint>>(ref Unsafe.Add(ref stateRef, 8));// 8 9 10 11 12 13 14 15
		Vector256<uint> t = s1;

		uint t8 = Unsafe.Add(ref stateRef, 8);
		uint t9 = Unsafe.Add(ref stateRef, 9);

		ref ulong counter = ref Unsafe.As<uint, ulong>(ref Unsafe.Add(ref stateRef, 8));
		++counter;

		// 4 9 14 3
		Vector256<uint> x0 = Vector256.Create(
			Unsafe.Add(ref stateRef, 4),
			t9,
			Unsafe.Add(ref stateRef, 14),
			Unsafe.Add(ref stateRef, 3),
			Unsafe.Add(ref stateRef, 4),
			Unsafe.Add(ref stateRef, 9),
			Unsafe.Add(ref stateRef, 14),
			Unsafe.Add(ref stateRef, 3));
		// 0 5 10 15
		Vector256<uint> x1 = Vector256.Create(
			Unsafe.Add(ref stateRef, 0),
			Unsafe.Add(ref stateRef, 5),
			Unsafe.Add(ref stateRef, 10),
			Unsafe.Add(ref stateRef, 15),
			Unsafe.Add(ref stateRef, 0),
			Unsafe.Add(ref stateRef, 5),
			Unsafe.Add(ref stateRef, 10),
			Unsafe.Add(ref stateRef, 15));
		// 12 1 6 11
		Vector256<uint> x2 = Vector256.Create(
			Unsafe.Add(ref stateRef, 12),
			Unsafe.Add(ref stateRef, 1),
			Unsafe.Add(ref stateRef, 6),
			Unsafe.Add(ref stateRef, 11),
			Unsafe.Add(ref stateRef, 12),
			Unsafe.Add(ref stateRef, 1),
			Unsafe.Add(ref stateRef, 6),
			Unsafe.Add(ref stateRef, 11));
		// 8 13 2 7
		Vector256<uint> x3 = Vector256.Create(
			t8,
			Unsafe.Add(ref stateRef, 13),
			Unsafe.Add(ref stateRef, 2),
			Unsafe.Add(ref stateRef, 7),
			Unsafe.Add(ref stateRef, 8),
			Unsafe.Add(ref stateRef, 13),
			Unsafe.Add(ref stateRef, 2),
			Unsafe.Add(ref stateRef, 7)
		);

		for (int i = 0; i < rounds; i += 2)
		{
			QuarterRound(ref x0, ref x1, ref x2, ref x3);
			Shuffle(ref x0, ref x2, ref x3);

			QuarterRound(ref x0, ref x1, ref x2, ref x3);
			Shuffle(ref x0, ref x2, ref x3);
		}

		Shuffle(ref x0, ref x1, ref x2, ref x3);

		x0 += s0;
		x1 += t;
		x2 += s0;
		x3 += s1;

		Vector256<byte> v0 = x0.AsByte() ^ src0;
		Vector256<byte> v1 = x1.AsByte() ^ src1;
		Vector256<byte> v2 = x2.AsByte() ^ src2;
		Vector256<byte> v3 = x3.AsByte() ^ src3;

		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 0 * 32), v0);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 1 * 32), v1);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 2 * 32), v2);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 3 * 32), v3);

		++counter;
	}

	#region 处理 256*n bytes

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static int SalsaCore256(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Vector128<ulong> incCounter01 = Vector128.Create(0ul, 1);
		Vector128<ulong> incCounter23 = Vector128.Create(2ul, 3);
		int length = source.Length;
		int offset = 0;

		ref uint stateRef = ref state.GetReference();
		ref byte sourceRef = ref source.GetReference();
		ref byte dstRef = ref destination.GetReference();

		#region s

		Vector128<uint> s0 = Vector128.Create(Unsafe.Add(ref stateRef, 0));
		Vector128<uint> s1 = Vector128.Create(Unsafe.Add(ref stateRef, 1));
		Vector128<uint> s2 = Vector128.Create(Unsafe.Add(ref stateRef, 2));
		Vector128<uint> s3 = Vector128.Create(Unsafe.Add(ref stateRef, 3));
		Vector128<uint> s4 = Vector128.Create(Unsafe.Add(ref stateRef, 4));
		Vector128<uint> s5 = Vector128.Create(Unsafe.Add(ref stateRef, 5));
		Vector128<uint> s6 = Vector128.Create(Unsafe.Add(ref stateRef, 6));
		Vector128<uint> s7 = Vector128.Create(Unsafe.Add(ref stateRef, 7));
		// s8
		// s9
		Vector128<uint> s10 = Vector128.Create(Unsafe.Add(ref stateRef, 10));
		Vector128<uint> s11 = Vector128.Create(Unsafe.Add(ref stateRef, 11));
		Vector128<uint> s12 = Vector128.Create(Unsafe.Add(ref stateRef, 12));
		Vector128<uint> s13 = Vector128.Create(Unsafe.Add(ref stateRef, 13));
		Vector128<uint> s14 = Vector128.Create(Unsafe.Add(ref stateRef, 14));
		Vector128<uint> s15 = Vector128.Create(Unsafe.Add(ref stateRef, 15));
		ref ulong counter = ref Unsafe.As<uint, ulong>(ref Unsafe.Add(ref stateRef, 8));

		#endregion

		while (length >= 256)
		{
			#region x

			Vector128<uint> x0 = s0;
			Vector128<uint> x1 = s1;
			Vector128<uint> x2 = s2;
			Vector128<uint> x3 = s3;
			Vector128<uint> x4 = s4;
			Vector128<uint> x5 = s5;
			Vector128<uint> x6 = s6;
			Vector128<uint> x7 = s7;
			Vector128<uint> x10 = s10;
			Vector128<uint> x11 = s11;
			Vector128<uint> x12 = s12;
			Vector128<uint> x13 = s13;
			Vector128<uint> x14 = s14;
			Vector128<uint> x15 = s15;

			#endregion

			#region 8 9 位分别加 0 1 2 3

			Vector128<ulong> vo = Vector128.Create(counter);

			Vector128<uint> x8 = Sse2.Add(incCounter01, vo).AsUInt32();
			Vector128<uint> x9 = Sse2.Add(incCounter23, vo).AsUInt32();

			Vector128<uint> t8 = Sse2.UnpackLow(x8, x9);
			Vector128<uint> t9 = Sse2.UnpackHigh(x8, x9);

			x8 = Sse2.UnpackLow(t8, t9);
			x9 = Sse2.UnpackHigh(t8, t9);

			Vector128<uint> s8 = x8;
			Vector128<uint> s9 = x9;

			counter += 4;

			#endregion

			for (int i = 0; i < rounds; i += 2)
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

			ChaCha20Utils.AddTransposeXor(ref x0, ref x1, ref x2, ref x3, ref s0, ref s1, ref s2, ref s3, ref Unsafe.Add(ref sourceRef, offset + 0 * 16), ref Unsafe.Add(ref dstRef, offset + 0 * 16));
			ChaCha20Utils.AddTransposeXor(ref x4, ref x5, ref x6, ref x7, ref s4, ref s5, ref s6, ref s7, ref Unsafe.Add(ref sourceRef, offset + 1 * 16), ref Unsafe.Add(ref dstRef, offset + 1 * 16));
			ChaCha20Utils.AddTransposeXor(ref x8, ref x9, ref x10, ref x11, ref s8, ref s9, ref s10, ref s11, ref Unsafe.Add(ref sourceRef, offset + 2 * 16), ref Unsafe.Add(ref dstRef, offset + 2 * 16));
			ChaCha20Utils.AddTransposeXor(ref x12, ref x13, ref x14, ref x15, ref s12, ref s13, ref s14, ref s15, ref Unsafe.Add(ref sourceRef, offset + 3 * 16), ref Unsafe.Add(ref dstRef, offset + 3 * 16));

			offset += 256;
			length -= 256;
		}

		return offset;
	}

	#endregion

	#region 处理 512*n bytes

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static int SalsaCore512(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Vector256<ulong> incCounter0123 = Vector256.Create(0ul, 1, 2, 3);
		Vector256<ulong> incCounter4567 = Vector256.Create(4ul, 5, 6, 7);
		int length = source.Length;
		int offset = 0;

		ref uint stateRef = ref state.GetReference();
		ref byte sourceRef = ref source.GetReference();
		ref byte dstRef = ref destination.GetReference();

		Vector256<uint> o0 = Vector256.Create(Unsafe.Add(ref stateRef, 0));
		Vector256<uint> o1 = Vector256.Create(Unsafe.Add(ref stateRef, 1));
		Vector256<uint> o2 = Vector256.Create(Unsafe.Add(ref stateRef, 2));
		Vector256<uint> o3 = Vector256.Create(Unsafe.Add(ref stateRef, 3));
		Vector256<uint> o4 = Vector256.Create(Unsafe.Add(ref stateRef, 4));
		Vector256<uint> o5 = Vector256.Create(Unsafe.Add(ref stateRef, 5));
		Vector256<uint> o6 = Vector256.Create(Unsafe.Add(ref stateRef, 6));
		Vector256<uint> o7 = Vector256.Create(Unsafe.Add(ref stateRef, 7));
		// 8
		// 9
		Vector256<uint> o10 = Vector256.Create(Unsafe.Add(ref stateRef, 10));
		Vector256<uint> o11 = Vector256.Create(Unsafe.Add(ref stateRef, 11));
		Vector256<uint> o12 = Vector256.Create(Unsafe.Add(ref stateRef, 12));
		Vector256<uint> o13 = Vector256.Create(Unsafe.Add(ref stateRef, 13));
		Vector256<uint> o14 = Vector256.Create(Unsafe.Add(ref stateRef, 14));
		Vector256<uint> o15 = Vector256.Create(Unsafe.Add(ref stateRef, 15));
		ref ulong counter = ref Unsafe.As<uint, ulong>(ref Unsafe.Add(ref stateRef, 8));

		while (length >= 512)
		{
			Vector256<uint> x0 = o0;
			Vector256<uint> x1 = o1;
			Vector256<uint> x2 = o2;
			Vector256<uint> x3 = o3;
			Vector256<uint> x4 = o4;
			Vector256<uint> x5 = o5;
			Vector256<uint> x6 = o6;
			Vector256<uint> x7 = o7;
			Vector256<uint> x10 = o10;
			Vector256<uint> x11 = o11;
			Vector256<uint> x12 = o12;
			Vector256<uint> x13 = o13;
			Vector256<uint> x14 = o14;
			Vector256<uint> x15 = o15;

			Vector256<uint> x8 = Vector256.Create(counter).AsUInt32();
			Vector256<uint> x9 = x8;

			Vector256<uint> t0 = Avx2.Add(incCounter0123, x8.AsUInt64()).AsUInt32();
			Vector256<uint> t1 = Avx2.Add(incCounter4567, x8.AsUInt64()).AsUInt32();

			x8 = Avx2.UnpackLow(t0, t1);
			x9 = Avx2.UnpackHigh(t0, t1);

			t0 = Avx2.UnpackLow(x8, x9);
			t1 = Avx2.UnpackHigh(x8, x9);

			x8 = Avx2.PermuteVar8x32(t0, Vector256.Create(0u, 1, 4, 5, 2, 3, 6, 7));
			x9 = Avx2.PermuteVar8x32(t1, Vector256.Create(0u, 1, 4, 5, 2, 3, 6, 7));

			Vector256<uint> o8 = x8;
			Vector256<uint> o9 = x9;

			counter += 8;

			for (int i = 0; i < rounds; i += 2)
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
				ref x0,
				ref x1,
				ref x2,
				ref x3,
				ref x4,
				ref x5,
				ref x6,
				ref x7,
				ref o0,
				ref o1,
				ref o2,
				ref o3,
				ref o4,
				ref o5,
				ref o6,
				ref o7,
				ref Unsafe.Add(ref sourceRef, offset),
				ref Unsafe.Add(ref dstRef, offset));

			ChaCha20Utils.AddTransposeXor(
				ref x8,
				ref x9,
				ref x10,
				ref x11,
				ref x12,
				ref x13,
				ref x14,
				ref x15,
				ref o8,
				ref o9,
				ref o10,
				ref o11,
				ref o12,
				ref o13,
				ref o14,
				ref o15,
				ref Unsafe.Add(ref sourceRef, offset + 32),
				ref Unsafe.Add(ref dstRef, offset + 32));

			length -= 512;
			offset += 512;
		}

		return offset;
	}

	#endregion
}
