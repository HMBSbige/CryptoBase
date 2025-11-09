namespace CryptoBase.SymmetricCryptos.StreamCryptos;

internal static partial class Salsa20Utils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void QuarterRound(ref Vector128<uint> a, ref Vector128<uint> b, ref Vector128<uint> c, ref Vector128<uint> d)
	{
		a ^= (b + c).RotateLeftUInt32(7);
		d ^= (a + b).RotateLeftUInt32(9);
		c ^= (d + a).RotateLeftUInt32(13);
		b ^= (c + d).RotateLeftUInt32(18);
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

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void UpdateKeyStream(Span<uint> state, Span<byte> stream, byte rounds)
	{
		ref uint stateRef = ref state.GetReference();
		ref byte streamRef = ref stream.GetReference();

		Vector128<uint> x0 = Vector128.Create(Unsafe.Add(ref stateRef, 4), Unsafe.Add(ref stateRef, 9), Unsafe.Add(ref stateRef, 14), Unsafe.Add(ref stateRef, 3));// 4 9 14 3
		Vector128<uint> x1 = Vector128.Create(Unsafe.Add(ref stateRef, 0), Unsafe.Add(ref stateRef, 5), Unsafe.Add(ref stateRef, 10), Unsafe.Add(ref stateRef, 15));// 0 5 10 15
		Vector128<uint> x2 = Vector128.Create(Unsafe.Add(ref stateRef, 12), Unsafe.Add(ref stateRef, 1), Unsafe.Add(ref stateRef, 6), Unsafe.Add(ref stateRef, 11));// 12 1 6 11
		Vector128<uint> x3 = Vector128.Create(Unsafe.Add(ref stateRef, 8), Unsafe.Add(ref stateRef, 13), Unsafe.Add(ref stateRef, 2), Unsafe.Add(ref stateRef, 7));// 8 13 2 7

		ref readonly Vector128<uint> s0 = ref Unsafe.As<uint, Vector128<uint>>(ref Unsafe.Add(ref stateRef, 0 * 4));
		ref readonly Vector128<uint> s1 = ref Unsafe.As<uint, Vector128<uint>>(ref Unsafe.Add(ref stateRef, 1 * 4));
		ref readonly Vector128<uint> s2 = ref Unsafe.As<uint, Vector128<uint>>(ref Unsafe.Add(ref stateRef, 2 * 4));
		ref readonly Vector128<uint> s3 = ref Unsafe.As<uint, Vector128<uint>>(ref Unsafe.Add(ref stateRef, 3 * 4));

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

		Shuffle(ref x0, ref x1, ref x2, ref x3);

		Unsafe.WriteUnaligned(ref Unsafe.As<uint, byte>(ref Unsafe.Add(ref stateRef, 0 * 4)), x0);
		Unsafe.WriteUnaligned(ref Unsafe.As<uint, byte>(ref Unsafe.Add(ref stateRef, 1 * 4)), x1);
		Unsafe.WriteUnaligned(ref Unsafe.As<uint, byte>(ref Unsafe.Add(ref stateRef, 2 * 4)), x2);
		Unsafe.WriteUnaligned(ref Unsafe.As<uint, byte>(ref Unsafe.Add(ref stateRef, 3 * 4)), x3);
	}

	/// <summary>
	/// 处理 64 bytes
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void SalsaCore64(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ref uint stateRef = ref state.GetReference();
		ref byte sourceRef = ref source.GetReference();
		ref byte destRef = ref destination.GetReference();

		ref readonly Vector128<uint> s0 = ref Unsafe.As<uint, Vector128<uint>>(ref Unsafe.Add(ref stateRef, 0 * 4));
		ref readonly Vector128<uint> s1 = ref Unsafe.As<uint, Vector128<uint>>(ref Unsafe.Add(ref stateRef, 1 * 4));
		ref readonly Vector128<uint> s2 = ref Unsafe.As<uint, Vector128<uint>>(ref Unsafe.Add(ref stateRef, 2 * 4));
		ref readonly Vector128<uint> s3 = ref Unsafe.As<uint, Vector128<uint>>(ref Unsafe.Add(ref stateRef, 3 * 4));
		ref readonly Vector128<byte> src0 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref sourceRef, 0 * 16));
		ref readonly Vector128<byte> src1 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref sourceRef, 1 * 16));
		ref readonly Vector128<byte> src2 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref sourceRef, 2 * 16));
		ref readonly Vector128<byte> src3 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref sourceRef, 3 * 16));

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

		++GetCounter(ref stateRef);
	}

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
		ref ulong counter = ref GetCounter(ref stateRef);

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
}
