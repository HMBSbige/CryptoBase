namespace CryptoBase.SymmetricCryptos.StreamCryptos;

internal static partial class ChaCha20Utils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void QuarterRound(ref Vector128<uint> a, ref Vector128<uint> b, ref Vector128<uint> c, ref Vector128<uint> d)
	{
		a += b;
		d = (a ^ d).RotateLeftUInt32_16();

		c += d;
		b = (b ^ c).RotateLeftUInt32(12);

		a += b;
		d = (a ^ d).RotateLeftUInt32_8();

		c += d;
		b = (b ^ c).RotateLeftUInt32(7);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void UpdateKeyStream(Span<uint> state, Span<byte> stream, byte rounds)
	{
		ref uint stateRef = ref state.GetReference();
		ref byte streamRef = ref stream.GetReference();

		ref readonly Vector128<uint> s0 = ref Unsafe.As<uint, Vector128<uint>>(ref Unsafe.Add(ref stateRef, 0 * 4));
		ref readonly Vector128<uint> s1 = ref Unsafe.As<uint, Vector128<uint>>(ref Unsafe.Add(ref stateRef, 1 * 4));
		ref readonly Vector128<uint> s2 = ref Unsafe.As<uint, Vector128<uint>>(ref Unsafe.Add(ref stateRef, 2 * 4));
		ref readonly Vector128<uint> s3 = ref Unsafe.As<uint, Vector128<uint>>(ref Unsafe.Add(ref stateRef, 3 * 4));

		Vector128<uint> x0 = s0;
		Vector128<uint> x1 = s1;
		Vector128<uint> x2 = s2;
		Vector128<uint> x3 = s3;

		for (int i = 0; i < rounds; i += 2)
		{
			QuarterRound(ref x0, ref x1, ref x2, ref x3);
			Shuffle(ref x1, ref x2, ref x3);

			QuarterRound(ref x0, ref x1, ref x2, ref x3);
			Shuffle1(ref x1, ref x2, ref x3);
		}

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
	public static void ChaChaRound(Span<uint> state, byte rounds)
	{
		ref uint stateRef = ref state.GetReference();

		ref Vector128<uint> x0 = ref Unsafe.As<uint, Vector128<uint>>(ref Unsafe.Add(ref stateRef, 0 * 4));
		ref Vector128<uint> x1 = ref Unsafe.As<uint, Vector128<uint>>(ref Unsafe.Add(ref stateRef, 1 * 4));
		ref Vector128<uint> x2 = ref Unsafe.As<uint, Vector128<uint>>(ref Unsafe.Add(ref stateRef, 2 * 4));
		ref Vector128<uint> x3 = ref Unsafe.As<uint, Vector128<uint>>(ref Unsafe.Add(ref stateRef, 3 * 4));

		for (int i = 0; i < rounds; i += 2)
		{
			QuarterRound(ref x0, ref x1, ref x2, ref x3);
			Shuffle(ref x1, ref x2, ref x3);

			QuarterRound(ref x0, ref x1, ref x2, ref x3);
			Shuffle1(ref x1, ref x2, ref x3);
		}
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
	private static void Shuffle(ref Vector128<uint> a, ref Vector128<uint> b, ref Vector128<uint> c)
	{
		a = Sse2.Shuffle(a, 0b00_11_10_01);
		b = Sse2.Shuffle(b, 0b01_00_11_10);
		c = Sse2.Shuffle(c, 0b10_01_00_11);
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
	private static void Shuffle1(ref Vector128<uint> a, ref Vector128<uint> b, ref Vector128<uint> c)
	{
		a = Sse2.Shuffle(a, 0b10_01_00_11);
		b = Sse2.Shuffle(b, 0b01_00_11_10);
		c = Sse2.Shuffle(c, 0b00_11_10_01);
	}

	#region 处理 64 bytes

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ChaChaCore64Internal(byte rounds, ReadOnlySpan<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
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

		Vector128<uint> x0 = s0;
		Vector128<uint> x1 = s1;
		Vector128<uint> x2 = s2;
		Vector128<uint> x3 = s3;

		for (int i = 0; i < rounds; i += 2)
		{
			QuarterRound(ref x0, ref x1, ref x2, ref x3);
			Shuffle(ref x1, ref x2, ref x3);

			QuarterRound(ref x0, ref x1, ref x2, ref x3);
			Shuffle1(ref x1, ref x2, ref x3);
		}

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
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ChaChaCoreOriginal64(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ChaChaCore64Internal(rounds, state, source, destination);

		++GetCounterOriginal(ref state.GetReference());
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ChaChaCore64(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ChaChaCore64Internal(rounds, state, source, destination);

		++GetCounter(ref state.GetReference());
	}

	#endregion

	#region 处理 256*n bytes

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static int ChaChaCoreOriginal256(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Vector128<ulong> incCounter01 = Vector128.Create(0ul, 1);
		Vector128<ulong> incCounter23 = Vector128.Create(2ul, 3);
		int length = source.Length;
		int offset = 0;

		ref uint stateRef = ref state.GetReference();
		ref byte sourceRef = ref source.GetReference();
		ref byte dstRef = ref destination.GetReference();

		Vector128<uint> o0 = Vector128.Create(Unsafe.Add(ref stateRef, 0));
		Vector128<uint> o1 = Vector128.Create(Unsafe.Add(ref stateRef, 1));
		Vector128<uint> o2 = Vector128.Create(Unsafe.Add(ref stateRef, 2));
		Vector128<uint> o3 = Vector128.Create(Unsafe.Add(ref stateRef, 3));
		Vector128<uint> o4 = Vector128.Create(Unsafe.Add(ref stateRef, 4));
		Vector128<uint> o5 = Vector128.Create(Unsafe.Add(ref stateRef, 5));
		Vector128<uint> o6 = Vector128.Create(Unsafe.Add(ref stateRef, 6));
		Vector128<uint> o7 = Vector128.Create(Unsafe.Add(ref stateRef, 7));
		Vector128<uint> o8 = Vector128.Create(Unsafe.Add(ref stateRef, 8));
		Vector128<uint> o9 = Vector128.Create(Unsafe.Add(ref stateRef, 9));
		Vector128<uint> o10 = Vector128.Create(Unsafe.Add(ref stateRef, 10));
		Vector128<uint> o11 = Vector128.Create(Unsafe.Add(ref stateRef, 11));
		// 12
		// 13
		Vector128<uint> o14 = Vector128.Create(Unsafe.Add(ref stateRef, 14));
		Vector128<uint> o15 = Vector128.Create(Unsafe.Add(ref stateRef, 15));
		ref ulong counter = ref Unsafe.As<uint, ulong>(ref Unsafe.Add(ref stateRef, 12));

		while (length >= 256)
		{
			Vector128<uint> x0 = o0;
			Vector128<uint> x1 = o1;
			Vector128<uint> x2 = o2;
			Vector128<uint> x3 = o3;
			Vector128<uint> x4 = o4;
			Vector128<uint> x5 = o5;
			Vector128<uint> x6 = o6;
			Vector128<uint> x7 = o7;
			Vector128<uint> x8 = o8;
			Vector128<uint> x9 = o9;
			Vector128<uint> x10 = o10;
			Vector128<uint> x11 = o11;
			// 12
			// 13
			Vector128<uint> x14 = o14;
			Vector128<uint> x15 = o15;

			Vector128<uint> t0 = Vector128.Create(counter).AsUInt32();

			Vector128<uint> x12 = Sse2.Add(incCounter01, t0.AsUInt64()).AsUInt32();
			Vector128<uint> x13 = Sse2.Add(incCounter23, t0.AsUInt64()).AsUInt32();

			t0 = Sse2.UnpackLow(x12, x13);
			Vector128<uint> t1 = Sse2.UnpackHigh(x12, x13);

			x12 = Sse2.UnpackLow(t0, t1);
			x13 = Sse2.UnpackHigh(t0, t1);

			Vector128<uint> o12 = x12;
			Vector128<uint> o13 = x13;

			counter += 4;

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

			AddTransposeXor(ref x0, ref x1, ref x2, ref x3, ref o0, ref o1, ref o2, ref o3, ref Unsafe.Add(ref sourceRef, offset + 0 * 16), ref Unsafe.Add(ref dstRef, offset + 0 * 16));
			AddTransposeXor(ref x4, ref x5, ref x6, ref x7, ref o4, ref o5, ref o6, ref o7, ref Unsafe.Add(ref sourceRef, offset + 1 * 16), ref Unsafe.Add(ref dstRef, offset + 1 * 16));
			AddTransposeXor(ref x8, ref x9, ref x10, ref x11, ref o8, ref o9, ref o10, ref o11, ref Unsafe.Add(ref sourceRef, offset + 2 * 16), ref Unsafe.Add(ref dstRef, offset + 2 * 16));
			AddTransposeXor(ref x12, ref x13, ref x14, ref x15, ref o12, ref o13, ref o14, ref o15, ref Unsafe.Add(ref sourceRef, offset + 3 * 16), ref Unsafe.Add(ref dstRef, offset + 3 * 16));

			length -= 256;
			offset += 256;
		}

		return offset;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static int ChaChaCore256(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Vector128<uint> incCounter0123_128 = Vector128.Create(0u, 1, 2, 3);
		int length = source.Length;
		int offset = 0;

		ref uint stateRef = ref state.GetReference();
		ref byte sourceRef = ref source.GetReference();
		ref byte dstRef = ref destination.GetReference();

		Vector128<uint> o0 = Vector128.Create(Unsafe.Add(ref stateRef, 0));
		Vector128<uint> o1 = Vector128.Create(Unsafe.Add(ref stateRef, 1));
		Vector128<uint> o2 = Vector128.Create(Unsafe.Add(ref stateRef, 2));
		Vector128<uint> o3 = Vector128.Create(Unsafe.Add(ref stateRef, 3));
		Vector128<uint> o4 = Vector128.Create(Unsafe.Add(ref stateRef, 4));
		Vector128<uint> o5 = Vector128.Create(Unsafe.Add(ref stateRef, 5));
		Vector128<uint> o6 = Vector128.Create(Unsafe.Add(ref stateRef, 6));
		Vector128<uint> o7 = Vector128.Create(Unsafe.Add(ref stateRef, 7));
		Vector128<uint> o8 = Vector128.Create(Unsafe.Add(ref stateRef, 8));
		Vector128<uint> o9 = Vector128.Create(Unsafe.Add(ref stateRef, 9));
		Vector128<uint> o10 = Vector128.Create(Unsafe.Add(ref stateRef, 10));
		Vector128<uint> o11 = Vector128.Create(Unsafe.Add(ref stateRef, 11));
		// 12
		Vector128<uint> o13 = Vector128.Create(Unsafe.Add(ref stateRef, 13));
		Vector128<uint> o14 = Vector128.Create(Unsafe.Add(ref stateRef, 14));
		Vector128<uint> o15 = Vector128.Create(Unsafe.Add(ref stateRef, 15));
		ref uint counter = ref Unsafe.Add(ref stateRef, 12);

		while (length >= 256)
		{
			Vector128<uint> x0 = o0;
			Vector128<uint> x1 = o1;
			Vector128<uint> x2 = o2;
			Vector128<uint> x3 = o3;
			Vector128<uint> x4 = o4;
			Vector128<uint> x5 = o5;
			Vector128<uint> x6 = o6;
			Vector128<uint> x7 = o7;
			Vector128<uint> x8 = o8;
			Vector128<uint> x9 = o9;
			Vector128<uint> x10 = o10;
			Vector128<uint> x11 = o11;
			// 12
			Vector128<uint> x13 = o13;
			Vector128<uint> x14 = o14;
			Vector128<uint> x15 = o15;

			Vector128<uint> x12 = incCounter0123_128 + Vector128.Create(Unsafe.Add(ref stateRef, 12));
			Vector128<uint> o12 = x12;

			counter += 4;

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

			AddTransposeXor(ref x0, ref x1, ref x2, ref x3, ref o0, ref o1, ref o2, ref o3, ref Unsafe.Add(ref sourceRef, offset + 0 * 16), ref Unsafe.Add(ref dstRef, offset + 0 * 16));
			AddTransposeXor(ref x4, ref x5, ref x6, ref x7, ref o4, ref o5, ref o6, ref o7, ref Unsafe.Add(ref sourceRef, offset + 1 * 16), ref Unsafe.Add(ref dstRef, offset + 1 * 16));
			AddTransposeXor(ref x8, ref x9, ref x10, ref x11, ref o8, ref o9, ref o10, ref o11, ref Unsafe.Add(ref sourceRef, offset + 2 * 16), ref Unsafe.Add(ref dstRef, offset + 2 * 16));
			AddTransposeXor(ref x12, ref x13, ref x14, ref x15, ref o12, ref o13, ref o14, ref o15, ref Unsafe.Add(ref sourceRef, offset + 3 * 16), ref Unsafe.Add(ref dstRef, offset + 3 * 16));

			length -= 256;
			offset += 256;
		}

		return offset;
	}

	/// <summary>
	/// destination = (x+s) ^ source
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void AddTransposeXor(
		ref Vector128<uint> x0, ref Vector128<uint> x1, ref Vector128<uint> x2, ref Vector128<uint> x3,
		ref Vector128<uint> o0, ref Vector128<uint> o1, ref Vector128<uint> o2, ref Vector128<uint> o3,
		ref byte source, ref byte destination)
	{
		ref Vector128<byte> s0 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref source, 0 * 64));
		ref Vector128<byte> s1 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref source, 1 * 64));
		ref Vector128<byte> s2 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref source, 2 * 64));
		ref Vector128<byte> s3 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref source, 3 * 64));

		// x+=o
		x0 += o0;
		x1 += o1;
		x2 += o2;
		x3 += o3;

		// Transpose
		Vector128<uint> t0 = Sse2.UnpackLow(x0, x1);
		Vector128<uint> t1 = Sse2.UnpackLow(x2, x3);
		Vector128<uint> t2 = Sse2.UnpackHigh(x0, x1);
		Vector128<uint> t3 = Sse2.UnpackHigh(x2, x3);

		x0 = Sse2.UnpackLow(t0.AsUInt64(), t1.AsUInt64()).AsUInt32();
		x1 = Sse2.UnpackHigh(t0.AsUInt64(), t1.AsUInt64()).AsUInt32();
		x2 = Sse2.UnpackLow(t2.AsUInt64(), t3.AsUInt64()).AsUInt32();
		x3 = Sse2.UnpackHigh(t2.AsUInt64(), t3.AsUInt64()).AsUInt32();

		// Xor
		Vector128<byte> v0 = x0.AsByte() ^ s0;
		Vector128<byte> v1 = x1.AsByte() ^ s1;
		Vector128<byte> v2 = x2.AsByte() ^ s2;
		Vector128<byte> v3 = x3.AsByte() ^ s3;

		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination, 0 * 64), v0);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination, 1 * 64), v1);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination, 2 * 64), v2);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination, 3 * 64), v3);
	}

	#endregion
}
