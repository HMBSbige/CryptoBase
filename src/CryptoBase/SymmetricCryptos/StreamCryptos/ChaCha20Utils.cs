namespace CryptoBase.SymmetricCryptos.StreamCryptos;

internal static class ChaCha20Utils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ref ulong GetCounterOriginal(ref uint state)
	{
		return ref Unsafe.As<uint, ulong>(ref Unsafe.Add(ref state, 12));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ref uint GetCounter(ref uint state)
	{
		return ref Unsafe.Add(ref state, 12);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void UpdateKeyStream(in int rounds, in ReadOnlySpan<uint> state, in Span<byte> keyStream)
	{
		Span<uint> x = MemoryMarshal.Cast<byte, uint>(keyStream);
		state.CopyTo(x);

		ChaChaRound(rounds, x);

		x[15] += state[15];
		x[14] += state[14];
		x[13] += state[13];
		x[12] += state[12];
		x[11] += state[11];
		x[10] += state[10];
		x[9] += state[9];
		x[8] += state[8];
		x[7] += state[7];
		x[6] += state[6];
		x[5] += state[5];
		x[4] += state[4];
		x[3] += state[3];
		x[2] += state[2];
		x[1] += state[1];
		x[0] += state[0];
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ChaChaRound(in int rounds, in Span<uint> x)
	{
		uint x15 = x[15], x14 = x[14], x13 = x[13], x12 = x[12];
		uint x11 = x[11], x10 = x[10], x09 = x[9], x08 = x[8];
		uint x07 = x[7], x06 = x[6], x05 = x[5], x04 = x[4];
		uint x03 = x[3], x02 = x[2], x01 = x[1], x00 = x[0];

		for (int i = 0; i < rounds; i += 2)
		{
			QuarterRound(ref x00, ref x04, ref x08, ref x12);
			QuarterRound(ref x01, ref x05, ref x09, ref x13);
			QuarterRound(ref x02, ref x06, ref x10, ref x14);
			QuarterRound(ref x03, ref x07, ref x11, ref x15);

			QuarterRound(ref x00, ref x05, ref x10, ref x15);
			QuarterRound(ref x01, ref x06, ref x11, ref x12);
			QuarterRound(ref x02, ref x07, ref x08, ref x13);
			QuarterRound(ref x03, ref x04, ref x09, ref x14);
		}

		x[15] = x15;
		x[14] = x14;
		x[13] = x13;
		x[12] = x12;
		x[11] = x11;
		x[10] = x10;
		x[9] = x09;
		x[8] = x08;
		x[7] = x07;
		x[6] = x06;
		x[5] = x05;
		x[4] = x04;
		x[3] = x03;
		x[2] = x02;
		x[1] = x01;
		x[0] = x00;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
	{
		Step(ref a, ref b, ref d, 16);
		Step(ref c, ref d, ref b, 12);
		Step(ref a, ref b, ref d, 8);
		Step(ref c, ref d, ref b, 7);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Step(ref uint a, ref readonly uint b, ref uint c, in int i)
	{
		a += b;
		c = (a ^ c).RotateLeft(i);
	}

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
	private static void QuarterRound(ref Vector256<uint> a, ref Vector256<uint> b, ref Vector256<uint> c, ref Vector256<uint> d)
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
	private static void QuarterRound(ref Vector512<uint> a, ref Vector512<uint> b, ref Vector512<uint> c, ref Vector512<uint> d)
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

	#region 处理 128 bytes

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ChaChaCoreOriginal128(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Vector256<ulong> incCounterOriginal128 = Vector256.Create(0ul, 0, 1, 0);
		ref uint stateRef = ref state.GetReference();
		ref byte sourceRef = ref source.GetReference();
		ref byte destRef = ref destination.GetReference();

		ref readonly Vector256<byte> src0 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref sourceRef, 0 * 32));
		ref readonly Vector256<byte> src1 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref sourceRef, 1 * 32));
		ref readonly Vector256<byte> src2 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref sourceRef, 2 * 32));
		ref readonly Vector256<byte> src3 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref sourceRef, 3 * 32));

		ref readonly Vector256<uint> s0 = ref Unsafe.As<uint, Vector256<uint>>(ref Unsafe.Add(ref stateRef, 0));// 0 1 2 3 4 5 6 7
		ref readonly Vector256<uint> s1 = ref Unsafe.As<uint, Vector256<uint>>(ref Unsafe.Add(ref stateRef, 8));// 8 9 10 11 12 13 14 15
		Vector256<uint> t = s1;

		Vector256<uint> x0 = FastUtils.BroadcastVector128ToVector256(ref Unsafe.Add(ref stateRef, 0));
		Vector256<uint> x1 = FastUtils.BroadcastVector128ToVector256(ref Unsafe.Add(ref stateRef, 4));
		Vector256<uint> x2 = FastUtils.BroadcastVector128ToVector256(ref Unsafe.Add(ref stateRef, 8));
		Vector256<uint> x3 = FastUtils.BroadcastVector128ToVector256(ref Unsafe.Add(ref stateRef, 12));
		x3 = (x3.AsUInt64() + incCounterOriginal128).AsUInt32();

		for (int i = 0; i < rounds; i += 2)
		{
			QuarterRound(ref x0, ref x1, ref x2, ref x3);
			Shuffle(ref x1, ref x2, ref x3);

			QuarterRound(ref x0, ref x1, ref x2, ref x3);
			Shuffle1(ref x1, ref x2, ref x3);
		}

		Shuffle(ref x0, ref x1, ref x2, ref x3);
		++GetCounterOriginal(ref stateRef);

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

		++GetCounterOriginal(ref stateRef);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ChaChaCore128(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Vector256<uint> incCounter128 = Vector256.Create(0u, 0, 0, 0, 1, 0, 0, 0);
		ref uint stateRef = ref state.GetReference();
		ref byte sourceRef = ref source.GetReference();
		ref byte destRef = ref destination.GetReference();

		ref readonly Vector256<byte> src0 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref sourceRef, 0 * 32));
		ref readonly Vector256<byte> src1 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref sourceRef, 1 * 32));
		ref readonly Vector256<byte> src2 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref sourceRef, 2 * 32));
		ref readonly Vector256<byte> src3 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref sourceRef, 3 * 32));

		ref readonly Vector256<uint> s0 = ref Unsafe.As<uint, Vector256<uint>>(ref Unsafe.Add(ref stateRef, 0));// 0 1 2 3 4 5 6 7
		ref readonly Vector256<uint> s1 = ref Unsafe.As<uint, Vector256<uint>>(ref Unsafe.Add(ref stateRef, 8));// 8 9 10 11 12 13 14 15
		Vector256<uint> t = s1;

		Vector256<uint> x0 = FastUtils.BroadcastVector128ToVector256(ref Unsafe.Add(ref stateRef, 0));
		Vector256<uint> x1 = FastUtils.BroadcastVector128ToVector256(ref Unsafe.Add(ref stateRef, 4));
		Vector256<uint> x2 = FastUtils.BroadcastVector128ToVector256(ref Unsafe.Add(ref stateRef, 8));
		Vector256<uint> x3 = FastUtils.BroadcastVector128ToVector256(ref Unsafe.Add(ref stateRef, 12));
		x3 += incCounter128;

		for (int i = 0; i < rounds; i += 2)
		{
			QuarterRound(ref x0, ref x1, ref x2, ref x3);
			Shuffle(ref x1, ref x2, ref x3);

			QuarterRound(ref x0, ref x1, ref x2, ref x3);
			Shuffle1(ref x1, ref x2, ref x3);
		}

		Shuffle(ref x0, ref x1, ref x2, ref x3);
		++GetCounter(ref stateRef);

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

		++GetCounter(ref stateRef);
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

	#region 处理 512*n bytes

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static int ChaChaCoreOriginal512(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
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
		Vector256<uint> o8 = Vector256.Create(Unsafe.Add(ref stateRef, 8));
		Vector256<uint> o9 = Vector256.Create(Unsafe.Add(ref stateRef, 9));
		Vector256<uint> o10 = Vector256.Create(Unsafe.Add(ref stateRef, 10));
		Vector256<uint> o11 = Vector256.Create(Unsafe.Add(ref stateRef, 11));
		// 12
		// 13
		Vector256<uint> o14 = Vector256.Create(Unsafe.Add(ref stateRef, 14));
		Vector256<uint> o15 = Vector256.Create(Unsafe.Add(ref stateRef, 15));
		ref ulong counter = ref Unsafe.As<uint, ulong>(ref Unsafe.Add(ref stateRef, 12));

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
			Vector256<uint> x8 = o8;
			Vector256<uint> x9 = o9;
			Vector256<uint> x10 = o10;
			Vector256<uint> x11 = o11;
			Vector256<uint> x14 = o14;
			Vector256<uint> x15 = o15;

			Vector256<uint> x12 = Vector256.Create(counter).AsUInt32();

			Vector256<uint> t0 = Avx2.Add(incCounter0123, x12.AsUInt64()).AsUInt32();
			Vector256<uint> t1 = Avx2.Add(incCounter4567, x12.AsUInt64()).AsUInt32();

			x12 = Avx2.UnpackLow(t0, t1);
			Vector256<uint> x13 = Avx2.UnpackHigh(t0, t1);

			t0 = Avx2.UnpackLow(x12, x13);
			t1 = Avx2.UnpackHigh(x12, x13);

			x12 = Avx2.PermuteVar8x32(t0, Vector256.Create(0u, 1, 4, 5, 2, 3, 6, 7));
			x13 = Avx2.PermuteVar8x32(t1, Vector256.Create(0u, 1, 4, 5, 2, 3, 6, 7));

			Vector256<uint> o12 = x12;
			Vector256<uint> o13 = x13;

			counter += 8;

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

			AddTransposeXor
			(
				ref x0, ref x1, ref x2, ref x3,
				ref x4, ref x5, ref x6, ref x7,
				ref o0, ref o1, ref o2, ref o3,
				ref o4, ref o5, ref o6, ref o7,
				ref Unsafe.Add(ref sourceRef, offset),
				ref Unsafe.Add(ref dstRef, offset)
			);
			AddTransposeXor
			(
				ref x8, ref x9, ref x10, ref x11,
				ref x12, ref x13, ref x14, ref x15,
				ref o8, ref o9, ref o10, ref o11,
				ref o12, ref o13, ref o14, ref o15,
				ref Unsafe.Add(ref sourceRef, offset + 32),
				ref Unsafe.Add(ref dstRef, offset + 32)
			);

			length -= 512;
			offset += 512;
		}

		return offset;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static int ChaChaCore512(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Vector256<uint> incCounter01234567 = Vector256.Create(0u, 1, 2, 3, 4, 5, 6, 7);
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
		Vector256<uint> o8 = Vector256.Create(Unsafe.Add(ref stateRef, 8));
		Vector256<uint> o9 = Vector256.Create(Unsafe.Add(ref stateRef, 9));
		Vector256<uint> o10 = Vector256.Create(Unsafe.Add(ref stateRef, 10));
		Vector256<uint> o11 = Vector256.Create(Unsafe.Add(ref stateRef, 11));
		// 12
		Vector256<uint> o13 = Vector256.Create(Unsafe.Add(ref stateRef, 13));
		Vector256<uint> o14 = Vector256.Create(Unsafe.Add(ref stateRef, 14));
		Vector256<uint> o15 = Vector256.Create(Unsafe.Add(ref stateRef, 15));
		ref uint counter = ref Unsafe.Add(ref stateRef, 12);

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
			Vector256<uint> x8 = o8;
			Vector256<uint> x9 = o9;
			Vector256<uint> x10 = o10;
			Vector256<uint> x11 = o11;
			Vector256<uint> x13 = o13;
			Vector256<uint> x14 = o14;
			Vector256<uint> x15 = o15;

			Vector256<uint> x12 = incCounter01234567 + Vector256.Create(counter);
			Vector256<uint> o12 = x12;

			counter += 8;

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

			AddTransposeXor
			(
				ref x0, ref x1, ref x2, ref x3,
				ref x4, ref x5, ref x6, ref x7,
				ref o0, ref o1, ref o2, ref o3,
				ref o4, ref o5, ref o6, ref o7,
				ref Unsafe.Add(ref sourceRef, offset),
				ref Unsafe.Add(ref dstRef, offset)
			);
			AddTransposeXor
			(
				ref x8, ref x9, ref x10, ref x11,
				ref x12, ref x13, ref x14, ref x15,
				ref o8, ref o9, ref o10, ref o11,
				ref o12, ref o13, ref o14, ref o15,
				ref Unsafe.Add(ref sourceRef, offset + 32),
				ref Unsafe.Add(ref dstRef, offset + 32)
			);

			length -= 512;
			offset += 512;
		}

		return offset;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void AddTransposeXor(
		ref Vector256<uint> x0, ref Vector256<uint> x1, ref Vector256<uint> x2, ref Vector256<uint> x3,
		ref Vector256<uint> x4, ref Vector256<uint> x5, ref Vector256<uint> x6, ref Vector256<uint> x7,
		ref Vector256<uint> o0, ref Vector256<uint> o1, ref Vector256<uint> o2, ref Vector256<uint> o3,
		ref Vector256<uint> o4, ref Vector256<uint> o5, ref Vector256<uint> o6, ref Vector256<uint> o7,
		ref byte source, ref byte destination)
	{
		ref Vector256<byte> s0 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref source, 0 * 64));
		ref Vector256<byte> s1 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref source, 1 * 64));
		ref Vector256<byte> s2 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref source, 2 * 64));
		ref Vector256<byte> s3 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref source, 3 * 64));
		ref Vector256<byte> s4 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref source, 4 * 64));
		ref Vector256<byte> s5 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref source, 5 * 64));
		ref Vector256<byte> s6 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref source, 6 * 64));
		ref Vector256<byte> s7 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref source, 7 * 64));

		// x += o
		x0 += o0;
		x1 += o1;
		x2 += o2;
		x3 += o3;
		x4 += o4;
		x5 += o5;
		x6 += o6;
		x7 += o7;

		// Transpose
		Vector256<uint> t0 = Avx2.UnpackLow(x0, x1);
		Vector256<uint> t1 = Avx2.UnpackLow(x2, x3);
		Vector256<uint> t2 = Avx2.UnpackHigh(x0, x1);
		Vector256<uint> t3 = Avx2.UnpackHigh(x2, x3);
		Vector256<uint> t4 = Avx2.UnpackLow(x4, x5);
		Vector256<uint> t5 = Avx2.UnpackLow(x6, x7);
		Vector256<uint> t6 = Avx2.UnpackHigh(x4, x5);
		Vector256<uint> t7 = Avx2.UnpackHigh(x6, x7);

		x0 = Avx2.UnpackLow(t0.AsUInt64(), t1.AsUInt64()).AsUInt32();
		x1 = Avx2.UnpackHigh(t0.AsUInt64(), t1.AsUInt64()).AsUInt32();
		x2 = Avx2.UnpackLow(t2.AsUInt64(), t3.AsUInt64()).AsUInt32();
		x3 = Avx2.UnpackHigh(t2.AsUInt64(), t3.AsUInt64()).AsUInt32();
		x4 = Avx2.UnpackLow(t4.AsUInt64(), t5.AsUInt64()).AsUInt32();
		x5 = Avx2.UnpackHigh(t4.AsUInt64(), t5.AsUInt64()).AsUInt32();
		x6 = Avx2.UnpackLow(t6.AsUInt64(), t7.AsUInt64()).AsUInt32();
		x7 = Avx2.UnpackHigh(t6.AsUInt64(), t7.AsUInt64()).AsUInt32();

		t0 = Avx2.Permute2x128(x0, x4, 0x20);
		t4 = Avx2.Permute2x128(x0, x4, 0x31);
		t1 = Avx2.Permute2x128(x1, x5, 0x20);
		t5 = Avx2.Permute2x128(x1, x5, 0x31);
		t2 = Avx2.Permute2x128(x2, x6, 0x20);
		t6 = Avx2.Permute2x128(x2, x6, 0x31);
		t3 = Avx2.Permute2x128(x3, x7, 0x20);
		t7 = Avx2.Permute2x128(x3, x7, 0x31);

		// Xor
		Vector256<byte> v0 = t0.AsByte() ^ s0;
		Vector256<byte> v1 = t1.AsByte() ^ s1;
		Vector256<byte> v2 = t2.AsByte() ^ s2;
		Vector256<byte> v3 = t3.AsByte() ^ s3;
		Vector256<byte> v4 = t4.AsByte() ^ s4;
		Vector256<byte> v5 = t5.AsByte() ^ s5;
		Vector256<byte> v6 = t6.AsByte() ^ s6;
		Vector256<byte> v7 = t7.AsByte() ^ s7;

		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination, 0 * 64), v0);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination, 1 * 64), v1);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination, 2 * 64), v2);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination, 3 * 64), v3);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination, 4 * 64), v4);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination, 5 * 64), v5);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination, 6 * 64), v6);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination, 7 * 64), v7);
	}

	#endregion

	#region Avx

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
	private static void Shuffle(ref Vector256<uint> a, ref Vector256<uint> b, ref Vector256<uint> c)
	{
		Vector256<uint> permute0 = Vector256.Create(1u, 2, 3, 0, 5, 6, 7, 4);
		Vector256<uint> permute1 = Vector256.Create(2u, 3, 0, 1, 6, 7, 4, 5);
		Vector256<uint> permute2 = Vector256.Create(3u, 0, 1, 2, 7, 4, 5, 6);
		a = Avx2.PermuteVar8x32(a, permute0);
		b = Avx2.PermuteVar8x32(b, permute1);
		c = Avx2.PermuteVar8x32(c, permute2);
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
	private static void Shuffle1(ref Vector256<uint> a, ref Vector256<uint> b, ref Vector256<uint> c)
	{
		Vector256<uint> permute0 = Vector256.Create(1u, 2, 3, 0, 5, 6, 7, 4);
		Vector256<uint> permute1 = Vector256.Create(2u, 3, 0, 1, 6, 7, 4, 5);
		Vector256<uint> permute2 = Vector256.Create(3u, 0, 1, 2, 7, 4, 5, 6);
		a = Avx2.PermuteVar8x32(a, permute2);
		b = Avx2.PermuteVar8x32(b, permute1);
		c = Avx2.PermuteVar8x32(c, permute0);
	}

	/// <summary>
	/// 0 1 2 3 16 17 18 19
	/// 4 5 6 7 20 21 22 23
	/// 8 9 10 11 24 25 26 27
	/// 12 13 14 15 28 29 30 31
	/// =>
	/// 0 1 2 3 4 5 6 7
	/// 8 9 10 11 12 13 14 15
	/// 16 17 18 19 20 21 22 23
	/// 24 25 26 27 28 29 30 31
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Shuffle(ref Vector256<uint> a, ref Vector256<uint> b, ref Vector256<uint> c, ref Vector256<uint> d)
	{
		Vector256<uint> t0 = Avx2.Permute2x128(a, b, 0x20);
		Vector256<uint> t1 = Avx2.Permute2x128(c, d, 0x20);
		Vector256<uint> t2 = Avx2.Permute2x128(a, b, 0x31);
		Vector256<uint> t3 = Avx2.Permute2x128(c, d, 0x31);

		a = t0;
		b = t1;
		c = t2;
		d = t3;
	}

	#endregion
}
