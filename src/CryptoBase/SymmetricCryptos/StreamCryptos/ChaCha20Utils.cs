using CryptoBase.Abstractions.SymmetricCryptos;

namespace CryptoBase.SymmetricCryptos.StreamCryptos;

internal static class ChaCha20Utils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void UpdateKeyStream(int rounds, uint[] state, byte[] keyStream)
	{
		uint[] x = ArrayPool<uint>.Shared.Rent(SnuffleCryptoBase.StateSize);

		try
		{
			state.AsSpan().CopyTo(x);

			ChaChaRound(rounds, x);

			for (int i = 0; i < SnuffleCryptoBase.StateSize; i += 4)
			{
				x[i] += state[i];
				x[i + 1] += state[i + 1];
				x[i + 2] += state[i + 2];
				x[i + 3] += state[i + 3];
			}

			Span<uint> span = MemoryMarshal.Cast<byte, uint>(keyStream.AsSpan(0, 64));
			x.AsSpan(0, SnuffleCryptoBase.StateSize).CopyTo(span);
		}
		finally
		{
			ArrayPool<uint>.Shared.Return(x);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ChaChaRound(int rounds, uint[] x)
	{
		for (int i = 0; i < rounds; i += 2)
		{
			QuarterRound(ref x[0], ref x[4], ref x[8], ref x[12]);
			QuarterRound(ref x[1], ref x[5], ref x[9], ref x[13]);
			QuarterRound(ref x[2], ref x[6], ref x[10], ref x[14]);
			QuarterRound(ref x[3], ref x[7], ref x[11], ref x[15]);

			QuarterRound(ref x[0], ref x[5], ref x[10], ref x[15]);
			QuarterRound(ref x[1], ref x[6], ref x[11], ref x[12]);
			QuarterRound(ref x[2], ref x[7], ref x[8], ref x[13]);
			QuarterRound(ref x[3], ref x[4], ref x[9], ref x[14]);
		}
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
	private static void Step(ref uint a, ref uint b, ref uint c, byte i)
	{
		a += b;
		c = (a ^ c).RotateLeft(i);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void QuarterRound(ref Vector128<uint> a, ref Vector128<uint> b, ref Vector128<uint> c, ref Vector128<uint> d)
	{
		a = Sse2.Add(a, b);
		d = Sse2.Xor(a, d).RotateLeftUInt32_16();

		c = Sse2.Add(c, d);
		b = Sse2.Xor(b, c).RotateLeftUInt32(12);

		a = Sse2.Add(a, b);
		d = Sse2.Xor(a, d).RotateLeftUInt32_8();

		c = Sse2.Add(c, d);
		b = Sse2.Xor(b, c).RotateLeftUInt32(7);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void QuarterRound(ref Vector256<uint> a, ref Vector256<uint> b, ref Vector256<uint> c, ref Vector256<uint> d)
	{
		a = Avx2.Add(a, b);
		d = Avx2.Xor(a, d).RotateLeftUInt32_16();

		c = Avx2.Add(c, d);
		b = Avx2.Xor(b, c).RotateLeftUInt32(12);

		a = Avx2.Add(a, b);
		d = Avx2.Xor(a, d).RotateLeftUInt32_8();

		c = Avx2.Add(c, d);
		b = Avx2.Xor(b, c).RotateLeftUInt32(7);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void UpdateKeyStream(Span<uint> state, Span<byte> stream, byte rounds)
	{
		ref uint stateRef = ref MemoryMarshal.GetReference(state);
		ref byte streamRef = ref MemoryMarshal.GetReference(stream);

		Vector128<uint> s0 = Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref stateRef));
		Vector128<uint> s1 = Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref Unsafe.Add(ref stateRef, 4)));
		Vector128<uint> s2 = Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref Unsafe.Add(ref stateRef, 8)));
		Vector128<uint> s3 = Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref Unsafe.Add(ref stateRef, 12)));

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

		x0 = Sse2.Add(x0, s0);
		x1 = Sse2.Add(x1, s1);
		x2 = Sse2.Add(x2, s2);
		x3 = Sse2.Add(x3, s3);

		Unsafe.WriteUnaligned(ref streamRef, x0.AsByte());
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref streamRef, 16), x1.AsByte());
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref streamRef, 32), x2.AsByte());
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref streamRef, 48), x3.AsByte());
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void IncrementCounterOriginal(Span<uint> state)
	{
		ref uint counter = ref Unsafe.Add(ref MemoryMarshal.GetReference(state), 12);
		if (++counter == 0)
		{
			++Unsafe.Add(ref MemoryMarshal.GetReference(state), 13);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void IncrementCounter(Span<uint> state)
	{
		ref uint counter = ref Unsafe.Add(ref MemoryMarshal.GetReference(state), 12);
		if (++counter == 0)
		{
			Throw();
		}

		return;

		[DoesNotReturn]
		void Throw()
		{
			throw new InvalidOperationException(@"Data maximum length reached.");
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ChaChaRound(Span<uint> state, byte rounds)
	{
		ref uint stateRef = ref MemoryMarshal.GetReference(state);

		Vector128<uint> x0 = Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref stateRef));
		Vector128<uint> x1 = Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref Unsafe.Add(ref stateRef, 4)));
		Vector128<uint> x2 = Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref Unsafe.Add(ref stateRef, 8)));
		Vector128<uint> x3 = Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref Unsafe.Add(ref stateRef, 12)));

		for (int i = 0; i < rounds; i += 2)
		{
			QuarterRound(ref x0, ref x1, ref x2, ref x3);
			Shuffle(ref x1, ref x2, ref x3);

			QuarterRound(ref x0, ref x1, ref x2, ref x3);
			Shuffle1(ref x1, ref x2, ref x3);
		}

		Unsafe.WriteUnaligned(ref Unsafe.As<uint, byte>(ref stateRef), x0);
		Unsafe.WriteUnaligned(ref Unsafe.As<uint, byte>(ref Unsafe.Add(ref stateRef, 4)), x1);
		Unsafe.WriteUnaligned(ref Unsafe.As<uint, byte>(ref Unsafe.Add(ref stateRef, 8)), x2);
		Unsafe.WriteUnaligned(ref Unsafe.As<uint, byte>(ref Unsafe.Add(ref stateRef, 12)), x3);
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
	private static void ChaChaCore64Internal(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ref uint stateRef = ref MemoryMarshal.GetReference(state);
		ref byte sourceRef = ref MemoryMarshal.GetReference(source);
		ref byte destRef = ref MemoryMarshal.GetReference(destination);

		Vector128<uint> s0 = Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref stateRef));
		Vector128<uint> s1 = Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref Unsafe.Add(ref stateRef, 4)));
		Vector128<uint> s2 = Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref Unsafe.Add(ref stateRef, 8)));
		Vector128<uint> s3 = Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref Unsafe.Add(ref stateRef, 12)));

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

		x0 = Sse2.Add(x0, s0);
		x1 = Sse2.Add(x1, s1);
		x2 = Sse2.Add(x2, s2);
		x3 = Sse2.Add(x3, s3);

		Vector128<byte> v0 = Sse2.Xor(x0.AsByte(), Unsafe.ReadUnaligned<Vector128<byte>>(ref sourceRef));
		Vector128<byte> v1 = Sse2.Xor(x1.AsByte(), Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref sourceRef, 16)));
		Vector128<byte> v2 = Sse2.Xor(x2.AsByte(), Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref sourceRef, 32)));
		Vector128<byte> v3 = Sse2.Xor(x3.AsByte(), Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref sourceRef, 48)));

		Unsafe.WriteUnaligned(ref destRef, v0);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 16), v1);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 32), v2);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 48), v3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ChaChaCoreOriginal64(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ChaChaCore64Internal(rounds, state, source, destination);

		IncrementCounterOriginal(state);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ChaChaCore64(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ChaChaCore64Internal(rounds, state, source, destination);

		IncrementCounter(state);
	}

	#endregion

	#region 处理 128 bytes

	private static readonly Vector256<uint> IncCounter128 = Vector256.Create(0, 0, 0, 0, 1, 0, 0, 0).AsUInt32();
	private static readonly Vector256<ulong> IncCounterOriginal128 = Vector256.Create(0, 0, 1, 0).AsUInt64();

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ChaChaCoreOriginal128(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ref uint stateRef = ref MemoryMarshal.GetReference(state);
		ref byte sourceRef = ref MemoryMarshal.GetReference(source);
		ref byte destRef = ref MemoryMarshal.GetReference(destination);

		var v0 = Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref stateRef));
		var v1 = Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref Unsafe.Add(ref stateRef, 4)));
		var v2 = Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref Unsafe.Add(ref stateRef, 8)));
		var v3 = Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref Unsafe.Add(ref stateRef, 12)));

		Vector256<uint> x0 = Vector256.Create(v0, v0);
		Vector256<uint> x1 = Vector256.Create(v1, v1);
		Vector256<uint> x2 = Vector256.Create(v2, v2);
		Vector256<uint> x3 = Vector256.Create(v3, v3);
		x3 = Avx2.Add(x3.AsUInt64(), IncCounterOriginal128).AsUInt32();

		for (int i = 0; i < rounds; i += 2)
		{
			QuarterRound(ref x0, ref x1, ref x2, ref x3);
			Shuffle(ref x1, ref x2, ref x3);

			QuarterRound(ref x0, ref x1, ref x2, ref x3);
			Shuffle1(ref x1, ref x2, ref x3);
		}

		Shuffle(ref x0, ref x1, ref x2, ref x3);

		Vector256<uint> s0 = Unsafe.ReadUnaligned<Vector256<uint>>(ref Unsafe.As<uint, byte>(ref stateRef));
		Vector256<uint> s1 = Unsafe.ReadUnaligned<Vector256<uint>>(ref Unsafe.As<uint, byte>(ref Unsafe.Add(ref stateRef, 8)));
		IncrementCounterOriginal(state);

		x0 = Avx2.Add(x0, s0);
		x1 = Avx2.Add(x1, s1);
		x2 = Avx2.Add(x2, s0);
		x3 = Avx2.Add(x3, Unsafe.ReadUnaligned<Vector256<uint>>(ref Unsafe.As<uint, byte>(ref Unsafe.Add(ref stateRef, 8))));

		Vector256<byte> vx0 = Avx2.Xor(x0.AsByte(), Unsafe.ReadUnaligned<Vector256<byte>>(ref sourceRef));
		Vector256<byte> vx1 = Avx2.Xor(x1.AsByte(), Unsafe.ReadUnaligned<Vector256<byte>>(ref Unsafe.Add(ref sourceRef, 32)));
		Vector256<byte> vx2 = Avx2.Xor(x2.AsByte(), Unsafe.ReadUnaligned<Vector256<byte>>(ref Unsafe.Add(ref sourceRef, 64)));
		Vector256<byte> vx3 = Avx2.Xor(x3.AsByte(), Unsafe.ReadUnaligned<Vector256<byte>>(ref Unsafe.Add(ref sourceRef, 96)));

		Unsafe.WriteUnaligned(ref destRef, vx0);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 32), vx1);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 64), vx2);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 96), vx3);

		IncrementCounterOriginal(state);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ChaChaCore128(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ref uint stateRef = ref MemoryMarshal.GetReference(state);
		ref byte sourceRef = ref MemoryMarshal.GetReference(source);
		ref byte destRef = ref MemoryMarshal.GetReference(destination);

		var v0 = Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref stateRef));
		var v1 = Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref Unsafe.Add(ref stateRef, 4)));
		var v2 = Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref Unsafe.Add(ref stateRef, 8)));
		var v3 = Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref Unsafe.Add(ref stateRef, 12)));

		Vector256<uint> x0 = Vector256.Create(v0, v0);
		Vector256<uint> x1 = Vector256.Create(v1, v1);
		Vector256<uint> x2 = Vector256.Create(v2, v2);
		Vector256<uint> x3 = Vector256.Create(v3, v3);
		x3 = Avx2.Add(x3, IncCounter128);

		for (int i = 0; i < rounds; i += 2)
		{
			QuarterRound(ref x0, ref x1, ref x2, ref x3);
			Shuffle(ref x1, ref x2, ref x3);

			QuarterRound(ref x0, ref x1, ref x2, ref x3);
			Shuffle1(ref x1, ref x2, ref x3);
		}

		Shuffle(ref x0, ref x1, ref x2, ref x3);

		Vector256<uint> s0 = Unsafe.ReadUnaligned<Vector256<uint>>(ref Unsafe.As<uint, byte>(ref stateRef));
		Vector256<uint> s1 = Unsafe.ReadUnaligned<Vector256<uint>>(ref Unsafe.As<uint, byte>(ref Unsafe.Add(ref stateRef, 8)));
		IncrementCounter(state);

		x0 = Avx2.Add(x0, s0);
		x1 = Avx2.Add(x1, s1);
		x2 = Avx2.Add(x2, s0);
		x3 = Avx2.Add(x3, Unsafe.ReadUnaligned<Vector256<uint>>(ref Unsafe.As<uint, byte>(ref Unsafe.Add(ref stateRef, 8))));

		Vector256<byte> vx0 = Avx2.Xor(x0.AsByte(), Unsafe.ReadUnaligned<Vector256<byte>>(ref sourceRef));
		Vector256<byte> vx1 = Avx2.Xor(x1.AsByte(), Unsafe.ReadUnaligned<Vector256<byte>>(ref Unsafe.Add(ref sourceRef, 32)));
		Vector256<byte> vx2 = Avx2.Xor(x2.AsByte(), Unsafe.ReadUnaligned<Vector256<byte>>(ref Unsafe.Add(ref sourceRef, 64)));
		Vector256<byte> vx3 = Avx2.Xor(x3.AsByte(), Unsafe.ReadUnaligned<Vector256<byte>>(ref Unsafe.Add(ref sourceRef, 96)));

		Unsafe.WriteUnaligned(ref destRef, vx0);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 32), vx1);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 64), vx2);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destRef, 96), vx3);

		IncrementCounter(state);
	}

	#endregion

	#region 处理 256*n bytes

	public static readonly Vector128<ulong> IncCounter01 = Vector128.Create(0ul, 1);
	public static readonly Vector128<ulong> IncCounter23 = Vector128.Create(2ul, 3);
	private static readonly Vector128<uint> IncCounter0123_128 = Vector128.Create(0u, 1, 2, 3);

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ChaChaCoreOriginal256(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination, ref int length, ref int sourceOffset, ref int destOffset)
	{
		Vector128<uint> o0 = Vector128.Create(state[0]);
		Vector128<uint> o1 = Vector128.Create(state[1]);
		Vector128<uint> o2 = Vector128.Create(state[2]);
		Vector128<uint> o3 = Vector128.Create(state[3]);
		Vector128<uint> o4 = Vector128.Create(state[4]);
		Vector128<uint> o5 = Vector128.Create(state[5]);
		Vector128<uint> o6 = Vector128.Create(state[6]);
		Vector128<uint> o7 = Vector128.Create(state[7]);
		Vector128<uint> o8 = Vector128.Create(state[8]);
		Vector128<uint> o9 = Vector128.Create(state[9]);
		Vector128<uint> o10 = Vector128.Create(state[10]);
		Vector128<uint> o11 = Vector128.Create(state[11]);
		// 12
		// 13
		Vector128<uint> o14 = Vector128.Create(state[14]);
		Vector128<uint> o15 = Vector128.Create(state[15]);

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

			ulong counter = state[12] | (ulong)state[13] << 32;
			Vector128<uint> t0 = Vector128.Create(counter).AsUInt32();
			Vector128<uint> t1 = t0;

			Vector128<uint> x12 = Sse2.Add(IncCounter01, t0.AsUInt64()).AsUInt32();
			Vector128<uint> x13 = Sse2.Add(IncCounter23, t1.AsUInt64()).AsUInt32();

			t0 = Sse2.UnpackLow(x12, x13);
			t1 = Sse2.UnpackHigh(x12, x13);

			x12 = Sse2.UnpackLow(t0, t1);
			x13 = Sse2.UnpackHigh(t0, t1);

			Vector128<uint> o12 = x12;
			Vector128<uint> o13 = x13;

			counter += 4;

			state[12] = (uint)(counter & 0xFFFFFFFF);
			state[13] = (uint)(counter >> 32 & 0xFFFFFFFF);

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

			AddTransposeXor(ref x0, ref x1, ref x2, ref x3, ref o0, ref o1, ref o2, ref o3, source.Slice(sourceOffset), destination.Slice(destOffset));
			AddTransposeXor(ref x4, ref x5, ref x6, ref x7, ref o4, ref o5, ref o6, ref o7, source.Slice(sourceOffset + 16), destination.Slice(destOffset + 16));
			AddTransposeXor(ref x8, ref x9, ref x10, ref x11, ref o8, ref o9, ref o10, ref o11, source.Slice(sourceOffset + 32), destination.Slice(destOffset + 32));
			AddTransposeXor(ref x12, ref x13, ref x14, ref x15, ref o12, ref o13, ref o14, ref o15, source.Slice(sourceOffset + 48), destination.Slice(destOffset + 48));

			length -= 256;
			destOffset += 256;
			sourceOffset += 256;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ChaChaCore256(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination, ref int length, ref int sourceOffset, ref int destOffset)
	{
		Vector128<uint> o0 = Vector128.Create(state[0]);
		Vector128<uint> o1 = Vector128.Create(state[1]);
		Vector128<uint> o2 = Vector128.Create(state[2]);
		Vector128<uint> o3 = Vector128.Create(state[3]);
		Vector128<uint> o4 = Vector128.Create(state[4]);
		Vector128<uint> o5 = Vector128.Create(state[5]);
		Vector128<uint> o6 = Vector128.Create(state[6]);
		Vector128<uint> o7 = Vector128.Create(state[7]);
		Vector128<uint> o8 = Vector128.Create(state[8]);
		Vector128<uint> o9 = Vector128.Create(state[9]);
		Vector128<uint> o10 = Vector128.Create(state[10]);
		Vector128<uint> o11 = Vector128.Create(state[11]);
		// 12
		Vector128<uint> o13 = Vector128.Create(state[13]);
		Vector128<uint> o14 = Vector128.Create(state[14]);
		Vector128<uint> o15 = Vector128.Create(state[15]);

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

			Vector128<uint> x12 = Sse2.Add(IncCounter0123_128, Vector128.Create(state[12]));
			Vector128<uint> o12 = x12;

			state[12] += 4;

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

			AddTransposeXor(ref x0, ref x1, ref x2, ref x3, ref o0, ref o1, ref o2, ref o3, source, destination);
			AddTransposeXor(ref x4, ref x5, ref x6, ref x7, ref o4, ref o5, ref o6, ref o7, source + 16, destination + 16);
			AddTransposeXor(ref x8, ref x9, ref x10, ref x11, ref o8, ref o9, ref o10, ref o11, source + 32, destination + 32);
			AddTransposeXor(ref x12, ref x13, ref x14, ref x15, ref o12, ref o13, ref o14, ref o15, source + 48, destination + 48);

			length -= 256;
			destination += 256;
			source += 256;
		}
	}

	/// <summary>
	/// destination = (x+s) ^ source
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void AddTransposeXor(
		ref Vector128<uint> x0, ref Vector128<uint> x1, ref Vector128<uint> x2, ref Vector128<uint> x3,
		ref Vector128<uint> o0, ref Vector128<uint> o1, ref Vector128<uint> o2, ref Vector128<uint> o3,
		ReadOnlySpan<byte> source, Span<byte> destination)
	{
		// x+=o
		x0 = Sse2.Add(x0, o0);
		x1 = Sse2.Add(x1, o1);
		x2 = Sse2.Add(x2, o2);
		x3 = Sse2.Add(x3, o3);

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
		Unsafe.WriteUnaligned(ref MemoryMarshal.GetReference(destination), Sse2.Xor(x0.AsByte(), Sse2.LoadVector128(source)));
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref MemoryMarshal.GetReference(destination), 64), Sse2.Xor(x1.AsByte(), Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref MemoryMarshal.GetReference(source), 64))));
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref MemoryMarshal.GetReference(destination), 128), Sse2.Xor(x2.AsByte(), Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref MemoryMarshal.GetReference(source), 128))));
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref MemoryMarshal.GetReference(destination), 192), Sse2.Xor(x3.AsByte(), Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref MemoryMarshal.GetReference(source), 192))));
	}

	#endregion

	#region 处理 512*n bytes

	public static readonly Vector256<ulong> IncCounter0123 = Vector256.Create(0ul, 1, 2, 3);
	public static readonly Vector256<ulong> IncCounter4567 = Vector256.Create(4ul, 5, 6, 7);
	private static readonly Vector256<uint> IncCounter01234567 = Vector256.Create(0u, 1, 2, 3, 4, 5, 6, 7);
	public static readonly Vector256<uint> Permute3 = Vector256.Create(0, 1, 4, 5, 2, 3, 6, 7).AsUInt32();

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ChaChaCoreOriginal512(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination, ref int length, ref int sourceOffset, ref int destOffset)
	{
		Vector256<uint> o0 = Vector256.Create(state[0]);
		Vector256<uint> o1 = Vector256.Create(state[1]);
		Vector256<uint> o2 = Vector256.Create(state[2]);
		Vector256<uint> o3 = Vector256.Create(state[3]);
		Vector256<uint> o4 = Vector256.Create(state[4]);
		Vector256<uint> o5 = Vector256.Create(state[5]);
		Vector256<uint> o6 = Vector256.Create(state[6]);
		Vector256<uint> o7 = Vector256.Create(state[7]);
		Vector256<uint> o8 = Vector256.Create(state[8]);
		Vector256<uint> o9 = Vector256.Create(state[9]);
		Vector256<uint> o10 = Vector256.Create(state[10]);
		Vector256<uint> o11 = Vector256.Create(state[11]);
		Vector256<uint> o14 = Vector256.Create(state[14]);
		Vector256<uint> o15 = Vector256.Create(state[15]);

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

			ulong counter = state[12] | (ulong)state[13] << 32;
			Vector256<uint> x12 = Vector256.Create(counter).AsUInt32();
			Vector256<uint> x13 = x12;

			Vector256<uint> t0 = Avx2.Add(IncCounter0123, x12.AsUInt64()).AsUInt32();
			Vector256<uint> t1 = Avx2.Add(IncCounter4567, x13.AsUInt64()).AsUInt32();

			x12 = Avx2.UnpackLow(t0, t1);
			x13 = Avx2.UnpackHigh(t0, t1);

			t0 = Avx2.UnpackLow(x12, x13);
			t1 = Avx2.UnpackHigh(x12, x13);

			x12 = Avx2.PermuteVar8x32(t0, Permute3);
			x13 = Avx2.PermuteVar8x32(t1, Permute3);

			Vector256<uint> o12 = x12;
			Vector256<uint> o13 = x13;

			counter += 8;

			state[12] = (uint)(counter & 0xFFFFFFFF);
			state[13] = (uint)(counter >> 32 & 0xFFFFFFFF);

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

			AddTransposeXor(
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
				source,
				destination);
			AddTransposeXor(
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
				source + 32,
				destination + 32);

			length -= 512;
			destination += 512;
			source += 512;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ChaChaCore512(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination, ref int length, ref int sourceOffset, ref int destOffset)
	{
		Vector256<uint> o0 = Vector256.Create(state[0]);
		Vector256<uint> o1 = Vector256.Create(state[1]);
		Vector256<uint> o2 = Vector256.Create(state[2]);
		Vector256<uint> o3 = Vector256.Create(state[3]);
		Vector256<uint> o4 = Vector256.Create(state[4]);
		Vector256<uint> o5 = Vector256.Create(state[5]);
		Vector256<uint> o6 = Vector256.Create(state[6]);
		Vector256<uint> o7 = Vector256.Create(state[7]);
		Vector256<uint> o8 = Vector256.Create(state[8]);
		Vector256<uint> o9 = Vector256.Create(state[9]);
		Vector256<uint> o10 = Vector256.Create(state[10]);
		Vector256<uint> o11 = Vector256.Create(state[11]);
		Vector256<uint> o13 = Vector256.Create(state[13]);
		Vector256<uint> o14 = Vector256.Create(state[14]);
		Vector256<uint> o15 = Vector256.Create(state[15]);

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

			Vector256<uint> x12 = Avx2.Add(IncCounter01234567, Vector256.Create(state[12]));
			Vector256<uint> o12 = x12;

			state[12] += 8;

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

			AddTransposeXor(
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
				source,
				destination);
			AddTransposeXor(
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
				source + 32,
				destination + 32);

			length -= 512;
			destination += 512;
			source += 512;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void AddTransposeXor(
		ref Vector256<uint> x0, ref Vector256<uint> x1, ref Vector256<uint> x2, ref Vector256<uint> x3,
		ref Vector256<uint> x4, ref Vector256<uint> x5, ref Vector256<uint> x6, ref Vector256<uint> x7,
		ref Vector256<uint> o0, ref Vector256<uint> o1, ref Vector256<uint> o2, ref Vector256<uint> o3,
		ref Vector256<uint> o4, ref Vector256<uint> o5, ref Vector256<uint> o6, ref Vector256<uint> o7,
		ReadOnlySpan<byte> source, Span<byte> destination)
	{
		// x += o
		x0 = Avx2.Add(x0, o0);
		x1 = Avx2.Add(x1, o1);
		x2 = Avx2.Add(x2, o2);
		x3 = Avx2.Add(x3, o3);
		x4 = Avx2.Add(x4, o4);
		x5 = Avx2.Add(x5, o5);
		x6 = Avx2.Add(x6, o6);
		x7 = Avx2.Add(x7, o7);

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
		Avx.Store(destination, Avx2.Xor(t0.AsByte(), Avx.LoadVector256(source)));
		Avx.Store(destination + 64, Avx2.Xor(t1.AsByte(), Avx.LoadVector256(source + 64)));
		Avx.Store(destination + 128, Avx2.Xor(t2.AsByte(), Avx.LoadVector256(source + 128)));
		Avx.Store(destination + 192, Avx2.Xor(t3.AsByte(), Avx.LoadVector256(source + 192)));
		Avx.Store(destination + 256, Avx2.Xor(t4.AsByte(), Avx.LoadVector256(source + 256)));
		Avx.Store(destination + 320, Avx2.Xor(t5.AsByte(), Avx.LoadVector256(source + 320)));
		Avx.Store(destination + 384, Avx2.Xor(t6.AsByte(), Avx.LoadVector256(source + 384)));
		Avx.Store(destination + 448, Avx2.Xor(t7.AsByte(), Avx.LoadVector256(source + 448)));
	}

	#endregion

	#region Avx

	private static readonly Vector256<uint> Permute0 = Vector256.Create(1, 2, 3, 0, 5, 6, 7, 4).AsUInt32();
	private static readonly Vector256<uint> Permute1 = Vector256.Create(2, 3, 0, 1, 6, 7, 4, 5).AsUInt32();
	private static readonly Vector256<uint> Permute2 = Vector256.Create(3, 0, 1, 2, 7, 4, 5, 6).AsUInt32();

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
		a = Avx2.PermuteVar8x32(a, Permute0);
		b = Avx2.PermuteVar8x32(b, Permute1);
		c = Avx2.PermuteVar8x32(c, Permute2);
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
		a = Avx2.PermuteVar8x32(a, Permute2);
		b = Avx2.PermuteVar8x32(b, Permute1);
		c = Avx2.PermuteVar8x32(c, Permute0);
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
