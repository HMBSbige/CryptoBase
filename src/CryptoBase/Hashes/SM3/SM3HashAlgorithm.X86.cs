namespace CryptoBase.Hashes.SM3;

public partial struct SM3HashAlgorithm
{
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void ProcessBlocksX86(ref SM3HashAlgorithm hashAlgorithm, ReadOnlySpan<byte> source)
	{
		Debug.Assert(X86Base.X64.IsSupported && Ssse3.IsSupported);
		Debug.Assert(!source.IsEmpty);
		Debug.Assert(source.Length % BlockSizeInBytes is 0);

		ref byte block0 = ref source.GetReference();
		int remaining = source.Length;
		uint a = hashAlgorithm._v0;
		uint b = hashAlgorithm._v1;
		uint c = hashAlgorithm._v2;
		uint d = hashAlgorithm._v3;
		uint e = hashAlgorithm._v4;
		uint f = hashAlgorithm._v5;
		uint g = hashAlgorithm._v6;
		uint h = hashAlgorithm._v7;

		do
		{
			Vector128<uint> q0 = LoadWordsX86(ref block0, 0);
			Vector128<uint> q1 = LoadWordsX86(ref block0, 16);
			Vector128<uint> q2 = LoadWordsX86(ref block0, 32);
			Vector128<uint> q3 = LoadWordsX86(ref block0, 48);

			Round4EarlyX86(ref a, ref b, ref c, ref d, ref e, ref f, ref g, ref h, q0, q0 ^ q1, 0);
			Round2EarlyX86(ref a, ref b, ref c, ref d, ref e, ref f, ref g, ref h, q1, q1 ^ q2);

			Vector128<uint> w0 = Sse2.Shuffle(q0, 0b01_00_11_10);
			Vector128<uint> w1 = Sse2.Shuffle(q0, 0b00_11_10_01);
			Vector128<uint> w2 = q1;
			Vector128<uint> w3 = Ssse3.AlignRight(q2, q1, 12);
			Vector128<uint> w4 = Ssse3.AlignRight(q3, q2, 8);
			Vector128<uint> w5 = Sse2.ShiftRightLogical128BitLane(q3, 4);

			for (int round = 6; round < 15; round += 3)
			{
				Vector128<uint> words = WindowX86(w2, w3);
				Vector128<uint> next = ScheduleAndRound3EarlyX86(ref a, ref b, ref c, ref d, ref e, ref f, ref g, ref h, w0, w1, w2, w3, w4, w5, words, words ^ w4, round);

				w0 = w1;
				w1 = w2;
				w2 = w3;
				w3 = w4;
				w4 = w5;
				w5 = next;
			}

			{
				Vector128<uint> words = WindowX86(w2, w3);
				Vector128<uint> next = ScheduleAndRoundMixedX86(ref a, ref b, ref c, ref d, ref e, ref f, ref g, ref h, w0, w1, w2, w3, w4, w5, words, words ^ w4);
				w0 = w1;
				w1 = w2;
				w2 = w3;
				w3 = w4;
				w4 = w5;
				w5 = next;
			}

			ref uint roundConstants = ref RoundConstants.GetReference();

			for (int round = 18; round < 60; round += 3)
			{
				Vector128<uint> words = WindowX86(w2, w3);
				Vector128<uint> next = ScheduleAndRound3LateX86(ref a, ref b, ref c, ref d, ref e, ref f, ref g, ref h, w0, w1, w2, w3, w4, w5, words, words ^ w4, ref roundConstants, round);
				w0 = w1;
				w1 = w2;
				w2 = w3;
				w3 = w4;
				w4 = w5;
				w5 = next;
			}

			Vector128<uint> words60 = WindowX86(w2, w3);
			Round3LateX86(ref a, ref b, ref c, ref d, ref e, ref f, ref g, ref h, words60, words60 ^ w4, 60);
			RoundLateX86(ref a, ref b, ref c, ref d, ref e, ref f, ref g, ref h, words60.GetElement(3), words60.GetElement(3) ^ w5.GetElement(0), RoundConstants[63]);

			hashAlgorithm._v0 = a ^= hashAlgorithm._v0;
			hashAlgorithm._v1 = b ^= hashAlgorithm._v1;
			hashAlgorithm._v2 = c ^= hashAlgorithm._v2;
			hashAlgorithm._v3 = d ^= hashAlgorithm._v3;
			hashAlgorithm._v4 = e ^= hashAlgorithm._v4;
			hashAlgorithm._v5 = f ^= hashAlgorithm._v5;
			hashAlgorithm._v6 = g ^= hashAlgorithm._v6;
			hashAlgorithm._v7 = h ^= hashAlgorithm._v7;

			block0 = ref Unsafe.Add(ref block0, BlockSizeInBytes);
			remaining -= BlockSizeInBytes;
		} while (remaining is not 0);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> LoadWordsX86(ref byte source, nuint byteOffset)
	{
		return Vector128.LoadUnsafe(ref source, byteOffset).ReverseEndianness32().AsUInt32();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> WindowX86(Vector128<uint> previous, Vector128<uint> next)
	{
		Vector128<uint> tail = Sse2.Shuffle(previous, 0b10_11_11_11);
		return Ssse3.AlignRight(next, tail, 12);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> P1X86(Vector128<uint> value)
	{
		if (Avx512F.VL.IsSupported)
		{
			return value ^ value.RotateLeftUInt32(15) ^ value.RotateLeftUInt32(23);
		}

		return P1(value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> ScheduleAndRound3EarlyX86
	(
		ref uint a, ref uint b, ref uint c, ref uint d, ref uint e, ref uint f, ref uint g, ref uint h,
		Vector128<uint> w0, Vector128<uint> w1, Vector128<uint> w2, Vector128<uint> w3, Vector128<uint> w4, Vector128<uint> w5,
		Vector128<uint> words, Vector128<uint> mixed,
		int round
	)
	{
		Vector128<ulong> packed01 = Sse2.UnpackLow(words, mixed).AsUInt64();
		ulong packedRound = packed01.ToScalar();
		Vector128<uint> partial = WindowX86(w0, w1);
		d = RoundSoftwareEarly(a, b, c, d, e, f, g, h, (uint)packedRound, (uint)(packedRound >> 32), RoundConstants[round], out h);
		b = b.RotateLeft(9);
		f = f.RotateLeft(19);
		partial ^= w3 ^ w5.RotateLeftUInt32(15);
		Vector128<uint> window13 = WindowX86(w1, w2);
		packedRound = packed01.GetElement(1);
		c = RoundSoftwareEarly(d, a, b, c, h, e, f, g, (uint)packedRound, (uint)(packedRound >> 32), RoundConstants[round + 1], out g);
		a = a.RotateLeft(9);
		e = e.RotateLeft(19);
		Vector128<uint> next = P1X86(partial);
		packedRound = Sse2.UnpackHigh(words, mixed).AsUInt64().ToScalar();
		b = RoundSoftwareEarly(c, d, a, b, g, h, e, f, (uint)packedRound, (uint)(packedRound >> 32), RoundConstants[round + 2], out f);
		d = d.RotateLeft(9);
		h = h.RotateLeft(19);
		(a, b, c, d) = (b, c, d, a);
		(e, f, g, h) = (f, g, h, e);
		return next ^ window13.RotateLeftUInt32(7) ^ w4;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Round4EarlyX86
	(
		ref uint a, ref uint b, ref uint c, ref uint d, ref uint e, ref uint f, ref uint g, ref uint h,
		Vector128<uint> words, Vector128<uint> mixed,
		int round
	)
	{
		d = RoundSoftwareEarly(a, b, c, d, e, f, g, h, words.GetElement(0), mixed.GetElement(0), RoundConstants[round], out h);
		b = b.RotateLeft(9);
		f = f.RotateLeft(19);
		c = RoundSoftwareEarly(d, a, b, c, h, e, f, g, words.GetElement(1), mixed.GetElement(1), RoundConstants[round + 1], out g);
		a = a.RotateLeft(9);
		e = e.RotateLeft(19);
		b = RoundSoftwareEarly(c, d, a, b, g, h, e, f, words.GetElement(2), mixed.GetElement(2), RoundConstants[round + 2], out f);
		d = d.RotateLeft(9);
		h = h.RotateLeft(19);
		a = RoundSoftwareEarly(b, c, d, a, f, g, h, e, words.GetElement(3), mixed.GetElement(3), RoundConstants[round + 3], out e);
		c = c.RotateLeft(9);
		g = g.RotateLeft(19);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Round2EarlyX86
	(
		ref uint a, ref uint b, ref uint c, ref uint d, ref uint e, ref uint f, ref uint g, ref uint h,
		Vector128<uint> words, Vector128<uint> mixed
	)
	{
		d = RoundSoftwareEarly(a, b, c, d, e, f, g, h, words.GetElement(0), mixed.GetElement(0), RoundConstants[4], out h);
		b = b.RotateLeft(9);
		f = f.RotateLeft(19);
		c = RoundSoftwareEarly(d, a, b, c, h, e, f, g, words.GetElement(1), mixed.GetElement(1), RoundConstants[5], out g);
		a = a.RotateLeft(9);
		e = e.RotateLeft(19);
		(a, b, c, d) = (c, d, a, b);
		(e, f, g, h) = (g, h, e, f);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> ScheduleAndRoundMixedX86
	(
		ref uint a, ref uint b, ref uint c, ref uint d, ref uint e, ref uint f, ref uint g, ref uint h,
		Vector128<uint> w0, Vector128<uint> w1, Vector128<uint> w2, Vector128<uint> w3, Vector128<uint> w4, Vector128<uint> w5,
		Vector128<uint> words, Vector128<uint> mixed
	)
	{
		Vector128<ulong> packed01 = Sse2.UnpackLow(words, mixed).AsUInt64();
		ulong packedRound = packed01.ToScalar();
		Vector128<uint> partial = WindowX86(w0, w1);
		d = RoundSoftwareEarly(a, b, c, d, e, f, g, h, (uint)packedRound, (uint)(packedRound >> 32), RoundConstants[15], out h);
		b = b.RotateLeft(9);
		f = f.RotateLeft(19);
		partial ^= w3 ^ w5.RotateLeftUInt32(15);
		Vector128<uint> window13 = WindowX86(w1, w2);
		packedRound = packed01.GetElement(1);
		c = RoundSoftwareLate(d, a, b, c, h, e, f, g, (uint)packedRound, (uint)(packedRound >> 32), RoundConstants[16], out g);
		a = a.RotateLeft(9);
		e = e.RotateLeft(19);
		Vector128<uint> next = P1X86(partial);
		packedRound = Sse2.UnpackHigh(words, mixed).AsUInt64().ToScalar();
		b = RoundSoftwareLate(c, d, a, b, g, h, e, f, (uint)packedRound, (uint)(packedRound >> 32), RoundConstants[17], out f);
		d = d.RotateLeft(9);
		h = h.RotateLeft(19);
		(a, b, c, d) = (b, c, d, a);
		(e, f, g, h) = (f, g, h, e);
		return next ^ window13.RotateLeftUInt32(7) ^ w4;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> ScheduleAndRound3LateX86
	(
		ref uint a, ref uint b, ref uint c, ref uint d, ref uint e, ref uint f, ref uint g, ref uint h,
		Vector128<uint> w0, Vector128<uint> w1, Vector128<uint> w2, Vector128<uint> w3, Vector128<uint> w4, Vector128<uint> w5,
		Vector128<uint> words, Vector128<uint> mixed, ref uint roundConstants,
		int round
	)
	{
		Vector128<ulong> packed01 = Sse2.UnpackLow(words, mixed).AsUInt64();
		ulong packedRound = packed01.ToScalar();
		Vector128<uint> partial = WindowX86(w0, w1);
		d = RoundSoftwareLate(a, b, c, d, e, f, g, h, (uint)packedRound, (uint)(packedRound >> 32), Unsafe.Add(ref roundConstants, round), out h);
		b = b.RotateLeft(9);
		f = f.RotateLeft(19);
		partial ^= w3 ^ w5.RotateLeftUInt32(15);
		Vector128<uint> window13 = WindowX86(w1, w2);
		packedRound = packed01.GetElement(1);
		c = RoundSoftwareLate(d, a, b, c, h, e, f, g, (uint)packedRound, (uint)(packedRound >> 32), Unsafe.Add(ref roundConstants, round + 1), out g);
		a = a.RotateLeft(9);
		e = e.RotateLeft(19);
		Vector128<uint> next = P1X86(partial);
		packedRound = Sse2.UnpackHigh(words, mixed).AsUInt64().ToScalar();
		b = RoundSoftwareLate(c, d, a, b, g, h, e, f, (uint)packedRound, (uint)(packedRound >> 32), Unsafe.Add(ref roundConstants, round + 2), out f);
		d = d.RotateLeft(9);
		h = h.RotateLeft(19);
		(a, b, c, d) = (b, c, d, a);
		(e, f, g, h) = (f, g, h, e);
		return next ^ window13.RotateLeftUInt32(7) ^ w4;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Round3LateX86
	(
		ref uint a, ref uint b, ref uint c, ref uint d, ref uint e, ref uint f, ref uint g, ref uint h,
		Vector128<uint> words, Vector128<uint> mixed,
		int round
	)
	{
		Vector128<ulong> packed01 = Sse2.UnpackLow(words, mixed).AsUInt64();
		ulong packedRound = packed01.ToScalar();
		d = RoundSoftwareLate(a, b, c, d, e, f, g, h, (uint)packedRound, (uint)(packedRound >> 32), RoundConstants[round], out h);
		b = b.RotateLeft(9);
		f = f.RotateLeft(19);
		packedRound = packed01.GetElement(1);
		c = RoundSoftwareLate(d, a, b, c, h, e, f, g, (uint)packedRound, (uint)(packedRound >> 32), RoundConstants[round + 1], out g);
		a = a.RotateLeft(9);
		e = e.RotateLeft(19);
		packedRound = Sse2.UnpackHigh(words, mixed).AsUInt64().ToScalar();
		b = RoundSoftwareLate(c, d, a, b, g, h, e, f, (uint)packedRound, (uint)(packedRound >> 32), RoundConstants[round + 2], out f);
		d = d.RotateLeft(9);
		h = h.RotateLeft(19);
		(a, b, c, d) = (b, c, d, a);
		(e, f, g, h) = (f, g, h, e);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void RoundLateX86
	(
		ref uint a, ref uint b, ref uint c, ref uint d, ref uint e, ref uint f, ref uint g, ref uint h,
		uint word, uint mixed,
		uint constant
	)
	{
		uint a12 = a.RotateLeft(12);
		uint ss1 = (a12 + e + constant).RotateLeft(7);
		uint tt1 = FF1(a, b, c) + d + (ss1 ^ a12) + mixed;
		uint tt2 = GG1(e, f, g) + h + ss1 + word;
		d = c;
		c = b.RotateLeft(9);
		b = a;
		a = tt1;
		h = g;
		g = f.RotateLeft(19);
		f = e;
		e = P0(tt2);
	}
}
