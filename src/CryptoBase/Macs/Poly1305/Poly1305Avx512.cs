namespace CryptoBase.Macs.Poly1305;

internal ref struct Poly1305Avx512 : IPoly1305State<Poly1305Avx512>
{
	private const int BlockSize8 = Poly1305Algorithm.BlockSizeInBytes * 8;
	private const int SixteenWayMinimumInputLength = BlockSize8 * 7;

	public static bool IsSupported
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => Vector512.IsHardwareAccelerated && Avx512F.IsSupported && Avx2.IsSupported;
	}

	private Poly1305State26 _state;
	private Vector512<uint> _r0, _r1, _r2, _r3, _r4;
	private Vector512<uint> _s1, _s2, _s3, _s4;
	private bool _hasSixteenthPower;

	private void Initialize(scoped ReadOnlySpan<byte> key)
	{
		Debug.Assert(IsSupported);
		Debug.Assert(key.Length is Poly1305Algorithm.KeyLengthInBytes);

		_state.Initialize(key);
		_state.GetPowers(out Poly1305Power r1, out Poly1305Power r2, out Poly1305Power r3, out Poly1305Power r4);

		Vector256<uint> lower0 = Vector256.CreateUInt32EvenLanes(r4.Limb0, r3.Limb0, r2.Limb0, r1.Limb0);
		Vector256<uint> lower1 = Vector256.CreateUInt32EvenLanes(r4.Limb1, r3.Limb1, r2.Limb1, r1.Limb1);
		Vector256<uint> lower2 = Vector256.CreateUInt32EvenLanes(r4.Limb2, r3.Limb2, r2.Limb2, r1.Limb2);
		Vector256<uint> lower3 = Vector256.CreateUInt32EvenLanes(r4.Limb3, r3.Limb3, r2.Limb3, r1.Limb3);
		Vector256<uint> lower4 = Vector256.CreateUInt32EvenLanes(r4.Limb4, r3.Limb4, r2.Limb4, r1.Limb4);
		MultiplyFourByPower4(lower0, lower1, lower2, lower3, lower4, r4.Limb0, r4.Limb1, r4.Limb2, r4.Limb3, r4.Limb4, out Vector256<uint> upper0, out Vector256<uint> upper1, out Vector256<uint> upper2, out Vector256<uint> upper3, out Vector256<uint> upper4);

		_r0 = InterleavePowers(upper0, lower0);
		_r1 = InterleavePowers(upper1, lower1);
		_r2 = InterleavePowers(upper2, lower2);
		_r3 = InterleavePowers(upper3, lower3);
		_r4 = InterleavePowers(upper4, lower4);
		_s1 = _r1 * 5;
		_s2 = _r2 * 5;
		_s3 = _r3 * 5;
		_s4 = _r4 * 5;
		_hasSixteenthPower = false;
	}

	public static void Initialize(ref Poly1305Avx512 state, scoped ReadOnlySpan<byte> key)
	{
		state.Initialize(key);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<uint> InterleavePowers(Vector256<uint> upper, Vector256<uint> lower)
	{
		// Indices 0-3 and 8-11 read only the low halves, so the undefined upper bits from ToVector512Unsafe are never used.
		return Avx512F.PermuteVar8x64x2(upper.AsUInt64().ToVector512Unsafe(), Vector512.Create(0UL, 8, 1, 9, 2, 10, 3, 11), lower.AsUInt64().ToVector512Unsafe()).AsUInt32();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void MultiplyFourByPower4
	(
		Vector256<uint> h0, Vector256<uint> h1, Vector256<uint> h2, Vector256<uint> h3, Vector256<uint> h4,
		uint power0, uint power1, uint power2, uint power3, uint power4,
		out Vector256<uint> result0, out Vector256<uint> result1, out Vector256<uint> result2, out Vector256<uint> result3, out Vector256<uint> result4
	)
	{
		Vector256<uint> r0 = Vector256.Create(power0);
		Vector256<uint> r1 = Vector256.Create(power1);
		Vector256<uint> r2 = Vector256.Create(power2);
		Vector256<uint> r3 = Vector256.Create(power3);
		Vector256<uint> r4 = Vector256.Create(power4);
		Vector256<uint> s1 = Vector256.Create(power1 * 5);
		Vector256<uint> s2 = Vector256.Create(power2 * 5);
		Vector256<uint> s3 = Vector256.Create(power3 * 5);
		Vector256<uint> s4 = Vector256.Create(power4 * 5);

		Vector256<ulong> d0 = Avx2.Multiply(h0, r0) + Avx2.Multiply(h1, s4) + Avx2.Multiply(h2, s3) + Avx2.Multiply(h3, s2) + Avx2.Multiply(h4, s1);
		Vector256<ulong> d1 = Avx2.Multiply(h0, r1) + Avx2.Multiply(h1, r0) + Avx2.Multiply(h2, s4) + Avx2.Multiply(h3, s3) + Avx2.Multiply(h4, s2);
		Vector256<ulong> d2 = Avx2.Multiply(h0, r2) + Avx2.Multiply(h1, r1) + Avx2.Multiply(h2, r0) + Avx2.Multiply(h3, s4) + Avx2.Multiply(h4, s3);
		Vector256<ulong> d3 = Avx2.Multiply(h0, r3) + Avx2.Multiply(h1, r2) + Avx2.Multiply(h2, r1) + Avx2.Multiply(h3, r0) + Avx2.Multiply(h4, s4);
		Vector256<ulong> d4 = Avx2.Multiply(h0, r4) + Avx2.Multiply(h1, r3) + Avx2.Multiply(h2, r2) + Avx2.Multiply(h3, r1) + Avx2.Multiply(h4, r0);
		Vector256<ulong> mask = Vector256.Create((ulong)Poly1305State26.LimbMask);

		d1 += d0 >>> 26;
		d0 &= mask;
		d2 += d1 >>> 26;
		d1 &= mask;
		d3 += d2 >>> 26;
		d2 &= mask;
		d4 += d3 >>> 26;
		d3 &= mask;
		d0 += (d4 >>> 26) * 5;
		d4 &= mask;
		d1 += d0 >>> 26;
		d0 &= mask;
		result0 = d0.AsUInt32();
		result1 = d1.AsUInt32();
		result2 = d2.AsUInt32();
		result3 = d3.AsUInt32();
		result4 = d4.AsUInt32();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void LoadEight(ref byte source, out Vector512<ulong> m0, out Vector512<ulong> m1, out Vector512<ulong> m2, out Vector512<ulong> m3, out Vector512<ulong> m4)
	{
		Vector512<ulong> first = Vector512.LoadUnsafe(ref source).AsUInt64();
		Vector512<ulong> second = Vector512.LoadUnsafe(ref source, 64).AsUInt64();
		Vector512<ulong> low = Avx512F.UnpackLow(first, second);
		Vector512<ulong> high = Avx512F.UnpackHigh(first, second);
		Vector512<ulong> mask = Vector512.Create((ulong)Poly1305State26.LimbMask);

		m0 = low & mask;
		m1 = low >>> 26 & mask;
		m2 = (low >>> 52 | high << 12) & mask;
		m3 = high >>> 14 & mask;
		m4 = high >>> 40 | Vector512.Create((ulong)Poly1305State26.FullBlockHighBit);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<uint> BroadcastSixteenth(ref Vector512<uint> value)
	{
		ref uint first = ref Unsafe.As<Vector512<uint>, uint>(ref value);
		return Vector512.Create(Unsafe.Add(ref first, 1));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void EnsureSixteenthPower()
	{
		if (_hasSixteenthPower)
		{
			return;
		}

		Poly1305Power r16 = Poly1305State26.Square(new Poly1305Power(_r0.GetElement(0), _r1.GetElement(0), _r2.GetElement(0), _r3.GetElement(0), _r4.GetElement(0)));
		_r0 = _r0.WithElement(1, r16.Limb0);
		_r1 = _r1.WithElement(1, r16.Limb1);
		_r2 = _r2.WithElement(1, r16.Limb2);
		_r3 = _r3.WithElement(1, r16.Limb3);
		_r4 = _r4.WithElement(1, r16.Limb4);
		_s1 = _r1 * 5;
		_s2 = _r2 * 5;
		_s3 = _r3 * 5;
		_s4 = _r4 * 5;
		_hasSixteenthPower = true;
	}

	private void AppendEightWay(scoped ReadOnlySpan<byte> source)
	{
		Debug.Assert(source.Length >= BlockSize8 && source.Length % BlockSize8 is 0);
		int length = source.Length;
		ref byte input = ref MemoryMarshal.GetReference(source);
		Vector512<ulong> mask = Vector512.Create((ulong)Poly1305State26.LimbMask);
		Vector512<ulong> h0 = Vector512.CreateScalar(_state.H0).AsUInt64();
		Vector512<ulong> h1 = Vector512.CreateScalar(_state.H1).AsUInt64();
		Vector512<ulong> h2 = Vector512.CreateScalar(_state.H2).AsUInt64();
		Vector512<ulong> h3 = Vector512.CreateScalar(_state.H3).AsUInt64();
		Vector512<ulong> h4 = Vector512.CreateScalar(_state.H4).AsUInt64();
		Vector512<uint> r0 = BroadcastEighth(ref _r0);
		Vector512<uint> r1 = BroadcastEighth(ref _r1);
		Vector512<uint> r2 = BroadcastEighth(ref _r2);
		Vector512<uint> r3 = BroadcastEighth(ref _r3);
		Vector512<uint> r4 = BroadcastEighth(ref _r4);
		Vector512<uint> s1 = BroadcastEighth(ref _s1);
		Vector512<uint> s2 = BroadcastEighth(ref _s2);
		Vector512<uint> s3 = BroadcastEighth(ref _s3);
		Vector512<uint> s4 = BroadcastEighth(ref _s4);

		LoadEight(ref input, out Vector512<ulong> m0, out Vector512<ulong> m1, out Vector512<ulong> m2, out Vector512<ulong> m3, out Vector512<ulong> m4);
		h2 += m2;
		int remaining = length - BlockSize8;

		while (remaining is not 0)
		{
			h0 += m0;
			h1 += m1;
			h3 += m3;
			h4 += m4;

			Vector512<ulong> loopD2 = Avx512F.Multiply(h2.AsUInt32(), r0);
			Vector512<ulong> loopD3 = Avx512F.Multiply(h2.AsUInt32(), r1);
			Vector512<ulong> loopD4 = Avx512F.Multiply(h2.AsUInt32(), r2);
			Vector512<ulong> loopD0 = Avx512F.Multiply(h2.AsUInt32(), s3);
			Vector512<ulong> loopD1 = Avx512F.Multiply(h2.AsUInt32(), s4);

			loopD1 += Avx512F.Multiply(h0.AsUInt32(), r1);
			loopD2 += Avx512F.Multiply(h1.AsUInt32(), r1);
			loopD4 += Avx512F.Multiply(h3.AsUInt32(), r1);
			loopD0 += Avx512F.Multiply(h4.AsUInt32(), s1);
			loopD0 += Avx512F.Multiply(h0.AsUInt32(), r0);
			loopD1 += Avx512F.Multiply(h1.AsUInt32(), r0);
			loopD3 += Avx512F.Multiply(h3.AsUInt32(), r0);
			loopD4 += Avx512F.Multiply(h4.AsUInt32(), r0);
			loopD0 += Avx512F.Multiply(h3.AsUInt32(), s2);
			loopD1 += Avx512F.Multiply(h4.AsUInt32(), s2);
			loopD3 += Avx512F.Multiply(h1.AsUInt32(), r2);
			loopD2 += Avx512F.Multiply(h0.AsUInt32(), r2);
			loopD4 += Avx512F.Multiply(h1.AsUInt32(), r3);
			loopD3 += Avx512F.Multiply(h0.AsUInt32(), r3);
			loopD1 += Avx512F.Multiply(h3.AsUInt32(), s3);
			loopD2 += Avx512F.Multiply(h4.AsUInt32(), s3);
			loopD2 += Avx512F.Multiply(h3.AsUInt32(), s4);
			loopD3 += Avx512F.Multiply(h4.AsUInt32(), s4);
			loopD4 += Avx512F.Multiply(h0.AsUInt32(), r4);
			loopD0 += Avx512F.Multiply(h1.AsUInt32(), s4);

			Reduce(loopD0, loopD1, loopD2, loopD3, loopD4, mask, out h0, out h1, out h2, out h3, out h4);

			input = ref Unsafe.Add(ref input, BlockSize8);
			LoadEight(ref input, out m0, out m1, out m2, out m3, out m4);
			h2 += m2;
			remaining -= BlockSize8;
		}

		h0 += m0;
		h1 += m1;
		h3 += m3;
		h4 += m4;
		SetAccumulatorFromLanes(h0.AsUInt32(), h1.AsUInt32(), h2.AsUInt32(), h3.AsUInt32(), h4.AsUInt32());
	}

	private void AppendSixteenWay(scoped ReadOnlySpan<byte> source)
	{
		Debug.Assert(source.Length >= BlockSize8 && source.Length % BlockSize8 is 0);
		Debug.Assert(_hasSixteenthPower);
		int length = source.Length;
		ref byte input = ref MemoryMarshal.GetReference(source);
		Vector512<ulong> mask = Vector512.Create((ulong)Poly1305State26.LimbMask);
		Vector512<ulong> h0 = Vector512.CreateScalar(_state.H0).AsUInt64();
		Vector512<ulong> h1 = Vector512.CreateScalar(_state.H1).AsUInt64();
		Vector512<ulong> h2 = Vector512.CreateScalar(_state.H2).AsUInt64();
		Vector512<ulong> h3 = Vector512.CreateScalar(_state.H3).AsUInt64();
		Vector512<ulong> h4 = Vector512.CreateScalar(_state.H4).AsUInt64();
		Vector512<uint> r0 = BroadcastEighth(ref _r0);
		Vector512<uint> r1 = BroadcastEighth(ref _r1);
		Vector512<uint> r2 = BroadcastEighth(ref _r2);
		Vector512<uint> r3 = BroadcastEighth(ref _r3);
		Vector512<uint> r4 = BroadcastEighth(ref _r4);
		Vector512<uint> s1 = BroadcastEighth(ref _s1);
		Vector512<uint> s2 = BroadcastEighth(ref _s2);
		Vector512<uint> s3 = BroadcastEighth(ref _s3);
		Vector512<uint> s4 = BroadcastEighth(ref _s4);

		LoadEight(ref input, out Vector512<ulong> m0, out Vector512<ulong> m1, out Vector512<ulong> m2, out Vector512<ulong> m3, out Vector512<ulong> m4);
		h0 += m0;
		h1 += m1;
		h2 += m2;
		h3 += m3;
		h4 += m4;
		input = ref Unsafe.Add(ref input, BlockSize8);
		int remaining = length - BlockSize8;

		while (remaining >= BlockSize8 * 2)
		{
			Vector512<uint> coefficient = BroadcastSixteenth(ref _r0);
			Vector512<ulong> loopD0 = Avx512F.Multiply(h0.AsUInt32(), coefficient);
			Vector512<ulong> loopD1 = Avx512F.Multiply(h1.AsUInt32(), coefficient);
			Vector512<ulong> loopD2 = Avx512F.Multiply(h2.AsUInt32(), coefficient);
			Vector512<ulong> loopD3 = Avx512F.Multiply(h3.AsUInt32(), coefficient);
			Vector512<ulong> loopD4 = Avx512F.Multiply(h4.AsUInt32(), coefficient);

			coefficient = BroadcastSixteenth(ref _r1);
			loopD1 += Avx512F.Multiply(h0.AsUInt32(), coefficient);
			loopD2 += Avx512F.Multiply(h1.AsUInt32(), coefficient);
			loopD3 += Avx512F.Multiply(h2.AsUInt32(), coefficient);
			loopD4 += Avx512F.Multiply(h3.AsUInt32(), coefficient);

			coefficient = BroadcastSixteenth(ref _r2);
			loopD2 += Avx512F.Multiply(h0.AsUInt32(), coefficient);
			loopD3 += Avx512F.Multiply(h1.AsUInt32(), coefficient);
			loopD4 += Avx512F.Multiply(h2.AsUInt32(), coefficient);

			coefficient = BroadcastSixteenth(ref _r3);
			loopD3 += Avx512F.Multiply(h0.AsUInt32(), coefficient);
			loopD4 += Avx512F.Multiply(h1.AsUInt32(), coefficient);

			coefficient = BroadcastSixteenth(ref _r4);
			loopD4 += Avx512F.Multiply(h0.AsUInt32(), coefficient);

			coefficient = BroadcastSixteenth(ref _s1);
			loopD0 += Avx512F.Multiply(h4.AsUInt32(), coefficient);

			coefficient = BroadcastSixteenth(ref _s2);
			loopD0 += Avx512F.Multiply(h3.AsUInt32(), coefficient);
			loopD1 += Avx512F.Multiply(h4.AsUInt32(), coefficient);

			coefficient = BroadcastSixteenth(ref _s3);
			loopD0 += Avx512F.Multiply(h2.AsUInt32(), coefficient);
			loopD1 += Avx512F.Multiply(h3.AsUInt32(), coefficient);
			loopD2 += Avx512F.Multiply(h4.AsUInt32(), coefficient);

			coefficient = BroadcastSixteenth(ref _s4);
			loopD0 += Avx512F.Multiply(h1.AsUInt32(), coefficient);
			loopD1 += Avx512F.Multiply(h2.AsUInt32(), coefficient);
			loopD2 += Avx512F.Multiply(h3.AsUInt32(), coefficient);
			loopD3 += Avx512F.Multiply(h4.AsUInt32(), coefficient);

			LoadEight(ref input, out m0, out m1, out m2, out m3, out m4);
			loopD2 += Avx512F.Multiply(m2.AsUInt32(), r0);
			loopD3 += Avx512F.Multiply(m2.AsUInt32(), r1);
			loopD4 += Avx512F.Multiply(m2.AsUInt32(), r2);
			loopD0 += Avx512F.Multiply(m2.AsUInt32(), s3);
			loopD1 += Avx512F.Multiply(m2.AsUInt32(), s4);

			loopD1 += Avx512F.Multiply(m0.AsUInt32(), r1);
			loopD2 += Avx512F.Multiply(m1.AsUInt32(), r1);
			loopD4 += Avx512F.Multiply(m3.AsUInt32(), r1);
			loopD0 += Avx512F.Multiply(m4.AsUInt32(), s1);
			loopD0 += Avx512F.Multiply(m0.AsUInt32(), r0);
			loopD1 += Avx512F.Multiply(m1.AsUInt32(), r0);
			loopD3 += Avx512F.Multiply(m3.AsUInt32(), r0);
			loopD4 += Avx512F.Multiply(m4.AsUInt32(), r0);
			loopD0 += Avx512F.Multiply(m3.AsUInt32(), s2);
			loopD1 += Avx512F.Multiply(m4.AsUInt32(), s2);
			loopD3 += Avx512F.Multiply(m1.AsUInt32(), r2);
			loopD2 += Avx512F.Multiply(m0.AsUInt32(), r2);
			loopD4 += Avx512F.Multiply(m1.AsUInt32(), r3);
			loopD3 += Avx512F.Multiply(m0.AsUInt32(), r3);
			loopD1 += Avx512F.Multiply(m3.AsUInt32(), s3);
			loopD2 += Avx512F.Multiply(m4.AsUInt32(), s3);
			loopD2 += Avx512F.Multiply(m3.AsUInt32(), s4);
			loopD3 += Avx512F.Multiply(m4.AsUInt32(), s4);
			loopD4 += Avx512F.Multiply(m0.AsUInt32(), r4);
			loopD0 += Avx512F.Multiply(m1.AsUInt32(), s4);

			ref byte secondGroup = ref Unsafe.Add(ref input, BlockSize8);
			LoadEight(ref secondGroup, out m0, out m1, out m2, out m3, out m4);
			loopD0 += m0;
			loopD1 += m1;
			loopD2 += m2;
			loopD3 += m3;
			loopD4 += m4;

			Reduce(loopD0, loopD1, loopD2, loopD3, loopD4, mask, out h0, out h1, out h2, out h3, out h4);

			input = ref Unsafe.Add(ref input, BlockSize8 * 2);
			remaining -= BlockSize8 * 2;
		}

		while (remaining is not 0)
		{
			Vector512<ulong> loopD2 = Avx512F.Multiply(h2.AsUInt32(), r0);
			Vector512<ulong> loopD3 = Avx512F.Multiply(h2.AsUInt32(), r1);
			Vector512<ulong> loopD4 = Avx512F.Multiply(h2.AsUInt32(), r2);
			Vector512<ulong> loopD0 = Avx512F.Multiply(h2.AsUInt32(), s3);
			Vector512<ulong> loopD1 = Avx512F.Multiply(h2.AsUInt32(), s4);

			loopD1 += Avx512F.Multiply(h0.AsUInt32(), r1);
			loopD2 += Avx512F.Multiply(h1.AsUInt32(), r1);
			loopD4 += Avx512F.Multiply(h3.AsUInt32(), r1);
			loopD0 += Avx512F.Multiply(h4.AsUInt32(), s1);
			loopD0 += Avx512F.Multiply(h0.AsUInt32(), r0);
			loopD1 += Avx512F.Multiply(h1.AsUInt32(), r0);
			loopD3 += Avx512F.Multiply(h3.AsUInt32(), r0);
			loopD4 += Avx512F.Multiply(h4.AsUInt32(), r0);
			loopD0 += Avx512F.Multiply(h3.AsUInt32(), s2);
			loopD1 += Avx512F.Multiply(h4.AsUInt32(), s2);
			loopD3 += Avx512F.Multiply(h1.AsUInt32(), r2);
			loopD2 += Avx512F.Multiply(h0.AsUInt32(), r2);
			loopD4 += Avx512F.Multiply(h1.AsUInt32(), r3);
			loopD3 += Avx512F.Multiply(h0.AsUInt32(), r3);
			loopD1 += Avx512F.Multiply(h3.AsUInt32(), s3);
			loopD2 += Avx512F.Multiply(h4.AsUInt32(), s3);
			loopD2 += Avx512F.Multiply(h3.AsUInt32(), s4);
			loopD3 += Avx512F.Multiply(h4.AsUInt32(), s4);
			loopD4 += Avx512F.Multiply(h0.AsUInt32(), r4);
			loopD0 += Avx512F.Multiply(h1.AsUInt32(), s4);

			Reduce(loopD0, loopD1, loopD2, loopD3, loopD4, mask, out h0, out h1, out h2, out h3, out h4);

			LoadEight(ref input, out m0, out m1, out m2, out m3, out m4);
			h0 += m0;
			h1 += m1;
			h2 += m2;
			h3 += m3;
			h4 += m4;
			input = ref Unsafe.Add(ref input, BlockSize8);
			remaining -= BlockSize8;
		}

		SetAccumulatorFromLanes(h0.AsUInt32(), h1.AsUInt32(), h2.AsUInt32(), h3.AsUInt32(), h4.AsUInt32());
	}

	// Multiplies each lane by its remaining power and stores the sum of the lanes as the scalar accumulator.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void SetAccumulatorFromLanes(Vector512<uint> a0, Vector512<uint> a1, Vector512<uint> a2, Vector512<uint> a3, Vector512<uint> a4)
	{
		Vector512<ulong> d2 = Avx512F.Multiply(a2, _r0);
		Vector512<ulong> d3 = Avx512F.Multiply(a2, _r1);
		Vector512<ulong> d4 = Avx512F.Multiply(a2, _r2);
		Vector512<ulong> d0 = Avx512F.Multiply(a2, _s3);
		Vector512<ulong> d1 = Avx512F.Multiply(a2, _s4);

		d1 += Avx512F.Multiply(a0, _r1);
		d2 += Avx512F.Multiply(a1, _r1);
		d4 += Avx512F.Multiply(a3, _r1);
		d0 += Avx512F.Multiply(a4, _s1);
		d0 += Avx512F.Multiply(a0, _r0);
		d1 += Avx512F.Multiply(a1, _r0);
		d3 += Avx512F.Multiply(a3, _r0);
		d4 += Avx512F.Multiply(a4, _r0);
		d0 += Avx512F.Multiply(a3, _s2);
		d1 += Avx512F.Multiply(a4, _s2);
		d3 += Avx512F.Multiply(a1, _r2);
		d2 += Avx512F.Multiply(a0, _r2);
		d4 += Avx512F.Multiply(a1, _r3);
		d3 += Avx512F.Multiply(a0, _r3);
		d1 += Avx512F.Multiply(a3, _s3);
		d2 += Avx512F.Multiply(a4, _s3);
		d2 += Avx512F.Multiply(a3, _s4);
		d3 += Avx512F.Multiply(a4, _s4);
		d4 += Avx512F.Multiply(a0, _r4);
		d0 += Avx512F.Multiply(a1, _s4);

		// Passing the sums straight to the call makes x86 spill more.
		ulong sum0 = Vector512.Sum(d0);
		ulong sum1 = Vector512.Sum(d1);
		ulong sum2 = Vector512.Sum(d2);
		ulong sum3 = Vector512.Sum(d3);
		ulong sum4 = Vector512.Sum(d4);
		_state.SetAccumulator(sum0, sum1, sum2, sum3, sum4);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<uint> ExtractFourPowers(Vector512<uint> powers)
	{
		Vector512<ulong> indices = Vector512.Create(1ul, 3ul, 5ul, 7ul, 0ul, 0ul, 0ul, 0ul);
		return Vector512.Shuffle(powers.AsUInt64(), indices).GetLower().AsUInt32();
	}

	private void AppendFourWayTail(scoped ReadOnlySpan<byte> source)
	{
		Debug.Assert(source.Length >= Poly1305Algorithm.BlockSizeInBytes * 4);
		ref byte input = ref MemoryMarshal.GetReference(source);
		Poly1305Utils.LoadFour(ref input, out Vector256<ulong> m0, out Vector256<ulong> m1, out Vector256<ulong> m2, out Vector256<ulong> m3, out Vector256<ulong> m4);
		Vector256<ulong> h0 = m0 + Vector256.CreateScalar(_state.H0).AsUInt64();
		Vector256<ulong> h1 = m1 + Vector256.CreateScalar(_state.H1).AsUInt64();
		Vector256<ulong> h2 = m2 + Vector256.CreateScalar(_state.H2).AsUInt64();
		Vector256<ulong> h3 = m3 + Vector256.CreateScalar(_state.H3).AsUInt64();
		Vector256<ulong> h4 = m4 + Vector256.CreateScalar(_state.H4).AsUInt64();
		Vector256<uint> r0 = ExtractFourPowers(_r0);
		Vector256<uint> r1 = ExtractFourPowers(_r1);
		Vector256<uint> r2 = ExtractFourPowers(_r2);
		Vector256<uint> r3 = ExtractFourPowers(_r3);
		Vector256<uint> r4 = ExtractFourPowers(_r4);
		Vector256<uint> s1 = ExtractFourPowers(_s1);
		Vector256<uint> s2 = ExtractFourPowers(_s2);
		Vector256<uint> s3 = ExtractFourPowers(_s3);
		Vector256<uint> s4 = ExtractFourPowers(_s4);

		Vector256<ulong> d2 = Avx2.Multiply(h2.AsUInt32(), r0);
		Vector256<ulong> d3 = Avx2.Multiply(h2.AsUInt32(), r1);
		Vector256<ulong> d4 = Avx2.Multiply(h2.AsUInt32(), r2);
		Vector256<ulong> d0 = Avx2.Multiply(h2.AsUInt32(), s3);
		Vector256<ulong> d1 = Avx2.Multiply(h2.AsUInt32(), s4);

		d1 += Avx2.Multiply(h0.AsUInt32(), r1);
		d2 += Avx2.Multiply(h1.AsUInt32(), r1);
		d4 += Avx2.Multiply(h3.AsUInt32(), r1);
		d0 += Avx2.Multiply(h4.AsUInt32(), s1);
		d0 += Avx2.Multiply(h0.AsUInt32(), r0);
		d1 += Avx2.Multiply(h1.AsUInt32(), r0);
		d3 += Avx2.Multiply(h3.AsUInt32(), r0);
		d4 += Avx2.Multiply(h4.AsUInt32(), r0);
		d0 += Avx2.Multiply(h3.AsUInt32(), s2);
		d1 += Avx2.Multiply(h4.AsUInt32(), s2);
		d3 += Avx2.Multiply(h1.AsUInt32(), r2);
		d2 += Avx2.Multiply(h0.AsUInt32(), r2);
		d4 += Avx2.Multiply(h1.AsUInt32(), r3);
		d3 += Avx2.Multiply(h0.AsUInt32(), r3);
		d1 += Avx2.Multiply(h3.AsUInt32(), s3);
		d2 += Avx2.Multiply(h4.AsUInt32(), s3);
		d2 += Avx2.Multiply(h3.AsUInt32(), s4);
		d3 += Avx2.Multiply(h4.AsUInt32(), s4);
		d4 += Avx2.Multiply(h0.AsUInt32(), r4);
		d0 += Avx2.Multiply(h1.AsUInt32(), s4);

		_state.SetAccumulator(Vector256.Sum(d0), Vector256.Sum(d1), Vector256.Sum(d2), Vector256.Sum(d3), Vector256.Sum(d4));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Reduce
	(
		Vector512<ulong> d0, Vector512<ulong> d1, Vector512<ulong> d2, Vector512<ulong> d3, Vector512<ulong> d4,
		Vector512<ulong> mask,
		out Vector512<ulong> h0, out Vector512<ulong> h1, out Vector512<ulong> h2, out Vector512<ulong> h3, out Vector512<ulong> h4
	)
	{
		Vector512<ulong> carry3 = d3 >>> 26;
		h3 = d3 & mask;
		h4 = d4 + carry3;
		Vector512<ulong> carry0 = d0 >>> 26;
		h0 = d0 & mask;
		h1 = d1 + carry0;
		Vector512<ulong> carry4 = h4 >>> 26;
		h4 &= mask;
		Vector512<ulong> carry1 = h1 >>> 26;
		h1 &= mask;
		h2 = d2 + carry1;
		h0 += carry4 + (carry4 << 2);
		Vector512<ulong> carry2 = h2 >>> 26;
		h2 &= mask;
		h3 += carry2;
		carry0 = h0 >>> 26;
		h0 &= mask;
		h1 += carry0;
		carry3 = h3 >>> 26;
		h3 &= mask;
		h4 += carry3;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal readonly void GetEightWayAccumulator(out Vector512<ulong> h0, out Vector512<ulong> h1, out Vector512<ulong> h2, out Vector512<ulong> h3, out Vector512<ulong> h4)
	{
		h0 = Vector512.CreateScalar(_state.H0).AsUInt64();
		h1 = Vector512.CreateScalar(_state.H1).AsUInt64();
		h2 = Vector512.CreateScalar(_state.H2).AsUInt64();
		h3 = Vector512.CreateScalar(_state.H3).AsUInt64();
		h4 = Vector512.CreateScalar(_state.H4).AsUInt64();
	}

	// h = (h + m) * r^8 for one 128-byte group; powers are broadcast from memory to spare registers.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void AppendEightWayGroup(ref Poly1305Avx512 state, ref byte source, ref Vector512<ulong> h0, ref Vector512<ulong> h1, ref Vector512<ulong> h2, ref Vector512<ulong> h3, ref Vector512<ulong> h4)
	{
		LoadEight(ref source, out Vector512<ulong> m0, out Vector512<ulong> m1, out Vector512<ulong> m2, out Vector512<ulong> m3, out Vector512<ulong> m4);
		Vector512<uint> a0 = (h0 + m0).AsUInt32();
		Vector512<uint> a1 = (h1 + m1).AsUInt32();
		Vector512<uint> a2 = (h2 + m2).AsUInt32();
		Vector512<uint> a3 = (h3 + m3).AsUInt32();
		Vector512<uint> a4 = (h4 + m4).AsUInt32();

		// Grouping by coefficient keeps only one broadcast power live at a time.
		Vector512<uint> coefficient = BroadcastEighth(ref state._r0);
		Vector512<ulong> d0 = Avx512F.Multiply(a0, coefficient);
		Vector512<ulong> d1 = Avx512F.Multiply(a1, coefficient);
		Vector512<ulong> d2 = Avx512F.Multiply(a2, coefficient);
		Vector512<ulong> d3 = Avx512F.Multiply(a3, coefficient);
		Vector512<ulong> d4 = Avx512F.Multiply(a4, coefficient);

		coefficient = BroadcastEighth(ref state._r1);
		d1 += Avx512F.Multiply(a0, coefficient);
		d2 += Avx512F.Multiply(a1, coefficient);
		d3 += Avx512F.Multiply(a2, coefficient);
		d4 += Avx512F.Multiply(a3, coefficient);

		coefficient = BroadcastEighth(ref state._r2);
		d2 += Avx512F.Multiply(a0, coefficient);
		d3 += Avx512F.Multiply(a1, coefficient);
		d4 += Avx512F.Multiply(a2, coefficient);

		coefficient = BroadcastEighth(ref state._r3);
		d3 += Avx512F.Multiply(a0, coefficient);
		d4 += Avx512F.Multiply(a1, coefficient);

		d4 += Avx512F.Multiply(a0, BroadcastEighth(ref state._r4));
		d0 += Avx512F.Multiply(a4, BroadcastEighth(ref state._s1));

		coefficient = BroadcastEighth(ref state._s2);
		d0 += Avx512F.Multiply(a3, coefficient);
		d1 += Avx512F.Multiply(a4, coefficient);

		coefficient = BroadcastEighth(ref state._s3);
		d0 += Avx512F.Multiply(a2, coefficient);
		d1 += Avx512F.Multiply(a3, coefficient);
		d2 += Avx512F.Multiply(a4, coefficient);

		coefficient = BroadcastEighth(ref state._s4);
		d0 += Avx512F.Multiply(a1, coefficient);
		d1 += Avx512F.Multiply(a2, coefficient);
		d2 += Avx512F.Multiply(a3, coefficient);
		d3 += Avx512F.Multiply(a4, coefficient);

		// Reduce into locals so the carry chain stays in registers even when the caller's accumulator is spilled.
		Reduce(d0, d1, d2, d3, d4, Vector512.Create((ulong)Poly1305State26.LimbMask), out Vector512<ulong> n0, out Vector512<ulong> n1, out Vector512<ulong> n2, out Vector512<ulong> n3, out Vector512<ulong> n4);
		h0 = n0;
		h1 = n1;
		h2 = n2;
		h3 = n3;
		h4 = n4;
	}

	// Hashes the remaining groups, multiplies each lane of the last one by its remaining power, and stores the sum as the scalar accumulator.
	[MethodImpl(MethodImplOptions.NoInlining)]
	internal void FinishEightWay(ref byte source, int length, Vector512<ulong> h0, Vector512<ulong> h1, Vector512<ulong> h2, Vector512<ulong> h3, Vector512<ulong> h4)
	{
		Debug.Assert(length >= BlockSize8 && length % BlockSize8 is 0);

		for (int offset = 0; offset < length - BlockSize8; offset += BlockSize8)
		{
			AppendEightWayGroup(ref this, ref Unsafe.Add(ref source, offset), ref h0, ref h1, ref h2, ref h3, ref h4);
		}

		LoadEight(ref Unsafe.Add(ref source, length - BlockSize8), out Vector512<ulong> m0, out Vector512<ulong> m1, out Vector512<ulong> m2, out Vector512<ulong> m3, out Vector512<ulong> m4);
		Vector512<uint> a0 = (h0 + m0).AsUInt32();
		Vector512<uint> a1 = (h1 + m1).AsUInt32();
		Vector512<uint> a2 = (h2 + m2).AsUInt32();
		Vector512<uint> a3 = (h3 + m3).AsUInt32();
		Vector512<uint> a4 = (h4 + m4).AsUInt32();
		SetAccumulatorFromLanes(a0, a1, a2, a3, a4);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<uint> BroadcastEighth(ref Vector512<uint> value)
	{
		return Vector512.Create(Unsafe.As<Vector512<uint>, uint>(ref value));
	}

	public void AppendMessage(scoped ReadOnlySpan<byte> source)
	{
		Append(source, false);
	}

	public void AppendPaddedSegment(scoped ReadOnlySpan<byte> source)
	{
		Append(source, true);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private void Append(scoped ReadOnlySpan<byte> source, bool padPartialBlock)
	{
		if (source.Length >= BlockSize8)
		{
			int eightWayLength = source.Length & -BlockSize8;
			ReadOnlySpan<byte> vectorInput = source.Slice(0, eightWayLength);

			if (eightWayLength >= SixteenWayMinimumInputLength)
			{
				EnsureSixteenthPower();
				AppendSixteenWay(vectorInput);
			}
			else
			{
				AppendEightWay(vectorInput);
			}

			source = source.Slice(eightWayLength);
		}

		if (source.Length >= Poly1305Algorithm.BlockSizeInBytes * 4)
		{
			AppendFourWayTail(source);
			source = source.Slice(Poly1305Algorithm.BlockSizeInBytes * 4);
		}

		_state.Append(source, padPartialBlock);
	}

	public void WriteMac(scoped Span<byte> destination)
	{
		_state.WriteMac(destination);
	}
}
