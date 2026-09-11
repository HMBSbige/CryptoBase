namespace CryptoBase.Macs.Poly1305;

internal ref struct Poly1305Avx512 : IPoly1305State<Poly1305Avx512>
{
	private const int BlockSize8 = Poly1305Algorithm.BlockSizeInBytes * 8;
	private const int SixteenWayMinimumInputLength = BlockSize8 * 7;

	public static bool IsSupported => Avx512F.IsSupported && Avx2.IsSupported;

	private Poly1305State26 _state;
	private Vector512<uint> _r0, _r1, _r2, _r3, _r4;
	private Vector512<uint> _s1, _s2, _s3, _s4;
	private bool _hasSixteenthPower;

	private void Initialize(scoped ReadOnlySpan<byte> key)
	{
		Debug.Assert(IsSupported);
		Debug.Assert(key.Length is Poly1305Algorithm.KeyLengthInBytes);

		_state = new Poly1305State26(key);
		_state.GetPowers(out Poly1305Power r1, out Poly1305Power r2, out Poly1305Power r3, out Poly1305Power r4);

		Vector256<uint> lower0 = VectorCreationUtils.Create4UInt(r4.Limb0, r3.Limb0, r2.Limb0, r1.Limb0);
		Vector256<uint> lower1 = VectorCreationUtils.Create4UInt(r4.Limb1, r3.Limb1, r2.Limb1, r1.Limb1);
		Vector256<uint> lower2 = VectorCreationUtils.Create4UInt(r4.Limb2, r3.Limb2, r2.Limb2, r1.Limb2);
		Vector256<uint> lower3 = VectorCreationUtils.Create4UInt(r4.Limb3, r3.Limb3, r2.Limb3, r1.Limb3);
		Vector256<uint> lower4 = VectorCreationUtils.Create4UInt(r4.Limb4, r3.Limb4, r2.Limb4, r1.Limb4);
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
		Vector256<ulong> zippedLow = Avx2.UnpackLow(upper.AsUInt64(), lower.AsUInt64());
		Vector256<ulong> zippedHigh = Avx2.UnpackHigh(upper.AsUInt64(), lower.AsUInt64());
		Vector256<ulong> first = Vector256.Create(zippedLow.GetLower(), zippedHigh.GetLower());
		Vector256<ulong> second = Vector256.Create(zippedLow.GetUpper(), zippedHigh.GetUpper());
		return Vector512.Create(first, second).AsUInt32();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void MultiplyFourByPower4
	(
		Vector256<uint> h0, Vector256<uint> h1, Vector256<uint> h2, Vector256<uint> h3, Vector256<uint> h4,
		uint power0, uint power1, uint power2, uint power3, uint power4,
		out Vector256<uint> result0, out Vector256<uint> result1, out Vector256<uint> result2, out Vector256<uint> result3, out Vector256<uint> result4
	)
	{
		Vector256<uint> r0 = Vector256.Create((ulong)power0).AsUInt32();
		Vector256<uint> r1 = Vector256.Create((ulong)power1).AsUInt32();
		Vector256<uint> r2 = Vector256.Create((ulong)power2).AsUInt32();
		Vector256<uint> r3 = Vector256.Create((ulong)power3).AsUInt32();
		Vector256<uint> r4 = Vector256.Create((ulong)power4).AsUInt32();
		Vector256<uint> s1 = Vector256.Create((ulong)(power1 * 5)).AsUInt32();
		Vector256<uint> s2 = Vector256.Create((ulong)(power2 * 5)).AsUInt32();
		Vector256<uint> s3 = Vector256.Create((ulong)(power3 * 5)).AsUInt32();
		Vector256<uint> s4 = Vector256.Create((ulong)(power4 * 5)).AsUInt32();

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
		int length = source.Length & -BlockSize8;
		ref byte input = ref source.GetReference();
		Vector512<ulong> mask = Vector512.Create((ulong)Poly1305State26.LimbMask);
		Vector512<ulong> h0 = Vector512.CreateScalar((ulong)_state.H0);
		Vector512<ulong> h1 = Vector512.CreateScalar((ulong)_state.H1);
		Vector512<ulong> h2 = Vector512.CreateScalar((ulong)_state.H2);
		Vector512<ulong> h3 = Vector512.CreateScalar((ulong)_state.H3);
		Vector512<ulong> h4 = Vector512.CreateScalar((ulong)_state.H4);
		Vector512<uint> r0 = Vector512.Create(_r0.AsUInt64().ToScalar()).AsUInt32();
		Vector512<uint> r1 = Vector512.Create(_r1.AsUInt64().ToScalar()).AsUInt32();
		Vector512<uint> r2 = Vector512.Create(_r2.AsUInt64().ToScalar()).AsUInt32();
		Vector512<uint> r3 = Vector512.Create(_r3.AsUInt64().ToScalar()).AsUInt32();
		Vector512<uint> r4 = Vector512.Create(_r4.AsUInt64().ToScalar()).AsUInt32();
		Vector512<uint> s1 = Vector512.Create(_s1.AsUInt64().ToScalar()).AsUInt32();
		Vector512<uint> s2 = Vector512.Create(_s2.AsUInt64().ToScalar()).AsUInt32();
		Vector512<uint> s3 = Vector512.Create(_s3.AsUInt64().ToScalar()).AsUInt32();
		Vector512<uint> s4 = Vector512.Create(_s4.AsUInt64().ToScalar()).AsUInt32();

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

			Vector512<ulong> carry3 = loopD3 >>> 26;
			h3 = loopD3 & mask;
			h4 = loopD4 + carry3;
			Vector512<ulong> carry0 = loopD0 >>> 26;
			h0 = loopD0 & mask;
			h1 = loopD1 + carry0;
			Vector512<ulong> carry4 = h4 >>> 26;
			h4 &= mask;
			Vector512<ulong> carry1 = h1 >>> 26;
			h1 &= mask;
			h2 = loopD2 + carry1;
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

			input = ref Unsafe.Add(ref input, BlockSize8);
			LoadEight(ref input, out m0, out m1, out m2, out m3, out m4);
			h2 += m2;
			remaining -= BlockSize8;
		}

		h0 += m0;
		h1 += m1;
		h3 += m3;
		h4 += m4;

		Vector512<ulong> finalD2 = Avx512F.Multiply(h2.AsUInt32(), _r0);
		Vector512<ulong> finalD3 = Avx512F.Multiply(h2.AsUInt32(), _r1);
		Vector512<ulong> finalD4 = Avx512F.Multiply(h2.AsUInt32(), _r2);
		Vector512<ulong> finalD0 = Avx512F.Multiply(h2.AsUInt32(), _s3);
		Vector512<ulong> finalD1 = Avx512F.Multiply(h2.AsUInt32(), _s4);

		finalD1 += Avx512F.Multiply(h0.AsUInt32(), _r1);
		finalD2 += Avx512F.Multiply(h1.AsUInt32(), _r1);
		finalD4 += Avx512F.Multiply(h3.AsUInt32(), _r1);
		finalD0 += Avx512F.Multiply(h4.AsUInt32(), _s1);
		finalD0 += Avx512F.Multiply(h0.AsUInt32(), _r0);
		finalD1 += Avx512F.Multiply(h1.AsUInt32(), _r0);
		finalD3 += Avx512F.Multiply(h3.AsUInt32(), _r0);
		finalD4 += Avx512F.Multiply(h4.AsUInt32(), _r0);
		finalD0 += Avx512F.Multiply(h3.AsUInt32(), _s2);
		finalD1 += Avx512F.Multiply(h4.AsUInt32(), _s2);
		finalD3 += Avx512F.Multiply(h1.AsUInt32(), _r2);
		finalD2 += Avx512F.Multiply(h0.AsUInt32(), _r2);
		finalD4 += Avx512F.Multiply(h1.AsUInt32(), _r3);
		finalD3 += Avx512F.Multiply(h0.AsUInt32(), _r3);
		finalD1 += Avx512F.Multiply(h3.AsUInt32(), _s3);
		finalD2 += Avx512F.Multiply(h4.AsUInt32(), _s3);
		finalD2 += Avx512F.Multiply(h3.AsUInt32(), _s4);
		finalD3 += Avx512F.Multiply(h4.AsUInt32(), _s4);
		finalD4 += Avx512F.Multiply(h0.AsUInt32(), _r4);
		finalD0 += Avx512F.Multiply(h1.AsUInt32(), _s4);

		_state.SetAccumulator(Vector512.Sum(finalD0), Vector512.Sum(finalD1), Vector512.Sum(finalD2), Vector512.Sum(finalD3), Vector512.Sum(finalD4));
	}

	private void AppendSixteenWay(scoped ReadOnlySpan<byte> source)
	{
		int length = source.Length & -BlockSize8;
		ref byte input = ref source.GetReference();
		Vector512<ulong> mask = Vector512.Create((ulong)Poly1305State26.LimbMask);
		Vector512<ulong> h0 = Vector512.CreateScalar((ulong)_state.H0);
		Vector512<ulong> h1 = Vector512.CreateScalar((ulong)_state.H1);
		Vector512<ulong> h2 = Vector512.CreateScalar((ulong)_state.H2);
		Vector512<ulong> h3 = Vector512.CreateScalar((ulong)_state.H3);
		Vector512<ulong> h4 = Vector512.CreateScalar((ulong)_state.H4);
		Vector512<uint> r0 = Vector512.Create(_r0.AsUInt64().ToScalar()).AsUInt32();
		Vector512<uint> r1 = Vector512.Create(_r1.AsUInt64().ToScalar()).AsUInt32();
		Vector512<uint> r2 = Vector512.Create(_r2.AsUInt64().ToScalar()).AsUInt32();
		Vector512<uint> r3 = Vector512.Create(_r3.AsUInt64().ToScalar()).AsUInt32();
		Vector512<uint> r4 = Vector512.Create(_r4.AsUInt64().ToScalar()).AsUInt32();
		Vector512<uint> s1 = Vector512.Create(_s1.AsUInt64().ToScalar()).AsUInt32();
		Vector512<uint> s2 = Vector512.Create(_s2.AsUInt64().ToScalar()).AsUInt32();
		Vector512<uint> s3 = Vector512.Create(_s3.AsUInt64().ToScalar()).AsUInt32();
		Vector512<uint> s4 = Vector512.Create(_s4.AsUInt64().ToScalar()).AsUInt32();

		LoadEight(ref input, out Vector512<ulong> m0, out Vector512<ulong> m1, out Vector512<ulong> m2, out Vector512<ulong> m3, out Vector512<ulong> m4);
		h0 += m0;
		h1 += m1;
		h2 += m2;
		h3 += m3;
		h4 += m4;
		input = ref Unsafe.Add(ref input, BlockSize8);
		int remaining = length - BlockSize8;

		while (_hasSixteenthPower && remaining >= BlockSize8 * 2)
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

			Vector512<ulong> carry3 = loopD3 >>> 26;
			h3 = loopD3 & mask;
			h4 = loopD4 + carry3;
			Vector512<ulong> carry0 = loopD0 >>> 26;
			h0 = loopD0 & mask;
			h1 = loopD1 + carry0;
			Vector512<ulong> carry4 = h4 >>> 26;
			h4 &= mask;
			Vector512<ulong> carry1 = h1 >>> 26;
			h1 &= mask;
			h2 = loopD2 + carry1;
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

			Vector512<ulong> carry3 = loopD3 >>> 26;
			h3 = loopD3 & mask;
			h4 = loopD4 + carry3;
			Vector512<ulong> carry0 = loopD0 >>> 26;
			h0 = loopD0 & mask;
			h1 = loopD1 + carry0;
			Vector512<ulong> carry4 = h4 >>> 26;
			h4 &= mask;
			Vector512<ulong> carry1 = h1 >>> 26;
			h1 &= mask;
			h2 = loopD2 + carry1;
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

			LoadEight(ref input, out m0, out m1, out m2, out m3, out m4);
			h0 += m0;
			h1 += m1;
			h2 += m2;
			h3 += m3;
			h4 += m4;
			input = ref Unsafe.Add(ref input, BlockSize8);
			remaining -= BlockSize8;
		}

		Vector512<ulong> finalD2 = Avx512F.Multiply(h2.AsUInt32(), _r0);
		Vector512<ulong> finalD3 = Avx512F.Multiply(h2.AsUInt32(), _r1);
		Vector512<ulong> finalD4 = Avx512F.Multiply(h2.AsUInt32(), _r2);
		Vector512<ulong> finalD0 = Avx512F.Multiply(h2.AsUInt32(), _s3);
		Vector512<ulong> finalD1 = Avx512F.Multiply(h2.AsUInt32(), _s4);

		finalD1 += Avx512F.Multiply(h0.AsUInt32(), _r1);
		finalD2 += Avx512F.Multiply(h1.AsUInt32(), _r1);
		finalD4 += Avx512F.Multiply(h3.AsUInt32(), _r1);
		finalD0 += Avx512F.Multiply(h4.AsUInt32(), _s1);
		finalD0 += Avx512F.Multiply(h0.AsUInt32(), _r0);
		finalD1 += Avx512F.Multiply(h1.AsUInt32(), _r0);
		finalD3 += Avx512F.Multiply(h3.AsUInt32(), _r0);
		finalD4 += Avx512F.Multiply(h4.AsUInt32(), _r0);
		finalD0 += Avx512F.Multiply(h3.AsUInt32(), _s2);
		finalD1 += Avx512F.Multiply(h4.AsUInt32(), _s2);
		finalD3 += Avx512F.Multiply(h1.AsUInt32(), _r2);
		finalD2 += Avx512F.Multiply(h0.AsUInt32(), _r2);
		finalD4 += Avx512F.Multiply(h1.AsUInt32(), _r3);
		finalD3 += Avx512F.Multiply(h0.AsUInt32(), _r3);
		finalD1 += Avx512F.Multiply(h3.AsUInt32(), _s3);
		finalD2 += Avx512F.Multiply(h4.AsUInt32(), _s3);
		finalD2 += Avx512F.Multiply(h3.AsUInt32(), _s4);
		finalD3 += Avx512F.Multiply(h4.AsUInt32(), _s4);
		finalD4 += Avx512F.Multiply(h0.AsUInt32(), _r4);
		finalD0 += Avx512F.Multiply(h1.AsUInt32(), _s4);

		ulong d0 = Vector512.Sum(finalD0);
		ulong d1 = Vector512.Sum(finalD1);
		ulong d2 = Vector512.Sum(finalD2);
		ulong d3 = Vector512.Sum(finalD3);
		ulong d4 = Vector512.Sum(finalD4);
		_state.SetAccumulator(d0, d1, d2, d3, d4);
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
		ref byte input = ref source.GetReference();
		Poly1305Utils.LoadFour(ref input, out Vector256<ulong> m0, out Vector256<ulong> m1, out Vector256<ulong> m2, out Vector256<ulong> m3, out Vector256<ulong> m4);
		Vector256<ulong> h0 = m0 + Vector256.CreateScalar((ulong)_state.H0);
		Vector256<ulong> h1 = m1 + Vector256.CreateScalar((ulong)_state.H1);
		Vector256<ulong> h2 = m2 + Vector256.CreateScalar((ulong)_state.H2);
		Vector256<ulong> h3 = m3 + Vector256.CreateScalar((ulong)_state.H3);
		Vector256<ulong> h4 = m4 + Vector256.CreateScalar((ulong)_state.H4);
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

	public void AppendMessage(scoped ReadOnlySpan<byte> source)
	{
		Append(source, false);
	}

	public void AppendPaddedSegment(scoped ReadOnlySpan<byte> source)
	{
		Append(source, true);
	}

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
