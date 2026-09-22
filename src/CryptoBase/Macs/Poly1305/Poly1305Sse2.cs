namespace CryptoBase.Macs.Poly1305;

internal ref struct Poly1305Sse2 : IPoly1305State<Poly1305Sse2>
{
	private const int BlockSize2 = Poly1305Algorithm.BlockSizeInBytes * 2;

	public static bool IsSupported => Sse2.IsSupported;

	private Poly1305State26 _state;
	private Vector128<uint> _ru0, _ru1, _ru2, _ru3, _ru4;
	private Vector128<uint> _sv1, _sv2, _sv3, _sv4;
	private bool _hasFourthPower;

	private void Initialize(scoped ReadOnlySpan<byte> key)
	{
		Debug.Assert(IsSupported);
		Debug.Assert(key.Length is Poly1305Algorithm.KeyLengthInBytes);

		_state = new Poly1305State26(key);
		_state.GetPowers(out Poly1305Power r1, out Poly1305Power r2);

		_ru0 = VectorCreationUtils.CreateTwoUInt(r2.Limb0, r1.Limb0);
		_ru1 = VectorCreationUtils.CreateTwoUInt(r2.Limb1, r1.Limb1);
		_ru2 = VectorCreationUtils.CreateTwoUInt(r2.Limb2, r1.Limb2);
		_ru3 = VectorCreationUtils.CreateTwoUInt(r2.Limb3, r1.Limb3);
		_ru4 = VectorCreationUtils.CreateTwoUInt(r2.Limb4, r1.Limb4);
		_sv1 = _ru1 * 5;
		_sv2 = _ru2 * 5;
		_sv3 = _ru3 * 5;
		_sv4 = _ru4 * 5;
		_hasFourthPower = false;
	}

	public static void Initialize(ref Poly1305Sse2 state, scoped ReadOnlySpan<byte> key)
	{
		state.Initialize(key);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> BroadcastFirst(ref Vector128<uint> value)
	{
		if (Avx2.IsSupported)
		{
			return Vector128.Create(Unsafe.As<Vector128<uint>, uint>(ref value));
		}

		return Vector128.Shuffle(value, Vector128<uint>.Zero);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> BroadcastFourth(ref Vector128<uint> value)
	{
		ref uint first = ref Unsafe.As<Vector128<uint>, uint>(ref value);
		return Vector128.Create(Unsafe.Add(ref first, 1));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void EnsureFourthPower()
	{
		if (_hasFourthPower)
		{
			return;
		}

		Poly1305Power r4 = Poly1305State26.Square(new Poly1305Power(_ru0.GetElement(0), _ru1.GetElement(0), _ru2.GetElement(0), _ru3.GetElement(0), _ru4.GetElement(0)));
		_ru0 = _ru0.WithElement(1, r4.Limb0);
		_ru1 = _ru1.WithElement(1, r4.Limb1);
		_ru2 = _ru2.WithElement(1, r4.Limb2);
		_ru3 = _ru3.WithElement(1, r4.Limb3);
		_ru4 = _ru4.WithElement(1, r4.Limb4);
		_sv1 = _ru1 * 5;
		_sv2 = _ru2 * 5;
		_sv3 = _ru3 * 5;
		_sv4 = _ru4 * 5;
		_hasFourthPower = true;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void LoadTwo(ref byte source, out Vector128<ulong> m0, out Vector128<ulong> m1, out Vector128<ulong> m2, out Vector128<ulong> m3, out Vector128<ulong> m4)
	{
		Vector128<ulong> first = Vector128.LoadUnsafe(ref source).AsUInt64();
		Vector128<ulong> second = Vector128.LoadUnsafe(ref source, 16).AsUInt64();
		Vector128<ulong> low = Sse2.UnpackLow(first, second);
		Vector128<ulong> high = Sse2.UnpackHigh(first, second);
		Vector128<ulong> mask = Vector128.Create((ulong)Poly1305State26.LimbMask);

		m0 = low & mask;
		m1 = low >>> 26 & mask;
		m2 = (low >>> 52 | high << 12) & mask;
		m3 = high >>> 14 & mask;
		m4 = high >>> 40 | Vector128.Create((ulong)Poly1305State26.FullBlockHighBit);
	}

	private void AppendTwoWay(scoped ReadOnlySpan<byte> source)
	{
		int length = source.Length & -BlockSize2;
		ref byte input = ref source.GetReference();
		Vector128<ulong> h0 = Vector128.CreateScalar((ulong)_state.H0);
		Vector128<ulong> h1 = Vector128.CreateScalar((ulong)_state.H1);
		Vector128<ulong> h2 = Vector128.CreateScalar((ulong)_state.H2);
		Vector128<ulong> h3 = Vector128.CreateScalar((ulong)_state.H3);
		Vector128<ulong> h4 = Vector128.CreateScalar((ulong)_state.H4);

		LoadTwo(ref input, out Vector128<ulong> m0, out Vector128<ulong> m1, out Vector128<ulong> m2, out Vector128<ulong> m3, out Vector128<ulong> m4);
		h0 += m0;
		h1 += m1;
		h2 += m2;
		h3 += m3;
		h4 += m4;
		input = ref Unsafe.Add(ref input, BlockSize2);
		int remaining = length - BlockSize2;

		while (remaining >= BlockSize2 * 2)
		{
			LoadTwo(ref input, out m0, out m1, out m2, out m3, out m4);
			Vector128<uint> coefficient = BroadcastFirst(ref _ru0);
			Vector128<ulong> d0 = Sse2.Multiply(m0.AsUInt32(), coefficient);
			Vector128<ulong> d1 = Sse2.Multiply(m1.AsUInt32(), coefficient);
			Vector128<ulong> d2 = Sse2.Multiply(m2.AsUInt32(), coefficient);
			Vector128<ulong> d3 = Sse2.Multiply(m3.AsUInt32(), coefficient);
			Vector128<ulong> d4 = Sse2.Multiply(m4.AsUInt32(), coefficient);

			coefficient = BroadcastFirst(ref _ru1);
			d1 += Sse2.Multiply(m0.AsUInt32(), coefficient);
			d2 += Sse2.Multiply(m1.AsUInt32(), coefficient);
			d3 += Sse2.Multiply(m2.AsUInt32(), coefficient);
			d4 += Sse2.Multiply(m3.AsUInt32(), coefficient);

			coefficient = BroadcastFirst(ref _ru2);
			d2 += Sse2.Multiply(m0.AsUInt32(), coefficient);
			d3 += Sse2.Multiply(m1.AsUInt32(), coefficient);
			d4 += Sse2.Multiply(m2.AsUInt32(), coefficient);

			coefficient = BroadcastFirst(ref _ru3);
			d3 += Sse2.Multiply(m0.AsUInt32(), coefficient);
			d4 += Sse2.Multiply(m1.AsUInt32(), coefficient);

			coefficient = BroadcastFirst(ref _ru4);
			d4 += Sse2.Multiply(m0.AsUInt32(), coefficient);

			coefficient = BroadcastFirst(ref _sv1);
			d0 += Sse2.Multiply(m4.AsUInt32(), coefficient);

			coefficient = BroadcastFirst(ref _sv2);
			d0 += Sse2.Multiply(m3.AsUInt32(), coefficient);
			d1 += Sse2.Multiply(m4.AsUInt32(), coefficient);

			coefficient = BroadcastFirst(ref _sv3);
			d0 += Sse2.Multiply(m2.AsUInt32(), coefficient);
			d1 += Sse2.Multiply(m3.AsUInt32(), coefficient);
			d2 += Sse2.Multiply(m4.AsUInt32(), coefficient);

			coefficient = BroadcastFirst(ref _sv4);
			d0 += Sse2.Multiply(m1.AsUInt32(), coefficient);
			d1 += Sse2.Multiply(m2.AsUInt32(), coefficient);
			d2 += Sse2.Multiply(m3.AsUInt32(), coefficient);
			d3 += Sse2.Multiply(m4.AsUInt32(), coefficient);

			coefficient = BroadcastFourth(ref _ru0);
			d0 += Sse2.Multiply(h0.AsUInt32(), coefficient);
			d1 += Sse2.Multiply(h1.AsUInt32(), coefficient);
			d2 += Sse2.Multiply(h2.AsUInt32(), coefficient);
			d3 += Sse2.Multiply(h3.AsUInt32(), coefficient);
			d4 += Sse2.Multiply(h4.AsUInt32(), coefficient);

			coefficient = BroadcastFourth(ref _ru1);
			d1 += Sse2.Multiply(h0.AsUInt32(), coefficient);
			d2 += Sse2.Multiply(h1.AsUInt32(), coefficient);
			d3 += Sse2.Multiply(h2.AsUInt32(), coefficient);
			d4 += Sse2.Multiply(h3.AsUInt32(), coefficient);

			coefficient = BroadcastFourth(ref _ru2);
			d2 += Sse2.Multiply(h0.AsUInt32(), coefficient);
			d3 += Sse2.Multiply(h1.AsUInt32(), coefficient);
			d4 += Sse2.Multiply(h2.AsUInt32(), coefficient);

			coefficient = BroadcastFourth(ref _ru3);
			d3 += Sse2.Multiply(h0.AsUInt32(), coefficient);
			d4 += Sse2.Multiply(h1.AsUInt32(), coefficient);

			coefficient = BroadcastFourth(ref _ru4);
			d4 += Sse2.Multiply(h0.AsUInt32(), coefficient);

			coefficient = BroadcastFourth(ref _sv1);
			d0 += Sse2.Multiply(h4.AsUInt32(), coefficient);

			coefficient = BroadcastFourth(ref _sv2);
			d0 += Sse2.Multiply(h3.AsUInt32(), coefficient);
			d1 += Sse2.Multiply(h4.AsUInt32(), coefficient);

			coefficient = BroadcastFourth(ref _sv3);
			d0 += Sse2.Multiply(h2.AsUInt32(), coefficient);
			d1 += Sse2.Multiply(h3.AsUInt32(), coefficient);
			d2 += Sse2.Multiply(h4.AsUInt32(), coefficient);

			coefficient = BroadcastFourth(ref _sv4);
			d0 += Sse2.Multiply(h1.AsUInt32(), coefficient);
			d1 += Sse2.Multiply(h2.AsUInt32(), coefficient);
			d2 += Sse2.Multiply(h3.AsUInt32(), coefficient);
			d3 += Sse2.Multiply(h4.AsUInt32(), coefficient);

			ref byte secondPair = ref Unsafe.Add(ref input, BlockSize2);
			LoadTwo(ref secondPair, out m0, out m1, out m2, out m3, out m4);
			d0 += m0;
			d1 += m1;
			d2 += m2;
			d3 += m3;
			d4 += m4;

			Vector128<ulong> mask = Vector128.Create((ulong)Poly1305State26.LimbMask);
			Reduce(d0, d1, d2, d3, d4, mask, out h0, out h1, out h2, out h3, out h4);

			input = ref Unsafe.Add(ref input, BlockSize2 * 2);
			remaining -= BlockSize2 * 2;
		}

		if (remaining is not 0)
		{
			Vector128<uint> coefficient = BroadcastFirst(ref _ru0);
			Vector128<ulong> d0 = Sse2.Multiply(h0.AsUInt32(), coefficient);
			Vector128<ulong> d1 = Sse2.Multiply(h1.AsUInt32(), coefficient);
			Vector128<ulong> d2 = Sse2.Multiply(h2.AsUInt32(), coefficient);
			Vector128<ulong> d3 = Sse2.Multiply(h3.AsUInt32(), coefficient);
			Vector128<ulong> d4 = Sse2.Multiply(h4.AsUInt32(), coefficient);

			coefficient = BroadcastFirst(ref _ru1);
			d1 += Sse2.Multiply(h0.AsUInt32(), coefficient);
			d2 += Sse2.Multiply(h1.AsUInt32(), coefficient);
			d3 += Sse2.Multiply(h2.AsUInt32(), coefficient);
			d4 += Sse2.Multiply(h3.AsUInt32(), coefficient);

			coefficient = BroadcastFirst(ref _ru2);
			d2 += Sse2.Multiply(h0.AsUInt32(), coefficient);
			d3 += Sse2.Multiply(h1.AsUInt32(), coefficient);
			d4 += Sse2.Multiply(h2.AsUInt32(), coefficient);

			coefficient = BroadcastFirst(ref _ru3);
			d3 += Sse2.Multiply(h0.AsUInt32(), coefficient);
			d4 += Sse2.Multiply(h1.AsUInt32(), coefficient);

			coefficient = BroadcastFirst(ref _ru4);
			d4 += Sse2.Multiply(h0.AsUInt32(), coefficient);

			coefficient = BroadcastFirst(ref _sv1);
			d0 += Sse2.Multiply(h4.AsUInt32(), coefficient);

			coefficient = BroadcastFirst(ref _sv2);
			d0 += Sse2.Multiply(h3.AsUInt32(), coefficient);
			d1 += Sse2.Multiply(h4.AsUInt32(), coefficient);

			coefficient = BroadcastFirst(ref _sv3);
			d0 += Sse2.Multiply(h2.AsUInt32(), coefficient);
			d1 += Sse2.Multiply(h3.AsUInt32(), coefficient);
			d2 += Sse2.Multiply(h4.AsUInt32(), coefficient);

			coefficient = BroadcastFirst(ref _sv4);
			d0 += Sse2.Multiply(h1.AsUInt32(), coefficient);
			d1 += Sse2.Multiply(h2.AsUInt32(), coefficient);
			d2 += Sse2.Multiply(h3.AsUInt32(), coefficient);
			d3 += Sse2.Multiply(h4.AsUInt32(), coefficient);

			Vector128<ulong> mask = Vector128.Create((ulong)Poly1305State26.LimbMask);
			Reduce(d0, d1, d2, d3, d4, mask, out h0, out h1, out h2, out h3, out h4);

			LoadTwo(ref input, out m0, out m1, out m2, out m3, out m4);
			h0 += m0;
			h1 += m1;
			h2 += m2;
			h3 += m3;
			h4 += m4;
		}

		Vector128<ulong> finalD2 = Sse2.Multiply(h2.AsUInt32(), _ru0);
		Vector128<ulong> finalD3 = Sse2.Multiply(h2.AsUInt32(), _ru1);
		Vector128<ulong> finalD4 = Sse2.Multiply(h2.AsUInt32(), _ru2);
		Vector128<ulong> finalD0 = Sse2.Multiply(h2.AsUInt32(), _sv3);
		Vector128<ulong> finalD1 = Sse2.Multiply(h2.AsUInt32(), _sv4);

		finalD1 += Sse2.Multiply(h0.AsUInt32(), _ru1);
		finalD2 += Sse2.Multiply(h1.AsUInt32(), _ru1);
		finalD4 += Sse2.Multiply(h3.AsUInt32(), _ru1);
		finalD0 += Sse2.Multiply(h4.AsUInt32(), _sv1);
		finalD0 += Sse2.Multiply(h0.AsUInt32(), _ru0);
		finalD1 += Sse2.Multiply(h1.AsUInt32(), _ru0);
		finalD3 += Sse2.Multiply(h3.AsUInt32(), _ru0);
		finalD4 += Sse2.Multiply(h4.AsUInt32(), _ru0);
		finalD0 += Sse2.Multiply(h3.AsUInt32(), _sv2);
		finalD1 += Sse2.Multiply(h4.AsUInt32(), _sv2);
		finalD3 += Sse2.Multiply(h1.AsUInt32(), _ru2);
		finalD2 += Sse2.Multiply(h0.AsUInt32(), _ru2);
		finalD4 += Sse2.Multiply(h1.AsUInt32(), _ru3);
		finalD3 += Sse2.Multiply(h0.AsUInt32(), _ru3);
		finalD1 += Sse2.Multiply(h3.AsUInt32(), _sv3);
		finalD2 += Sse2.Multiply(h4.AsUInt32(), _sv3);
		finalD2 += Sse2.Multiply(h3.AsUInt32(), _sv4);
		finalD3 += Sse2.Multiply(h4.AsUInt32(), _sv4);
		finalD4 += Sse2.Multiply(h0.AsUInt32(), _ru4);
		finalD0 += Sse2.Multiply(h1.AsUInt32(), _sv4);

		ulong sum0 = Vector128.Sum(finalD0);
		ulong sum1 = Vector128.Sum(finalD1);
		ulong sum2 = Vector128.Sum(finalD2);
		ulong sum3 = Vector128.Sum(finalD3);
		ulong sum4 = Vector128.Sum(finalD4);
		_state.SetAccumulator(sum0, sum1, sum2, sum3, sum4);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Reduce
	(
		Vector128<ulong> d0, Vector128<ulong> d1, Vector128<ulong> d2, Vector128<ulong> d3, Vector128<ulong> d4,
		Vector128<ulong> mask,
		out Vector128<ulong> h0, out Vector128<ulong> h1, out Vector128<ulong> h2, out Vector128<ulong> h3, out Vector128<ulong> h4
	)
	{
		Vector128<ulong> carry3 = d3 >>> 26;
		h3 = d3 & mask;
		h4 = d4 + carry3;
		Vector128<ulong> carry0 = d0 >>> 26;
		h0 = d0 & mask;
		h1 = d1 + carry0;
		Vector128<ulong> carry4 = h4 >>> 26;
		h4 &= mask;
		Vector128<ulong> carry1 = h1 >>> 26;
		h1 &= mask;
		h2 = d2 + carry1;
		h0 += carry4 + (carry4 << 2);
		Vector128<ulong> carry2 = h2 >>> 26;
		h2 &= mask;
		h3 += carry2;
		carry0 = h0 >>> 26;
		h0 &= mask;
		h1 += carry0;
		carry3 = h3 >>> 26;
		h3 &= mask;
		h4 += carry3;
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
		if (source.Length >= BlockSize2)
		{
			int twoWayLength = source.Length & -BlockSize2;

			if (twoWayLength >= BlockSize2 * 3)
			{
				EnsureFourthPower();
			}

			AppendTwoWay(source.Slice(0, twoWayLength));
			source = source.Slice(twoWayLength);
		}

		_state.Append(source, padPartialBlock);
	}

	public void WriteMac(scoped Span<byte> destination)
	{
		_state.WriteMac(destination);
	}
}
