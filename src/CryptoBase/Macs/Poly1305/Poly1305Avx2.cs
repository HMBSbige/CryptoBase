namespace CryptoBase.Macs.Poly1305;

internal ref struct Poly1305Avx2 : IPoly1305State<Poly1305Avx2>
{
	private const int BlockSize4 = Poly1305Algorithm.BlockSizeInBytes * 4;

	public static bool IsSupported => Avx2.IsSupported;

	private Poly1305State26 _state;
	private Vector256<uint> _ruwy0, _ruwy1, _ruwy2, _ruwy3, _ruwy4;
	private Vector256<uint> _svxz1, _svxz2, _svxz3, _svxz4;
	private bool _hasEighthPower;

	private void Initialize(scoped ReadOnlySpan<byte> key)
	{
		Debug.Assert(IsSupported);
		Debug.Assert(key.Length is Poly1305Algorithm.KeyLengthInBytes);

		_state = new Poly1305State26(key);
		_state.GetPowers(out Poly1305Power r1, out Poly1305Power r2, out Poly1305Power r3, out Poly1305Power r4);

		_ruwy0 = VectorCreationUtils.Create4UInt(r4.Limb0, r3.Limb0, r2.Limb0, r1.Limb0);
		_ruwy1 = VectorCreationUtils.Create4UInt(r4.Limb1, r3.Limb1, r2.Limb1, r1.Limb1);
		_ruwy2 = VectorCreationUtils.Create4UInt(r4.Limb2, r3.Limb2, r2.Limb2, r1.Limb2);
		_ruwy3 = VectorCreationUtils.Create4UInt(r4.Limb3, r3.Limb3, r2.Limb3, r1.Limb3);
		_ruwy4 = VectorCreationUtils.Create4UInt(r4.Limb4, r3.Limb4, r2.Limb4, r1.Limb4);
		_svxz1 = _ruwy1 * 5;
		_svxz2 = _ruwy2 * 5;
		_svxz3 = _ruwy3 * 5;
		_svxz4 = _ruwy4 * 5;
		_hasEighthPower = false;
	}

	public static void Initialize(ref Poly1305Avx2 state, scoped ReadOnlySpan<byte> key)
	{
		state.Initialize(key);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<uint> BroadcastFirst(ref Vector256<uint> value)
	{
		return Vector256.Create(Unsafe.As<Vector256<uint>, uint>(ref value));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<uint> BroadcastEighth(ref Vector256<uint> value)
	{
		ref uint first = ref Unsafe.As<Vector256<uint>, uint>(ref value);
		return Vector256.Create(Unsafe.Add(ref first, 1));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void EnsureEighthPower()
	{
		if (_hasEighthPower)
		{
			return;
		}

		Poly1305Power r8 = Poly1305State26.Square(new Poly1305Power(_ruwy0.GetElement(0), _ruwy1.GetElement(0), _ruwy2.GetElement(0), _ruwy3.GetElement(0), _ruwy4.GetElement(0)));
		_ruwy0 = _ruwy0.WithElement(1, r8.Limb0);
		_ruwy1 = _ruwy1.WithElement(1, r8.Limb1);
		_ruwy2 = _ruwy2.WithElement(1, r8.Limb2);
		_ruwy3 = _ruwy3.WithElement(1, r8.Limb3);
		_ruwy4 = _ruwy4.WithElement(1, r8.Limb4);
		_svxz1 = _ruwy1 * 5;
		_svxz2 = _ruwy2 * 5;
		_svxz3 = _ruwy3 * 5;
		_svxz4 = _ruwy4 * 5;
		_hasEighthPower = true;
	}

	private void AppendFourWay(scoped ReadOnlySpan<byte> source)
	{
		int length = source.Length & -BlockSize4;
		ref byte input = ref source.GetReference();
		Vector256<ulong> mask = Vector256.Create((ulong)Poly1305State26.LimbMask);
		Vector256<ulong> h0 = Vector256.CreateScalar((ulong)_state.H0);
		Vector256<ulong> h1 = Vector256.CreateScalar((ulong)_state.H1);
		Vector256<ulong> h2 = Vector256.CreateScalar((ulong)_state.H2);
		Vector256<ulong> h3 = Vector256.CreateScalar((ulong)_state.H3);
		Vector256<ulong> h4 = Vector256.CreateScalar((ulong)_state.H4);
		Poly1305Utils.LoadFour(ref input, out Vector256<ulong> m0, out Vector256<ulong> m1, out Vector256<ulong> m2, out Vector256<ulong> m3, out Vector256<ulong> m4);
		h0 += m0;
		h1 += m1;
		h2 += m2;
		h3 += m3;
		h4 += m4;
		input = ref Unsafe.Add(ref input, BlockSize4);

		int remaining = length - BlockSize4;

		while (_hasEighthPower && remaining >= BlockSize4 * 2)
		{
			Vector256<uint> coefficient = BroadcastEighth(ref _ruwy0);
			Vector256<ulong> loopD0 = Avx2.Multiply(h0.AsUInt32(), coefficient);
			Vector256<ulong> loopD1 = Avx2.Multiply(h1.AsUInt32(), coefficient);
			Vector256<ulong> loopD2 = Avx2.Multiply(h2.AsUInt32(), coefficient);
			Vector256<ulong> loopD3 = Avx2.Multiply(h3.AsUInt32(), coefficient);
			Vector256<ulong> loopD4 = Avx2.Multiply(h4.AsUInt32(), coefficient);

			coefficient = BroadcastEighth(ref _ruwy1);
			loopD1 += Avx2.Multiply(h0.AsUInt32(), coefficient);
			loopD2 += Avx2.Multiply(h1.AsUInt32(), coefficient);
			loopD3 += Avx2.Multiply(h2.AsUInt32(), coefficient);
			loopD4 += Avx2.Multiply(h3.AsUInt32(), coefficient);

			coefficient = BroadcastEighth(ref _ruwy2);
			loopD2 += Avx2.Multiply(h0.AsUInt32(), coefficient);
			loopD3 += Avx2.Multiply(h1.AsUInt32(), coefficient);
			loopD4 += Avx2.Multiply(h2.AsUInt32(), coefficient);

			coefficient = BroadcastEighth(ref _ruwy3);
			loopD3 += Avx2.Multiply(h0.AsUInt32(), coefficient);
			loopD4 += Avx2.Multiply(h1.AsUInt32(), coefficient);

			coefficient = BroadcastEighth(ref _ruwy4);
			loopD4 += Avx2.Multiply(h0.AsUInt32(), coefficient);

			coefficient = BroadcastEighth(ref _svxz1);
			loopD0 += Avx2.Multiply(h4.AsUInt32(), coefficient);

			coefficient = BroadcastEighth(ref _svxz2);
			loopD0 += Avx2.Multiply(h3.AsUInt32(), coefficient);
			loopD1 += Avx2.Multiply(h4.AsUInt32(), coefficient);

			coefficient = BroadcastEighth(ref _svxz3);
			loopD0 += Avx2.Multiply(h2.AsUInt32(), coefficient);
			loopD1 += Avx2.Multiply(h3.AsUInt32(), coefficient);
			loopD2 += Avx2.Multiply(h4.AsUInt32(), coefficient);

			coefficient = BroadcastEighth(ref _svxz4);
			loopD0 += Avx2.Multiply(h1.AsUInt32(), coefficient);
			loopD1 += Avx2.Multiply(h2.AsUInt32(), coefficient);
			loopD2 += Avx2.Multiply(h3.AsUInt32(), coefficient);
			loopD3 += Avx2.Multiply(h4.AsUInt32(), coefficient);

			Poly1305Utils.LoadFour(ref input, out m0, out m1, out m2, out m3, out m4);
			coefficient = BroadcastFirst(ref _ruwy0);
			loopD0 += Avx2.Multiply(m0.AsUInt32(), coefficient);
			loopD1 += Avx2.Multiply(m1.AsUInt32(), coefficient);
			loopD2 += Avx2.Multiply(m2.AsUInt32(), coefficient);
			loopD3 += Avx2.Multiply(m3.AsUInt32(), coefficient);
			loopD4 += Avx2.Multiply(m4.AsUInt32(), coefficient);

			coefficient = BroadcastFirst(ref _ruwy1);
			loopD1 += Avx2.Multiply(m0.AsUInt32(), coefficient);
			loopD2 += Avx2.Multiply(m1.AsUInt32(), coefficient);
			loopD3 += Avx2.Multiply(m2.AsUInt32(), coefficient);
			loopD4 += Avx2.Multiply(m3.AsUInt32(), coefficient);

			coefficient = BroadcastFirst(ref _ruwy2);
			loopD2 += Avx2.Multiply(m0.AsUInt32(), coefficient);
			loopD3 += Avx2.Multiply(m1.AsUInt32(), coefficient);
			loopD4 += Avx2.Multiply(m2.AsUInt32(), coefficient);

			coefficient = BroadcastFirst(ref _ruwy3);
			loopD3 += Avx2.Multiply(m0.AsUInt32(), coefficient);
			loopD4 += Avx2.Multiply(m1.AsUInt32(), coefficient);

			coefficient = BroadcastFirst(ref _ruwy4);
			loopD4 += Avx2.Multiply(m0.AsUInt32(), coefficient);

			coefficient = BroadcastFirst(ref _svxz1);
			loopD0 += Avx2.Multiply(m4.AsUInt32(), coefficient);

			coefficient = BroadcastFirst(ref _svxz2);
			loopD0 += Avx2.Multiply(m3.AsUInt32(), coefficient);
			loopD1 += Avx2.Multiply(m4.AsUInt32(), coefficient);

			coefficient = BroadcastFirst(ref _svxz3);
			loopD0 += Avx2.Multiply(m2.AsUInt32(), coefficient);
			loopD1 += Avx2.Multiply(m3.AsUInt32(), coefficient);
			loopD2 += Avx2.Multiply(m4.AsUInt32(), coefficient);

			coefficient = BroadcastFirst(ref _svxz4);
			loopD0 += Avx2.Multiply(m1.AsUInt32(), coefficient);
			loopD1 += Avx2.Multiply(m2.AsUInt32(), coefficient);
			loopD2 += Avx2.Multiply(m3.AsUInt32(), coefficient);
			loopD3 += Avx2.Multiply(m4.AsUInt32(), coefficient);

			ref byte secondGroup = ref Unsafe.Add(ref input, BlockSize4);
			Poly1305Utils.LoadFour(ref secondGroup, out m0, out m1, out m2, out m3, out m4);
			loopD0 += m0;
			loopD1 += m1;
			loopD2 += m2;
			loopD3 += m3;
			loopD4 += m4;

			Reduce(loopD0, loopD1, loopD2, loopD3, loopD4, mask, out h0, out h1, out h2, out h3, out h4);

			input = ref Unsafe.Add(ref input, BlockSize4 * 2);
			remaining -= BlockSize4 * 2;
		}

		while (remaining is not 0)
		{
			Vector256<uint> coefficient = BroadcastFirst(ref _ruwy0);
			Vector256<ulong> loopD0 = Avx2.Multiply(h0.AsUInt32(), coefficient);
			Vector256<ulong> loopD1 = Avx2.Multiply(h1.AsUInt32(), coefficient);
			Vector256<ulong> loopD2 = Avx2.Multiply(h2.AsUInt32(), coefficient);
			Vector256<ulong> loopD3 = Avx2.Multiply(h3.AsUInt32(), coefficient);
			Vector256<ulong> loopD4 = Avx2.Multiply(h4.AsUInt32(), coefficient);

			coefficient = BroadcastFirst(ref _ruwy1);
			loopD1 += Avx2.Multiply(h0.AsUInt32(), coefficient);
			loopD2 += Avx2.Multiply(h1.AsUInt32(), coefficient);
			loopD3 += Avx2.Multiply(h2.AsUInt32(), coefficient);
			loopD4 += Avx2.Multiply(h3.AsUInt32(), coefficient);

			coefficient = BroadcastFirst(ref _ruwy2);
			loopD2 += Avx2.Multiply(h0.AsUInt32(), coefficient);
			loopD3 += Avx2.Multiply(h1.AsUInt32(), coefficient);
			loopD4 += Avx2.Multiply(h2.AsUInt32(), coefficient);

			coefficient = BroadcastFirst(ref _ruwy3);
			loopD3 += Avx2.Multiply(h0.AsUInt32(), coefficient);
			loopD4 += Avx2.Multiply(h1.AsUInt32(), coefficient);

			coefficient = BroadcastFirst(ref _ruwy4);
			loopD4 += Avx2.Multiply(h0.AsUInt32(), coefficient);

			coefficient = BroadcastFirst(ref _svxz1);
			loopD0 += Avx2.Multiply(h4.AsUInt32(), coefficient);

			coefficient = BroadcastFirst(ref _svxz2);
			loopD0 += Avx2.Multiply(h3.AsUInt32(), coefficient);
			loopD1 += Avx2.Multiply(h4.AsUInt32(), coefficient);

			coefficient = BroadcastFirst(ref _svxz3);
			loopD0 += Avx2.Multiply(h2.AsUInt32(), coefficient);
			loopD1 += Avx2.Multiply(h3.AsUInt32(), coefficient);
			loopD2 += Avx2.Multiply(h4.AsUInt32(), coefficient);

			coefficient = BroadcastFirst(ref _svxz4);
			loopD0 += Avx2.Multiply(h1.AsUInt32(), coefficient);
			loopD1 += Avx2.Multiply(h2.AsUInt32(), coefficient);
			loopD2 += Avx2.Multiply(h3.AsUInt32(), coefficient);
			loopD3 += Avx2.Multiply(h4.AsUInt32(), coefficient);

			Reduce(loopD0, loopD1, loopD2, loopD3, loopD4, mask, out h0, out h1, out h2, out h3, out h4);

			Poly1305Utils.LoadFour(ref input, out m0, out m1, out m2, out m3, out m4);
			h0 += m0;
			h1 += m1;
			h2 += m2;
			h3 += m3;
			h4 += m4;
			input = ref Unsafe.Add(ref input, BlockSize4);
			remaining -= BlockSize4;
		}

		Vector256<ulong> finalD2 = Avx2.Multiply(h2.AsUInt32(), _ruwy0);
		Vector256<ulong> finalD3 = Avx2.Multiply(h2.AsUInt32(), _ruwy1);
		Vector256<ulong> finalD4 = Avx2.Multiply(h2.AsUInt32(), _ruwy2);
		Vector256<ulong> finalD0 = Avx2.Multiply(h2.AsUInt32(), _svxz3);
		Vector256<ulong> finalD1 = Avx2.Multiply(h2.AsUInt32(), _svxz4);

		finalD1 += Avx2.Multiply(h0.AsUInt32(), _ruwy1);
		finalD2 += Avx2.Multiply(h1.AsUInt32(), _ruwy1);
		finalD4 += Avx2.Multiply(h3.AsUInt32(), _ruwy1);
		finalD0 += Avx2.Multiply(h4.AsUInt32(), _svxz1);

		finalD0 += Avx2.Multiply(h0.AsUInt32(), _ruwy0);
		finalD1 += Avx2.Multiply(h1.AsUInt32(), _ruwy0);
		finalD3 += Avx2.Multiply(h3.AsUInt32(), _ruwy0);
		finalD4 += Avx2.Multiply(h4.AsUInt32(), _ruwy0);

		finalD0 += Avx2.Multiply(h3.AsUInt32(), _svxz2);
		finalD1 += Avx2.Multiply(h4.AsUInt32(), _svxz2);
		finalD3 += Avx2.Multiply(h1.AsUInt32(), _ruwy2);
		finalD2 += Avx2.Multiply(h0.AsUInt32(), _ruwy2);

		finalD4 += Avx2.Multiply(h1.AsUInt32(), _ruwy3);
		finalD3 += Avx2.Multiply(h0.AsUInt32(), _ruwy3);
		finalD1 += Avx2.Multiply(h3.AsUInt32(), _svxz3);
		finalD2 += Avx2.Multiply(h4.AsUInt32(), _svxz3);

		finalD2 += Avx2.Multiply(h3.AsUInt32(), _svxz4);
		finalD3 += Avx2.Multiply(h4.AsUInt32(), _svxz4);
		finalD4 += Avx2.Multiply(h0.AsUInt32(), _ruwy4);
		finalD0 += Avx2.Multiply(h1.AsUInt32(), _svxz4);

		_state.SetAccumulator(Vector256.Sum(finalD0), Vector256.Sum(finalD1), Vector256.Sum(finalD2), Vector256.Sum(finalD3), Vector256.Sum(finalD4));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Reduce
	(
		Vector256<ulong> d0, Vector256<ulong> d1, Vector256<ulong> d2, Vector256<ulong> d3, Vector256<ulong> d4,
		Vector256<ulong> mask,
		out Vector256<ulong> h0, out Vector256<ulong> h1, out Vector256<ulong> h2, out Vector256<ulong> h3, out Vector256<ulong> h4
	)
	{
		Vector256<ulong> carry3 = d3 >>> 26;
		h3 = d3 & mask;
		h4 = d4 + carry3;
		Vector256<ulong> carry0 = d0 >>> 26;
		h0 = d0 & mask;
		h1 = d1 + carry0;
		Vector256<ulong> carry4 = h4 >>> 26;
		h4 &= mask;
		Vector256<ulong> carry1 = h1 >>> 26;
		h1 &= mask;
		h2 = d2 + carry1;
		h0 += carry4 + (carry4 << 2);
		Vector256<ulong> carry2 = h2 >>> 26;
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
		if (source.Length >= BlockSize4)
		{
			int fourWayLength = source.Length & -BlockSize4;

			if (fourWayLength >= BlockSize4 * 5)
			{
				EnsureEighthPower();
			}

			AppendFourWay(source.Slice(0, fourWayLength));
			source = source.Slice(fourWayLength);
		}

		_state.Append(source, padPartialBlock);
	}

	public void WriteMac(scoped Span<byte> destination)
	{
		_state.WriteMac(destination);
	}
}
