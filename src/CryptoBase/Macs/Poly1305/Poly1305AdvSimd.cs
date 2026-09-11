namespace CryptoBase.Macs.Poly1305;

internal ref struct Poly1305AdvSimd : IPoly1305State<Poly1305AdvSimd>
{
	private const int BlockSize2 = Poly1305Algorithm.BlockSizeInBytes * 2;
	private const int BlockSize4 = Poly1305Algorithm.BlockSizeInBytes * 4;

	public static bool IsSupported => AdvSimd.Arm64.IsSupported;

	private Poly1305State26 _state;
	private Vector128<uint> _r0, _r1, _r2, _r3, _r4;
	private Vector128<uint> _s1, _s2, _s3, _s4;

	private void Initialize(scoped ReadOnlySpan<byte> key)
	{
		Debug.Assert(IsSupported);
		Debug.Assert(key.Length is Poly1305Algorithm.KeyLengthInBytes);

		_state = new Poly1305State26(key);
		_state.GetPowers(out Poly1305Power r1, out Poly1305Power r2);
		GetThirdAndFourthPowers(in r1, in r2, out Poly1305Power r3, out Poly1305Power r4);

		_r0 = Vector128.Create(r4.Limb0, r3.Limb0, r2.Limb0, r1.Limb0);
		_r1 = Vector128.Create(r4.Limb1, r3.Limb1, r2.Limb1, r1.Limb1);
		_r2 = Vector128.Create(r4.Limb2, r3.Limb2, r2.Limb2, r1.Limb2);
		_r3 = Vector128.Create(r4.Limb3, r3.Limb3, r2.Limb3, r1.Limb3);
		_r4 = Vector128.Create(r4.Limb4, r3.Limb4, r2.Limb4, r1.Limb4);
		_s1 = _r1 * 5;
		_s2 = _r2 * 5;
		_s3 = _r3 * 5;
		_s4 = _r4 * 5;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void GetThirdAndFourthPowers(in Poly1305Power r1, in Poly1305Power r2, out Poly1305Power r3, out Poly1305Power r4)
	{
		Vector64<uint> h0 = Vector64.Create(r2.Limb0);
		Vector64<uint> h1 = Vector64.Create(r2.Limb1);
		Vector64<uint> h2 = Vector64.Create(r2.Limb2);
		Vector64<uint> h3 = Vector64.Create(r2.Limb3);
		Vector64<uint> h4 = Vector64.Create(r2.Limb4);
		Vector64<uint> coefficient0 = Vector64.Create(r1.Limb0, r2.Limb0);
		Vector64<uint> coefficient1 = Vector64.Create(r1.Limb1, r2.Limb1);
		Vector64<uint> coefficient2 = Vector64.Create(r1.Limb2, r2.Limb2);
		Vector64<uint> coefficient3 = Vector64.Create(r1.Limb3, r2.Limb3);
		Vector64<uint> coefficient4 = Vector64.Create(r1.Limb4, r2.Limb4);
		Vector64<uint> coefficient1x5 = coefficient1 * 5;
		Vector64<uint> coefficient2x5 = coefficient2 * 5;
		Vector64<uint> coefficient3x5 = coefficient3 * 5;
		Vector64<uint> coefficient4x5 = coefficient4 * 5;

		Vector128<ulong> d2 = AdvSimd.MultiplyWideningLower(h2, coefficient0);
		Vector128<ulong> d3 = AdvSimd.MultiplyWideningLower(h2, coefficient1);
		Vector128<ulong> d4 = AdvSimd.MultiplyWideningLower(h2, coefficient2);
		Vector128<ulong> d0 = AdvSimd.MultiplyWideningLower(h2, coefficient3x5);
		Vector128<ulong> d1 = AdvSimd.MultiplyWideningLower(h2, coefficient4x5);
		d1 = AdvSimd.MultiplyWideningLowerAndAdd(d1, h0, coefficient1);
		d2 = AdvSimd.MultiplyWideningLowerAndAdd(d2, h1, coefficient1);
		d4 = AdvSimd.MultiplyWideningLowerAndAdd(d4, h3, coefficient1);
		d0 = AdvSimd.MultiplyWideningLowerAndAdd(d0, h4, coefficient1x5);
		d0 = AdvSimd.MultiplyWideningLowerAndAdd(d0, h0, coefficient0);
		d1 = AdvSimd.MultiplyWideningLowerAndAdd(d1, h1, coefficient0);
		d3 = AdvSimd.MultiplyWideningLowerAndAdd(d3, h3, coefficient0);
		d4 = AdvSimd.MultiplyWideningLowerAndAdd(d4, h4, coefficient0);
		d0 = AdvSimd.MultiplyWideningLowerAndAdd(d0, h3, coefficient2x5);
		d1 = AdvSimd.MultiplyWideningLowerAndAdd(d1, h4, coefficient2x5);
		d3 = AdvSimd.MultiplyWideningLowerAndAdd(d3, h1, coefficient2);
		d2 = AdvSimd.MultiplyWideningLowerAndAdd(d2, h0, coefficient2);
		d4 = AdvSimd.MultiplyWideningLowerAndAdd(d4, h1, coefficient3);
		d3 = AdvSimd.MultiplyWideningLowerAndAdd(d3, h0, coefficient3);
		d1 = AdvSimd.MultiplyWideningLowerAndAdd(d1, h3, coefficient3x5);
		d2 = AdvSimd.MultiplyWideningLowerAndAdd(d2, h4, coefficient3x5);
		d2 = AdvSimd.MultiplyWideningLowerAndAdd(d2, h3, coefficient4x5);
		d3 = AdvSimd.MultiplyWideningLowerAndAdd(d3, h4, coefficient4x5);
		d4 = AdvSimd.MultiplyWideningLowerAndAdd(d4, h0, coefficient4);
		d0 = AdvSimd.MultiplyWideningLowerAndAdd(d0, h1, coefficient4x5);

		ReduceHalf(d0, d1, d2, d3, d4, out Vector128<ulong> p0, out Vector128<ulong> p1, out Vector128<ulong> p2, out Vector128<ulong> p3, out Vector128<ulong> p4);
		Vector64<uint> limb0 = Vector64.Narrow(p0.GetLower(), p0.GetUpper());
		Vector64<uint> limb1 = Vector64.Narrow(p1.GetLower(), p1.GetUpper());
		Vector64<uint> limb2 = Vector64.Narrow(p2.GetLower(), p2.GetUpper());
		Vector64<uint> limb3 = Vector64.Narrow(p3.GetLower(), p3.GetUpper());
		Vector64<uint> limb4 = Vector64.Narrow(p4.GetLower(), p4.GetUpper());
		r3 = new Poly1305Power(limb0.GetElement(0), limb1.GetElement(0), limb2.GetElement(0), limb3.GetElement(0), limb4.GetElement(0));
		r4 = new Poly1305Power(limb0.GetElement(1), limb1.GetElement(1), limb2.GetElement(1), limb3.GetElement(1), limb4.GetElement(1));
	}

	public static void Initialize(ref Poly1305AdvSimd state, scoped ReadOnlySpan<byte> key)
	{
		state.Initialize(key);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> NarrowUpper(Vector128<ulong> value, uint accumulator)
	{
		return Vector128.Narrow(Vector128<ulong>.Zero, value + Vector128.CreateScalar((ulong)accumulator));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private readonly void LoadTwo
	(
		ref byte source, int secondLength, bool padPartialBlock,
		out Vector128<uint> m0, out Vector128<uint> m1, out Vector128<uint> m2, out Vector128<uint> m3, out Vector128<uint> m4
	)
	{
		Vector128<ulong> block0 = Vector128.LoadUnsafe(ref source).AsUInt64();
		Vector128<ulong> block1;
		Vector128<ulong> highBits;

		if (secondLength is Poly1305Algorithm.BlockSizeInBytes)
		{
			block1 = Vector128.LoadUnsafe(ref source, Poly1305Algorithm.BlockSizeInBytes).AsUInt64();
			highBits = Vector128.Create((ulong)Poly1305State26.FullBlockHighBit);
		}
		else
		{
			ref byte partial = ref Unsafe.Add(ref source, Poly1305Algorithm.BlockSizeInBytes);
			Poly1305Utils.LoadPartialBlock(MemoryMarshal.CreateReadOnlySpan(ref partial, secondLength), out ulong low, out ulong high);
			uint highBit;

			if (padPartialBlock)
			{
				highBit = Poly1305State26.FullBlockHighBit;
			}
			else
			{
				highBit = 0;

				if (secondLength < sizeof(ulong))
				{
					low |= 1UL << secondLength * 8;
				}
				else
				{
					high |= 1UL << (secondLength - sizeof(ulong)) * 8;
				}
			}

			block1 = Vector128.Create(low, high);
			highBits = Vector128.Create((ulong)Poly1305State26.FullBlockHighBit, highBit);
		}

		Vector128<ulong> lower = AdvSimd.Arm64.ZipLow(block0, block1);
		Vector128<ulong> upper = AdvSimd.Arm64.ZipHigh(block0, block1);
		Vector128<ulong> mask = Vector128.Create((ulong)Poly1305State26.LimbMask);

		m0 = NarrowUpper(lower & mask, _state.H0);
		m1 = NarrowUpper(lower >>> 26 & mask, _state.H1);
		m2 = NarrowUpper((lower >>> 52 | upper << 12) & mask, _state.H2);
		m3 = NarrowUpper(upper >>> 14 & mask, _state.H3);
		m4 = NarrowUpper(upper >>> 40 | highBits, _state.H4);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void LoadFour(ref byte source, out Vector128<uint> m0, out Vector128<uint> m1, out Vector128<uint> m2, out Vector128<uint> m3, out Vector128<uint> m4)
	{
		Vector128<ulong> block0 = Vector128.LoadUnsafe(ref source).AsUInt64();
		Vector128<ulong> block1 = Vector128.LoadUnsafe(ref source, 16).AsUInt64();
		Vector128<ulong> block2 = Vector128.LoadUnsafe(ref source, 32).AsUInt64();
		Vector128<ulong> block3 = Vector128.LoadUnsafe(ref source, 48).AsUInt64();
		Vector128<ulong> lower01 = AdvSimd.Arm64.ZipLow(block0, block1);
		Vector128<ulong> lower23 = AdvSimd.Arm64.ZipLow(block2, block3);
		Vector128<ulong> upper01 = AdvSimd.Arm64.ZipHigh(block0, block1);
		Vector128<ulong> upper23 = AdvSimd.Arm64.ZipHigh(block2, block3);
		Vector128<ulong> mask = Vector128.Create((ulong)Poly1305State26.LimbMask);

		m0 = Vector128.Narrow(lower01 & mask, lower23 & mask);
		m1 = Vector128.Narrow(lower01 >>> 26 & mask, lower23 >>> 26 & mask);
		m2 = Vector128.Narrow((lower01 >>> 52 | upper01 << 12) & mask, (lower23 >>> 52 | upper23 << 12) & mask);
		m3 = Vector128.Narrow(upper01 >>> 14 & mask, upper23 >>> 14 & mask);
		m4 = Vector128.Narrow(upper01 >>> 40 | Vector128.Create((ulong)Poly1305State26.FullBlockHighBit), upper23 >>> 40 | Vector128.Create((ulong)Poly1305State26.FullBlockHighBit));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Multiply(Vector128<uint> left, Vector128<uint> right, out Vector128<ulong> lower, out Vector128<ulong> upper)
	{
		lower = AdvSimd.MultiplyWideningLower(left.GetLower(), right.GetLower());
		upper = AdvSimd.MultiplyWideningUpper(left, right);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void MultiplyAdd(ref Vector128<ulong> lower, ref Vector128<ulong> upper, Vector128<uint> left, Vector128<uint> right)
	{
		lower = AdvSimd.MultiplyWideningLowerAndAdd(lower, left.GetLower(), right.GetLower());
		upper = AdvSimd.MultiplyWideningUpperAndAdd(upper, left, right);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ulong> MultiplyUpper(Vector128<uint> left, Vector128<uint> right)
	{
		return AdvSimd.MultiplyWideningUpper(left, right);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void MultiplyAddUpper(ref Vector128<ulong> accumulator, Vector128<uint> left, Vector128<uint> right)
	{
		accumulator = AdvSimd.MultiplyWideningUpperAndAdd(accumulator, left, right);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ReduceHalf
	(
		Vector128<ulong> d0, Vector128<ulong> d1, Vector128<ulong> d2, Vector128<ulong> d3, Vector128<ulong> d4,
		out Vector128<ulong> h0, out Vector128<ulong> h1, out Vector128<ulong> h2, out Vector128<ulong> h3, out Vector128<ulong> h4
	)
	{
		Vector128<ulong> mask = Vector128.Create((ulong)Poly1305State26.LimbMask);
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

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Reduce
	(
		Vector128<ulong> d0Lower, Vector128<ulong> d0Upper,
		Vector128<ulong> d1Lower, Vector128<ulong> d1Upper,
		Vector128<ulong> d2Lower, Vector128<ulong> d2Upper,
		Vector128<ulong> d3Lower, Vector128<ulong> d3Upper,
		Vector128<ulong> d4Lower, Vector128<ulong> d4Upper,
		out Vector128<uint> h0, out Vector128<uint> h1, out Vector128<uint> h2, out Vector128<uint> h3, out Vector128<uint> h4
	)
	{
		ReduceHalf(d0Lower, d1Lower, d2Lower, d3Lower, d4Lower, out Vector128<ulong> h0Lower, out Vector128<ulong> h1Lower, out Vector128<ulong> h2Lower, out Vector128<ulong> h3Lower, out Vector128<ulong> h4Lower);
		ReduceHalf(d0Upper, d1Upper, d2Upper, d3Upper, d4Upper, out Vector128<ulong> h0Upper, out Vector128<ulong> h1Upper, out Vector128<ulong> h2Upper, out Vector128<ulong> h3Upper, out Vector128<ulong> h4Upper);
		h0 = Vector128.Narrow(h0Lower, h0Upper);
		h1 = Vector128.Narrow(h1Lower, h1Upper);
		h2 = Vector128.Narrow(h2Lower, h2Upper);
		h3 = Vector128.Narrow(h3Lower, h3Upper);
		h4 = Vector128.Narrow(h4Lower, h4Upper);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Multiply
	(
		Vector128<uint> h0, Vector128<uint> h1, Vector128<uint> h2, Vector128<uint> h3, Vector128<uint> h4,
		Vector128<uint> r0, Vector128<uint> r1, Vector128<uint> r2, Vector128<uint> r3, Vector128<uint> r4,
		Vector128<uint> s1, Vector128<uint> s2, Vector128<uint> s3, Vector128<uint> s4,
		out Vector128<ulong> d0Lower, out Vector128<ulong> d0Upper,
		out Vector128<ulong> d1Lower, out Vector128<ulong> d1Upper,
		out Vector128<ulong> d2Lower, out Vector128<ulong> d2Upper,
		out Vector128<ulong> d3Lower, out Vector128<ulong> d3Upper,
		out Vector128<ulong> d4Lower, out Vector128<ulong> d4Upper
	)
	{
		Multiply(h2, r0, out d2Lower, out d2Upper);
		Multiply(h2, r1, out d3Lower, out d3Upper);
		Multiply(h2, r2, out d4Lower, out d4Upper);
		Multiply(h2, s3, out d0Lower, out d0Upper);
		Multiply(h2, s4, out d1Lower, out d1Upper);
		MultiplyAdd(ref d1Lower, ref d1Upper, h0, r1);
		MultiplyAdd(ref d2Lower, ref d2Upper, h1, r1);
		MultiplyAdd(ref d4Lower, ref d4Upper, h3, r1);
		MultiplyAdd(ref d0Lower, ref d0Upper, h4, s1);
		MultiplyAdd(ref d0Lower, ref d0Upper, h0, r0);
		MultiplyAdd(ref d1Lower, ref d1Upper, h1, r0);
		MultiplyAdd(ref d3Lower, ref d3Upper, h3, r0);
		MultiplyAdd(ref d4Lower, ref d4Upper, h4, r0);
		MultiplyAdd(ref d0Lower, ref d0Upper, h3, s2);
		MultiplyAdd(ref d1Lower, ref d1Upper, h4, s2);
		MultiplyAdd(ref d3Lower, ref d3Upper, h1, r2);
		MultiplyAdd(ref d2Lower, ref d2Upper, h0, r2);
		MultiplyAdd(ref d4Lower, ref d4Upper, h1, r3);
		MultiplyAdd(ref d3Lower, ref d3Upper, h0, r3);
		MultiplyAdd(ref d1Lower, ref d1Upper, h3, s3);
		MultiplyAdd(ref d2Lower, ref d2Upper, h4, s3);
		MultiplyAdd(ref d2Lower, ref d2Upper, h3, s4);
		MultiplyAdd(ref d3Lower, ref d3Upper, h4, s4);
		MultiplyAdd(ref d4Lower, ref d4Upper, h0, r4);
		MultiplyAdd(ref d0Lower, ref d0Upper, h1, s4);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void MultiplyBroadcast
	(
		Vector128<uint> h0, Vector128<uint> h1, Vector128<uint> h2, Vector128<uint> h3, Vector128<uint> h4,
		in Poly1305Power power,
		out Vector128<ulong> d0Lower, out Vector128<ulong> d0Upper,
		out Vector128<ulong> d1Lower, out Vector128<ulong> d1Upper,
		out Vector128<ulong> d2Lower, out Vector128<ulong> d2Upper,
		out Vector128<ulong> d3Lower, out Vector128<ulong> d3Upper,
		out Vector128<ulong> d4Lower, out Vector128<ulong> d4Upper
	)
	{
		Vector128<uint> coefficient = Vector128.Create(power.Limb0);
		Multiply(h0, coefficient, out d0Lower, out d0Upper);
		Multiply(h1, coefficient, out d1Lower, out d1Upper);
		Multiply(h2, coefficient, out d2Lower, out d2Upper);
		Multiply(h3, coefficient, out d3Lower, out d3Upper);
		Multiply(h4, coefficient, out d4Lower, out d4Upper);

		coefficient = Vector128.Create(power.Limb1);
		MultiplyAdd(ref d1Lower, ref d1Upper, h0, coefficient);
		MultiplyAdd(ref d2Lower, ref d2Upper, h1, coefficient);
		MultiplyAdd(ref d3Lower, ref d3Upper, h2, coefficient);
		MultiplyAdd(ref d4Lower, ref d4Upper, h3, coefficient);

		coefficient = Vector128.Create(power.Limb2);
		MultiplyAdd(ref d2Lower, ref d2Upper, h0, coefficient);
		MultiplyAdd(ref d3Lower, ref d3Upper, h1, coefficient);
		MultiplyAdd(ref d4Lower, ref d4Upper, h2, coefficient);

		coefficient = Vector128.Create(power.Limb3);
		MultiplyAdd(ref d3Lower, ref d3Upper, h0, coefficient);
		MultiplyAdd(ref d4Lower, ref d4Upper, h1, coefficient);

		coefficient = Vector128.Create(power.Limb4);
		MultiplyAdd(ref d4Lower, ref d4Upper, h0, coefficient);

		coefficient = Vector128.Create(power.Limb1 * 5);
		MultiplyAdd(ref d0Lower, ref d0Upper, h4, coefficient);

		coefficient = Vector128.Create(power.Limb2 * 5);
		MultiplyAdd(ref d0Lower, ref d0Upper, h3, coefficient);
		MultiplyAdd(ref d1Lower, ref d1Upper, h4, coefficient);

		coefficient = Vector128.Create(power.Limb3 * 5);
		MultiplyAdd(ref d0Lower, ref d0Upper, h2, coefficient);
		MultiplyAdd(ref d1Lower, ref d1Upper, h3, coefficient);
		MultiplyAdd(ref d2Lower, ref d2Upper, h4, coefficient);

		coefficient = Vector128.Create(power.Limb4 * 5);
		MultiplyAdd(ref d0Lower, ref d0Upper, h1, coefficient);
		MultiplyAdd(ref d1Lower, ref d1Upper, h2, coefficient);
		MultiplyAdd(ref d2Lower, ref d2Upper, h3, coefficient);
		MultiplyAdd(ref d3Lower, ref d3Upper, h4, coefficient);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void MultiplyAddBroadcast
	(
		ref Vector128<ulong> d0Lower, ref Vector128<ulong> d0Upper,
		ref Vector128<ulong> d1Lower, ref Vector128<ulong> d1Upper,
		ref Vector128<ulong> d2Lower, ref Vector128<ulong> d2Upper,
		ref Vector128<ulong> d3Lower, ref Vector128<ulong> d3Upper,
		ref Vector128<ulong> d4Lower, ref Vector128<ulong> d4Upper,
		Vector128<uint> h0, Vector128<uint> h1, Vector128<uint> h2, Vector128<uint> h3, Vector128<uint> h4,
		in Poly1305Power power
	)
	{
		Vector128<uint> coefficient = Vector128.Create(power.Limb0);
		MultiplyAdd(ref d0Lower, ref d0Upper, h0, coefficient);
		MultiplyAdd(ref d1Lower, ref d1Upper, h1, coefficient);
		MultiplyAdd(ref d2Lower, ref d2Upper, h2, coefficient);
		MultiplyAdd(ref d3Lower, ref d3Upper, h3, coefficient);
		MultiplyAdd(ref d4Lower, ref d4Upper, h4, coefficient);

		coefficient = Vector128.Create(power.Limb1);
		MultiplyAdd(ref d1Lower, ref d1Upper, h0, coefficient);
		MultiplyAdd(ref d2Lower, ref d2Upper, h1, coefficient);
		MultiplyAdd(ref d3Lower, ref d3Upper, h2, coefficient);
		MultiplyAdd(ref d4Lower, ref d4Upper, h3, coefficient);

		coefficient = Vector128.Create(power.Limb2);
		MultiplyAdd(ref d2Lower, ref d2Upper, h0, coefficient);
		MultiplyAdd(ref d3Lower, ref d3Upper, h1, coefficient);
		MultiplyAdd(ref d4Lower, ref d4Upper, h2, coefficient);

		coefficient = Vector128.Create(power.Limb3);
		MultiplyAdd(ref d3Lower, ref d3Upper, h0, coefficient);
		MultiplyAdd(ref d4Lower, ref d4Upper, h1, coefficient);

		coefficient = Vector128.Create(power.Limb4);
		MultiplyAdd(ref d4Lower, ref d4Upper, h0, coefficient);

		coefficient = Vector128.Create(power.Limb1 * 5);
		MultiplyAdd(ref d0Lower, ref d0Upper, h4, coefficient);

		coefficient = Vector128.Create(power.Limb2 * 5);
		MultiplyAdd(ref d0Lower, ref d0Upper, h3, coefficient);
		MultiplyAdd(ref d1Lower, ref d1Upper, h4, coefficient);

		coefficient = Vector128.Create(power.Limb3 * 5);
		MultiplyAdd(ref d0Lower, ref d0Upper, h2, coefficient);
		MultiplyAdd(ref d1Lower, ref d1Upper, h3, coefficient);
		MultiplyAdd(ref d2Lower, ref d2Upper, h4, coefficient);

		coefficient = Vector128.Create(power.Limb4 * 5);
		MultiplyAdd(ref d0Lower, ref d0Upper, h1, coefficient);
		MultiplyAdd(ref d1Lower, ref d1Upper, h2, coefficient);
		MultiplyAdd(ref d2Lower, ref d2Upper, h3, coefficient);
		MultiplyAdd(ref d3Lower, ref d3Upper, h4, coefficient);
	}

	private void AppendFourWay(scoped ReadOnlySpan<byte> source)
	{
		int length = source.Length & -BlockSize4;
		ref byte input = ref source.GetReference();
		Vector128<uint> h0 = Vector128.CreateScalar(_state.H0);
		Vector128<uint> h1 = Vector128.CreateScalar(_state.H1);
		Vector128<uint> h2 = Vector128.CreateScalar(_state.H2);
		Vector128<uint> h3 = Vector128.CreateScalar(_state.H3);
		Vector128<uint> h4 = Vector128.CreateScalar(_state.H4);
		Vector128<uint> r0 = Vector128.Create(_r0.GetElement(0));
		Vector128<uint> r1 = Vector128.Create(_r1.GetElement(0));
		Vector128<uint> r2 = Vector128.Create(_r2.GetElement(0));
		Vector128<uint> r3 = Vector128.Create(_r3.GetElement(0));
		Vector128<uint> r4 = Vector128.Create(_r4.GetElement(0));
		Vector128<uint> s1 = Vector128.Create(_s1.GetElement(0));
		Vector128<uint> s2 = Vector128.Create(_s2.GetElement(0));
		Vector128<uint> s3 = Vector128.Create(_s3.GetElement(0));
		Vector128<uint> s4 = Vector128.Create(_s4.GetElement(0));
		LoadFour(ref input, out Vector128<uint> m0, out Vector128<uint> m1, out Vector128<uint> m2, out Vector128<uint> m3, out Vector128<uint> m4);
		h2 += m2;
		int remaining = length - BlockSize4;

		while (remaining is not 0)
		{
			h0 += m0;
			h1 += m1;
			h3 += m3;
			h4 += m4;
			Multiply
			(
				h0, h1, h2, h3, h4,
				r0, r1, r2, r3, r4,
				s1, s2, s3, s4,
				out Vector128<ulong> d0Lower, out Vector128<ulong> d0Upper,
				out Vector128<ulong> d1Lower, out Vector128<ulong> d1Upper,
				out Vector128<ulong> d2Lower, out Vector128<ulong> d2Upper,
				out Vector128<ulong> d3Lower, out Vector128<ulong> d3Upper,
				out Vector128<ulong> d4Lower, out Vector128<ulong> d4Upper
			);
			Reduce(d0Lower, d0Upper, d1Lower, d1Upper, d2Lower, d2Upper, d3Lower, d3Upper, d4Lower, d4Upper, out h0, out h1, out h2, out h3, out h4);
			input = ref Unsafe.Add(ref input, BlockSize4);
			LoadFour(ref input, out m0, out m1, out m2, out m3, out m4);
			h2 += m2;
			remaining -= BlockSize4;
		}

		h0 += m0;
		h1 += m1;
		h3 += m3;
		h4 += m4;
		Multiply
		(
			h0, h1, h2, h3, h4,
			_r0, _r1, _r2, _r3, _r4,
			_s1, _s2, _s3, _s4,
			out Vector128<ulong> finalD0Lower, out Vector128<ulong> finalD0Upper,
			out Vector128<ulong> finalD1Lower, out Vector128<ulong> finalD1Upper,
			out Vector128<ulong> finalD2Lower, out Vector128<ulong> finalD2Upper,
			out Vector128<ulong> finalD3Lower, out Vector128<ulong> finalD3Upper,
			out Vector128<ulong> finalD4Lower, out Vector128<ulong> finalD4Upper
		);

		_state.SetAccumulator(Vector128.Sum(finalD0Lower + finalD0Upper), Vector128.Sum(finalD1Lower + finalD1Upper), Vector128.Sum(finalD2Lower + finalD2Upper), Vector128.Sum(finalD3Lower + finalD3Upper), Vector128.Sum(finalD4Lower + finalD4Upper));
	}

	private void AppendEightWay(scoped ReadOnlySpan<byte> source)
	{
		int length = source.Length & -BlockSize4;
		ref byte input = ref source.GetReference();
		LoadFour(ref input, out Vector128<uint> m0, out Vector128<uint> m1, out Vector128<uint> m2, out Vector128<uint> m3, out Vector128<uint> m4);
		Vector128<uint> h0 = m0 + Vector128.CreateScalar(_state.H0);
		Vector128<uint> h1 = m1 + Vector128.CreateScalar(_state.H1);
		Vector128<uint> h2 = m2 + Vector128.CreateScalar(_state.H2);
		Vector128<uint> h3 = m3 + Vector128.CreateScalar(_state.H3);
		Vector128<uint> h4 = m4 + Vector128.CreateScalar(_state.H4);
		Poly1305Power power4 = new(_r0.GetElement(0), _r1.GetElement(0), _r2.GetElement(0), _r3.GetElement(0), _r4.GetElement(0));
		Poly1305Power power8 = Poly1305State26.Square(power4);
		input = ref Unsafe.Add(ref input, BlockSize4);
		int remaining = length - BlockSize4;

		while (remaining >= BlockSize4 * 2)
		{
			MultiplyBroadcast
			(
				h0, h1, h2, h3, h4, in power8,
				out Vector128<ulong> d0Lower, out Vector128<ulong> d0Upper,
				out Vector128<ulong> d1Lower, out Vector128<ulong> d1Upper,
				out Vector128<ulong> d2Lower, out Vector128<ulong> d2Upper,
				out Vector128<ulong> d3Lower, out Vector128<ulong> d3Upper,
				out Vector128<ulong> d4Lower, out Vector128<ulong> d4Upper
			);

			LoadFour(ref input, out m0, out m1, out m2, out m3, out m4);
			MultiplyAddBroadcast(ref d0Lower, ref d0Upper, ref d1Lower, ref d1Upper, ref d2Lower, ref d2Upper, ref d3Lower, ref d3Upper, ref d4Lower, ref d4Upper, m0, m1, m2, m3, m4, in power4);
			Reduce(d0Lower, d0Upper, d1Lower, d1Upper, d2Lower, d2Upper, d3Lower, d3Upper, d4Lower, d4Upper, out h0, out h1, out h2, out h3, out h4);

			ref byte secondGroup = ref Unsafe.Add(ref input, BlockSize4);
			LoadFour(ref secondGroup, out m0, out m1, out m2, out m3, out m4);
			h0 += m0;
			h1 += m1;
			h2 += m2;
			h3 += m3;
			h4 += m4;
			input = ref Unsafe.Add(ref input, BlockSize4 * 2);
			remaining -= BlockSize4 * 2;
		}

		while (remaining is not 0)
		{
			MultiplyBroadcast
			(
				h0, h1, h2, h3, h4, in power4,
				out Vector128<ulong> d0Lower, out Vector128<ulong> d0Upper,
				out Vector128<ulong> d1Lower, out Vector128<ulong> d1Upper,
				out Vector128<ulong> d2Lower, out Vector128<ulong> d2Upper,
				out Vector128<ulong> d3Lower, out Vector128<ulong> d3Upper,
				out Vector128<ulong> d4Lower, out Vector128<ulong> d4Upper
			);
			Reduce(d0Lower, d0Upper, d1Lower, d1Upper, d2Lower, d2Upper, d3Lower, d3Upper, d4Lower, d4Upper, out h0, out h1, out h2, out h3, out h4);
			LoadFour(ref input, out m0, out m1, out m2, out m3, out m4);
			h0 += m0;
			h1 += m1;
			h2 += m2;
			h3 += m3;
			h4 += m4;
			input = ref Unsafe.Add(ref input, BlockSize4);
			remaining -= BlockSize4;
		}

		Multiply
		(
			h0, h1, h2, h3, h4,
			_r0, _r1, _r2, _r3, _r4,
			_s1, _s2, _s3, _s4,
			out Vector128<ulong> finalD0Lower, out Vector128<ulong> finalD0Upper,
			out Vector128<ulong> finalD1Lower, out Vector128<ulong> finalD1Upper,
			out Vector128<ulong> finalD2Lower, out Vector128<ulong> finalD2Upper,
			out Vector128<ulong> finalD3Lower, out Vector128<ulong> finalD3Upper,
			out Vector128<ulong> finalD4Lower, out Vector128<ulong> finalD4Upper
		);

		_state.SetAccumulator(Vector128.Sum(finalD0Lower + finalD0Upper), Vector128.Sum(finalD1Lower + finalD1Upper), Vector128.Sum(finalD2Lower + finalD2Upper), Vector128.Sum(finalD3Lower + finalD3Upper), Vector128.Sum(finalD4Lower + finalD4Upper));
	}

	private void AppendTwoWay(scoped ReadOnlySpan<byte> source, int secondLength, bool padPartialBlock)
	{
		ref byte input = ref source.GetReference();
		LoadTwo(ref input, secondLength, padPartialBlock, out Vector128<uint> h0, out Vector128<uint> h1, out Vector128<uint> h2, out Vector128<uint> h3, out Vector128<uint> h4);

		Vector128<ulong> d0 = MultiplyUpper(h2, _s3);
		Vector128<ulong> d1 = MultiplyUpper(h2, _s4);
		Vector128<ulong> d2 = MultiplyUpper(h2, _r0);
		Vector128<ulong> d3 = MultiplyUpper(h2, _r1);
		Vector128<ulong> d4 = MultiplyUpper(h2, _r2);
		MultiplyAddUpper(ref d0, h0, _r0);
		MultiplyAddUpper(ref d1, h0, _r1);
		MultiplyAddUpper(ref d2, h0, _r2);
		MultiplyAddUpper(ref d3, h0, _r3);
		MultiplyAddUpper(ref d4, h0, _r4);
		MultiplyAddUpper(ref d0, h1, _s4);
		MultiplyAddUpper(ref d1, h1, _r0);
		MultiplyAddUpper(ref d2, h1, _r1);
		MultiplyAddUpper(ref d3, h1, _r2);
		MultiplyAddUpper(ref d4, h1, _r3);
		MultiplyAddUpper(ref d0, h3, _s2);
		MultiplyAddUpper(ref d1, h3, _s3);
		MultiplyAddUpper(ref d2, h3, _s4);
		MultiplyAddUpper(ref d3, h3, _r0);
		MultiplyAddUpper(ref d4, h3, _r1);
		MultiplyAddUpper(ref d0, h4, _s1);
		MultiplyAddUpper(ref d1, h4, _s2);
		MultiplyAddUpper(ref d2, h4, _s3);
		MultiplyAddUpper(ref d3, h4, _s4);
		MultiplyAddUpper(ref d4, h4, _r0);

		_state.SetAccumulator(Vector128.Sum(d0), Vector128.Sum(d1), Vector128.Sum(d2), Vector128.Sum(d3), Vector128.Sum(d4));
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
			ReadOnlySpan<byte> vectorInput = source.Slice(0, fourWayLength);

			if (fourWayLength >= BlockSize4 * 8)
			{
				AppendEightWay(vectorInput);
			}
			else
			{
				AppendFourWay(vectorInput);
			}

			source = source.Slice(fourWayLength);

			if (source.Length >= BlockSize2)
			{
				AppendTwoWay(source, Poly1305Algorithm.BlockSizeInBytes, padPartialBlock);
				source = source.Slice(BlockSize2);
			}

			if (source.Length > Poly1305Algorithm.BlockSizeInBytes)
			{
				AppendTwoWay(source, source.Length - Poly1305Algorithm.BlockSizeInBytes, padPartialBlock);
				return;
			}
		}

		_state.Append(source, padPartialBlock);
	}

	public void WriteMac(scoped Span<byte> destination)
	{
		_state.WriteMac(destination);
	}
}
