namespace CryptoBase.Macs.Poly1305;

internal ref struct Poly1305State26
{
	internal const uint LimbMask = 0x3ffffff;
	internal const uint FullBlockHighBit = 1u << 24;

	private readonly uint _r0, _r1, _r2, _r3, _r4;
	private readonly uint _s1, _s2, _s3, _s4;
	private readonly uint _x0, _x1, _x2, _x3;
	internal uint H0, H1, H2, H3, H4;

	internal Poly1305State26(scoped ReadOnlySpan<byte> key)
	{
		Debug.Assert(key.Length is Poly1305Algorithm.KeyLengthInBytes);
		Unsafe.SkipInit(out this);

		_r0 = BinaryPrimitives.ReadUInt32LittleEndian(key) & LimbMask;
		_r1 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(3)) >> 2 & 0x3FFFF03;
		_r2 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(6)) >> 4 & 0x3FFC0FF;
		_r3 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(9)) >> 6 & 0x3F03FFF;
		_r4 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(12)) >> 8 & 0x00FFFFF;
		_s1 = _r1 * 5;
		_s2 = _r2 * 5;
		_s3 = _r3 * 5;
		_s4 = _r4 * 5;

		_x0 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(16));
		_x1 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(20));
		_x2 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(24));
		_x3 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(28));
		H0 = 0;
		H1 = 0;
		H2 = 0;
		H3 = 0;
		H4 = 0;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private readonly void MultiplyR(ref uint h0, ref uint h1, ref uint h2, ref uint h3, ref uint h4)
	{
		Multiply(ref h0, ref h1, ref h2, ref h3, ref h4, _r0, _r1, _r2, _r3, _r4, _s1, _s2, _s3, _s4);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal readonly void GetPowers(out Poly1305Power r1, out Poly1305Power r2)
	{
		uint h0 = _r0;
		uint h1 = _r1;
		uint h2 = _r2;
		uint h3 = _r3;
		uint h4 = _r4;
		r1 = new Poly1305Power(h0, h1, h2, h3, h4);
		Square(ref h0, ref h1, ref h2, ref h3, ref h4);
		r2 = new Poly1305Power(h0, h1, h2, h3, h4);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal readonly void GetPowers(out Poly1305Power r1, out Poly1305Power r2, out Poly1305Power r3, out Poly1305Power r4)
	{
		uint h0 = _r0;
		uint h1 = _r1;
		uint h2 = _r2;
		uint h3 = _r3;
		uint h4 = _r4;
		r1 = new Poly1305Power(h0, h1, h2, h3, h4);
		Square(ref h0, ref h1, ref h2, ref h3, ref h4);
		r2 = new Poly1305Power(h0, h1, h2, h3, h4);

		uint squared0 = h0;
		uint squared1 = h1;
		uint squared2 = h2;
		uint squared3 = h3;
		uint squared4 = h4;
		MultiplyR(ref h0, ref h1, ref h2, ref h3, ref h4);
		r3 = new Poly1305Power(h0, h1, h2, h3, h4);
		Square(ref squared0, ref squared1, ref squared2, ref squared3, ref squared4);
		r4 = new Poly1305Power(squared0, squared1, squared2, squared3, squared4);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Square(ref uint h0, ref uint h1, ref uint h2, ref uint h3, ref uint h4)
	{
		uint s3 = h3 * 5;
		uint s4 = h4 * 5;
		ulong d0 = (ulong)h0 * h0 + 2 * ((ulong)h1 * s4 + (ulong)h2 * s3);
		ulong d1 = 2 * (ulong)h0 * h1 + 2 * (ulong)h2 * s4 + (ulong)h3 * s3;
		ulong d2 = 2 * (ulong)h0 * h2 + (ulong)h1 * h1 + 2 * (ulong)h3 * s4;
		ulong d3 = 2 * (ulong)h0 * h3 + 2 * (ulong)h1 * h2 + (ulong)h4 * s4;
		ulong d4 = 2 * (ulong)h0 * h4 + 2 * (ulong)h1 * h3 + (ulong)h2 * h2;
		Reduce(out h0, out h1, out h2, out h3, out h4, d0, d1, d2, d3, d4);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Poly1305Power Square(Poly1305Power value)
	{
		Square(ref value.Limb0, ref value.Limb1, ref value.Limb2, ref value.Limb3, ref value.Limb4);
		return value;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Multiply(ref uint h0, ref uint h1, ref uint h2, ref uint h3, ref uint h4, uint r0, uint r1, uint r2, uint r3, uint r4, uint s1, uint s2, uint s3, uint s4)
	{
		ulong d0 = (ulong)h0 * r0 + (ulong)h1 * s4 + (ulong)h2 * s3 + (ulong)h3 * s2 + (ulong)h4 * s1;
		ulong d1 = (ulong)h0 * r1 + (ulong)h1 * r0 + (ulong)h2 * s4 + (ulong)h3 * s3 + (ulong)h4 * s2;
		ulong d2 = (ulong)h0 * r2 + (ulong)h1 * r1 + (ulong)h2 * r0 + (ulong)h3 * s4 + (ulong)h4 * s3;
		ulong d3 = (ulong)h0 * r3 + (ulong)h1 * r2 + (ulong)h2 * r1 + (ulong)h3 * r0 + (ulong)h4 * s4;
		ulong d4 = (ulong)h0 * r4 + (ulong)h1 * r3 + (ulong)h2 * r2 + (ulong)h3 * r1 + (ulong)h4 * r0;
		Reduce(out h0, out h1, out h2, out h3, out h4, d0, d1, d2, d3, d4);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Reduce(out uint h0, out uint h1, out uint h2, out uint h3, out uint h4, ulong d0, ulong d1, ulong d2, ulong d3, ulong d4)
	{
		h0 = (uint)d0 & LimbMask;
		d1 += d0 >> 26;
		h1 = (uint)d1 & LimbMask;
		d2 += d1 >> 26;
		h2 = (uint)d2 & LimbMask;
		d3 += d2 >> 26;
		h3 = (uint)d3 & LimbMask;
		d4 += d3 >> 26;
		h4 = (uint)d4 & LimbMask;
		h0 += (uint)(d4 >> 26) * 5;
		h1 += h0 >> 26;
		h0 &= LimbMask;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal void SetAccumulator(ulong d0, ulong d1, ulong d2, ulong d3, ulong d4)
	{
		d1 += d0 >> 26;
		d0 &= LimbMask;
		d2 += d1 >> 26;
		d1 &= LimbMask;
		d3 += d2 >> 26;
		d2 &= LimbMask;
		d4 += d3 >> 26;
		d3 &= LimbMask;
		d0 += (d4 >> 26) * 5;
		d4 &= LimbMask;
		d1 += d0 >> 26;
		d0 &= LimbMask;
		H0 = (uint)d0;
		H1 = (uint)d1;
		H2 = (uint)d2;
		H3 = (uint)d3;
		H4 = (uint)d4;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void Block(scoped ReadOnlySpan<byte> source, uint highBit)
	{
		Block(BinaryPrimitives.ReadUInt64LittleEndian(source), BinaryPrimitives.ReadUInt64LittleEndian(source.Slice(sizeof(ulong))), highBit);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void Block(ulong low, ulong high, uint highBit)
	{
		H0 += (uint)low & LimbMask;
		H1 += (uint)(low >> 26) & LimbMask;
		H2 += (uint)(low >> 52 | high << 12) & LimbMask;
		H3 += (uint)(high >> 14) & LimbMask;
		H4 += (uint)(high >> 40) | highBit;
		MultiplyR(ref H0, ref H1, ref H2, ref H3, ref H4);
	}

	internal void Append(scoped ReadOnlySpan<byte> source, bool padPartialBlock)
	{
		while (source.Length >= Poly1305Algorithm.BlockSizeInBytes)
		{
			Block(source, FullBlockHighBit);
			source = source.Slice(Poly1305Algorithm.BlockSizeInBytes);
		}

		if (source.IsEmpty)
		{
			return;
		}

		Poly1305Utils.LoadPartialBlock(source, out ulong low, out ulong high);
		uint highBit;

		if (padPartialBlock)
		{
			highBit = FullBlockHighBit;
		}
		else
		{
			highBit = 0;

			if (source.Length < sizeof(ulong))
			{
				low |= 1UL << source.Length * 8;
			}
			else
			{
				high |= 1UL << (source.Length - sizeof(ulong)) * 8;
			}
		}

		Block(low, high, highBit);
	}

	internal void WriteMac(scoped Span<byte> destination)
	{
		Debug.Assert(destination.Length >= Poly1305Algorithm.MacLengthInBytes);

		H2 += H1 >> 26;
		H1 &= LimbMask;
		H3 += H2 >> 26;
		H2 &= LimbMask;
		H4 += H3 >> 26;
		H3 &= LimbMask;
		H0 += (H4 >> 26) * 5;
		H4 &= LimbMask;
		H1 += H0 >> 26;
		H0 &= LimbMask;

		uint g0 = H0 + 5;
		uint g1 = H1 + (g0 >> 26);
		g0 &= LimbMask;
		uint g2 = H2 + (g1 >> 26);
		g1 &= LimbMask;
		uint g3 = H3 + (g2 >> 26);
		g2 &= LimbMask;
		uint g4 = H4 + (g3 >> 26) - (1u << 26);
		g3 &= LimbMask;

		uint mask = (g4 >> 31) - 1;
		g0 &= mask;
		g1 &= mask;
		g2 &= mask;
		g3 &= mask;
		g4 &= mask;
		mask = ~mask;
		H0 = H0 & mask | g0;
		H1 = H1 & mask | g1;
		H2 = H2 & mask | g2;
		H3 = H3 & mask | g3;
		H4 = H4 & mask | g4;

		ulong f0 = (H0 | H1 << 26) + (ulong)_x0;
		ulong f1 = (H1 >> 6 | H2 << 20) + (ulong)_x1;
		ulong f2 = (H2 >> 12 | H3 << 14) + (ulong)_x2;
		ulong f3 = (H3 >> 18 | H4 << 8) + (ulong)_x3;
		f1 += f0 >> 32;
		f2 += f1 >> 32;
		f3 += f2 >> 32;

		BinaryPrimitives.WriteUInt32LittleEndian(destination, (uint)f0);
		BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(4), (uint)f1);
		BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(8), (uint)f2);
		BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(12), (uint)f3);
	}
}
