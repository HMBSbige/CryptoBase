namespace CryptoBase.Macs.Poly1305;

internal ref struct Poly1305Software : IPoly1305State<Poly1305Software>
{
	private const ulong FullBlockHighBit = 1;

	public static bool IsSupported => true;

	private ulong _r0, _r1;
	private ulong _s1;
	private ulong _x0, _x1;

	private ulong _h0, _h1, _h2;

	private void Initialize(scoped ReadOnlySpan<byte> key)
	{
		Debug.Assert(key.Length is Poly1305Algorithm.KeyLengthInBytes);

		ulong t0 = BinaryPrimitives.ReadUInt64LittleEndian(key);
		ulong t1 = BinaryPrimitives.ReadUInt64LittleEndian(key.Slice(8));
		_r0 = t0 & 0x0FFFFFFC0FFFFFFFUL;
		_r1 = t1 & 0x0FFFFFFC0FFFFFFCUL;
		_s1 = _r1 + (_r1 >> 2);

		_x0 = BinaryPrimitives.ReadUInt64LittleEndian(key.Slice(16));
		_x1 = BinaryPrimitives.ReadUInt64LittleEndian(key.Slice(24));
		_h0 = 0;
		_h1 = 0;
		_h2 = 0;
	}

	public static void Initialize(ref Poly1305Software state, scoped ReadOnlySpan<byte> key)
	{
		state.Initialize(key);
	}

	// carry holds the part of word 1 that Poly1305Utils.Multiply64 has not folded into h1 yet.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Block(ref ulong h0, ref ulong h1, ref ulong h2, ref ulong carry, ulong r0, ulong r1, ulong s1, ref byte source, ulong highBit)
	{
		ulong t0 = Unsafe.ReadUnaligned<ulong>(ref source);
		ulong t1 = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref source, 8));

		Block(ref h0, ref h1, ref h2, ref carry, r0, r1, s1, t0, t1, highBit);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Block(ref ulong h0, ref ulong h1, ref ulong h2, ref ulong carry, ulong r0, ulong r1, ulong s1, ulong t0, ulong t1, ulong highBit)
	{
		h0 += t0;
		carry += h0 < t0 ? 1UL : 0;
		h1 += t1;
		h2 += highBit + (h1 < t1 ? 1UL : 0);

		Poly1305Utils.Multiply64(ref h0, ref h1, ref h2, ref carry, r0, r1, s1);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void Block(ulong t0, ulong t1, ulong highBit)
	{
		ulong h0 = _h0;
		ulong h1 = _h1;
		ulong h2 = _h2;
		ulong carry = 0;
		Block(ref h0, ref h1, ref h2, ref carry, _r0, _r1, _s1, t0, t1, highBit);
		Poly1305Utils.PropagateCarry(ref h1, ref h2, carry);
		_h0 = h0;
		_h1 = h1;
		_h2 = h2;
	}

	public void AppendMessage(scoped ReadOnlySpan<byte> source)
	{
		Append(source, false);
	}

	public void AppendPaddedSegment(scoped ReadOnlySpan<byte> source)
	{
		Append(source, true);
	}

	[SkipLocalsInit]
	private void Append(scoped ReadOnlySpan<byte> source, bool padPartialBlock)
	{
		int length = source.Length;
		ref byte input = ref MemoryMarshal.GetReference(source);

		if (length >= Poly1305Algorithm.BlockSizeInBytes)
		{
			ulong r0 = _r0;
			ulong r1 = _r1;
			ulong s1 = _s1;
			ulong h0 = _h0;
			ulong h1 = _h1;
			ulong h2 = _h2;
			ulong carry = 0;

			do
			{
				Block(ref h0, ref h1, ref h2, ref carry, r0, r1, s1, ref input, FullBlockHighBit);
				input = ref Unsafe.Add(ref input, Poly1305Algorithm.BlockSizeInBytes);
				length -= Poly1305Algorithm.BlockSizeInBytes;
			} while (length >= Poly1305Algorithm.BlockSizeInBytes);

			Poly1305Utils.PropagateCarry(ref h1, ref h2, carry);
			_h0 = h0;
			_h1 = h1;
			_h2 = h2;
		}

		if (length is 0)
		{
			return;
		}

		Poly1305Utils.LoadFinalBlock(MemoryMarshal.CreateReadOnlySpan(ref input, length), padPartialBlock, FullBlockHighBit, out ulong low, out ulong high, out ulong highBit);
		Block(low, high, highBit);
	}

	public readonly void WriteMac(scoped Span<byte> destination)
	{
		Debug.Assert(destination.Length >= Poly1305Algorithm.MacLength);
		// Poly1305Utils.Multiply64 leaves h2 at most 3 and PropagateCarry adds at most 1, so g2 >> 2 is 0 or 1 and works as the mask bit.
		Debug.Assert(_h2 <= 4);

		ulong g0 = _h0 + 5;
		ulong carry = g0 < _h0 ? 1UL : 0;
		ulong g1 = _h1 + carry;
		carry = g1 < _h1 ? 1UL : 0;
		ulong g2 = _h2 + carry;
		ulong mask = 0UL - (g2 >> 2);
		ulong h0 = _h0 & ~mask | g0 & mask;
		ulong h1 = _h1 & ~mask | g1 & mask;

		ulong tag0 = h0 + _x0;
		carry = tag0 < h0 ? 1UL : 0;
		ulong tag1 = h1 + _x1 + carry;
		Poly1305Utils.WriteTag(destination, tag0, tag1);
	}
}
