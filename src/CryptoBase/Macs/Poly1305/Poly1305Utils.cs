namespace CryptoBase.Macs.Poly1305;

internal static class Poly1305Utils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void LoadFour(ref byte source, out Vector256<ulong> m0, out Vector256<ulong> m1, out Vector256<ulong> m2, out Vector256<ulong> m3, out Vector256<ulong> m4)
	{
		Vector128<ulong> block0 = Vector128.LoadUnsafe(ref source).AsUInt64();
		Vector128<ulong> block1 = Vector128.LoadUnsafe(ref source, 16).AsUInt64();
		Vector128<ulong> block2 = Vector128.LoadUnsafe(ref source, 32).AsUInt64();
		Vector128<ulong> block3 = Vector128.LoadUnsafe(ref source, 48).AsUInt64();
		Vector256<ulong> low = Vector256.Create(Sse2.UnpackLow(block0, block1), Sse2.UnpackLow(block2, block3));
		Vector256<ulong> high = Vector256.Create(Sse2.UnpackHigh(block0, block1), Sse2.UnpackHigh(block2, block3));
		Vector256<ulong> mask = Vector256.Create((ulong)Poly1305State26.LimbMask);

		m0 = low & mask;
		m1 = low >>> 26 & mask;
		m2 = (low >>> 52 | high << 12) & mask;
		m3 = high >>> 14 & mask;
		m4 = high >>> 40 | Vector256.Create((ulong)Poly1305State26.FullBlockHighBit);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Reduce
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

	// Word 1 of the accumulator is h1 + carry: the carry out of word 0 waits for the next product instead of rippling through h1 and h2, which keeps it off the chain from one block to the next.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Multiply64(ref ulong h0, ref ulong h1, ref ulong h2, ref ulong carry, ulong r0, ulong r1, ulong s1)
	{
		ulong d3 = Math.BigMul(r1, h0, out ulong d2);
		ulong d1 = Math.BigMul(r0, h0, out ulong d0);

		ulong high = Math.BigMul(r0, h1, out ulong low);
		d2 += low;
		d3 += high + (d2 < low ? 1UL : 0);

		high = Math.BigMul(s1, h1, out low);
		d0 += low;
		d1 += high + (d0 < low ? 1UL : 0);

		low = carry * s1;
		d0 += low;
		d1 += d0 < low ? 1UL : 0;

		low = h2 * s1 + carry * r0;
		d2 += low;
		d3 += d2 < low ? 1UL : 0;

		ulong word1 = d1 + d2;
		ulong word2 = d3 + h2 * r0 + (word1 < d2 ? 1UL : 0);
		ulong reduction = (word2 & ~3UL) + (word2 >> 2);
		h0 = d0 + reduction;
		carry = h0 < reduction ? 1UL : 0;
		h1 = word1;
		h2 = word2 & 3;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void PropagateCarry(ref ulong h1, ref ulong h2, ulong carry)
	{
		h1 += carry;
		h2 += h1 < carry ? 1UL : 0;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void WriteTag(scoped Span<byte> destination, ulong low, ulong high)
	{
		Debug.Assert(destination.Length >= Poly1305Algorithm.MacLength);

		ref byte output = ref MemoryMarshal.GetReference(destination);

		if (Vector128.IsHardwareAccelerated)
		{
			Vector128.Create(low, high).AsByte().StoreUnsafe(ref output);
			return;
		}

		Unsafe.WriteUnaligned(ref output, low);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref output, sizeof(ulong)), high);
	}

	// A zero-padded AEAD segment sets the full-block high bit; a message instead ends with a 0x01 byte after its last byte.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void LoadFinalBlock(scoped ReadOnlySpan<byte> source, bool padPartialBlock, ulong fullBlockHighBit, out ulong low, out ulong high, out ulong highBit)
	{
		LoadPartialBlock(source, out low, out high);

		if (padPartialBlock)
		{
			highBit = fullBlockHighBit;
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
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void LoadPartialBlock(scoped ReadOnlySpan<byte> source, out ulong low, out ulong high)
	{
		Debug.Assert(source.Length is > 0 and < Poly1305Algorithm.BlockSizeInBytes);

		if (source.Length >= sizeof(ulong))
		{
			low = BinaryPrimitives.ReadUInt64LittleEndian(source);
			high = LoadPartialWord(source.Slice(sizeof(ulong)));
		}
		else
		{
			low = LoadPartialWord(source);
			high = 0;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong LoadPartialWord(scoped ReadOnlySpan<byte> source)
	{
		Debug.Assert(source.Length < sizeof(ulong));

		int length = source.Length;
		int offset = 0;
		ulong value = 0;

		if ((length & sizeof(uint)) is not 0)
		{
			value = BinaryPrimitives.ReadUInt32LittleEndian(source);
			offset = sizeof(uint);
		}

		if ((length & sizeof(ushort)) is not 0)
		{
			ushort word = BinaryPrimitives.ReadUInt16LittleEndian(source.Slice(offset));
			value |= (ulong)word << offset * 8;
			offset += sizeof(ushort);
		}

		if ((length & 1) is not 0)
		{
			value |= (ulong)source[offset] << offset * 8;
		}

		return value;
	}
}
