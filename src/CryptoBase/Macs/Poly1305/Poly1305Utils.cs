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
	internal static void Multiply64(ref ulong h0, ref ulong h1, ref ulong h2, ulong r0, ulong r1, ulong s1)
	{
		ulong d3 = Math.BigMul(r1, h0, out ulong d2);
		ulong d1 = Math.BigMul(r0, h0, out ulong nextH0);

		ulong high = Math.BigMul(r0, h1, out ulong low);
		ulong previous = d2;
		d2 += low;
		d3 += high + (d2 < previous ? 1UL : 0);

		high = Math.BigMul(s1, h1, out low);
		previous = nextH0;
		nextH0 += low;
		d1 += high + (nextH0 < previous ? 1UL : 0);

		previous = d2;
		d2 += h2 * s1;
		d3 += d2 < previous ? 1UL : 0;

		previous = d1;
		ulong nextH1 = d1 + d2;
		d3 += h2 * r0 + (nextH1 < previous ? 1UL : 0);

		ulong nextH2 = d3 & 3;
		ulong reduction = (d3 & ~3UL) + (d3 >> 2);
		previous = nextH0;
		nextH0 += reduction;
		ulong carry = nextH0 < previous ? 1UL : 0;
		previous = nextH1;
		nextH1 += carry;
		nextH2 += nextH1 < previous ? 1UL : 0;

		h0 = nextH0;
		h1 = nextH1;
		h2 = nextH2;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void LoadPartialBlock(scoped ReadOnlySpan<byte> source, out ulong low, out ulong high)
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
