namespace CryptoBase.Ciphers.Modes.Gcm;

internal static partial class GHashSoftware
{
	internal static void Multiply32(ref ulong accumulatorHigh, ref ulong accumulatorLow, ulong keyHigh, ulong keyLow)
	{
		Span<uint> buffer = stackalloc uint[62];
		Span<uint> a = buffer.Slice(0, 18);
		Span<uint> b = buffer.Slice(18, 18);
		Span<uint> c = buffer.Slice(36, 18);
		Span<uint> z = buffer.Slice(54, 8);

		try
		{
			a[0] = (uint)accumulatorLow;
			a[1] = (uint)(accumulatorLow >> 32);
			a[2] = (uint)accumulatorHigh;
			a[3] = (uint)(accumulatorHigh >> 32);
			a[4] = a[0] ^ a[1];
			a[5] = a[2] ^ a[3];
			a[6] = a[0] ^ a[2];
			a[7] = a[1] ^ a[3];
			a[8] = a[6] ^ a[7];

			a[9] = ReverseBits32(a[0]);
			a[10] = ReverseBits32(a[1]);
			a[11] = ReverseBits32(a[2]);
			a[12] = ReverseBits32(a[3]);
			a[13] = a[9] ^ a[10];
			a[14] = a[11] ^ a[12];
			a[15] = a[9] ^ a[11];
			a[16] = a[10] ^ a[12];
			a[17] = a[15] ^ a[16];

			b[0] = (uint)keyLow;
			b[1] = (uint)(keyLow >> 32);
			b[2] = (uint)keyHigh;
			b[3] = (uint)(keyHigh >> 32);
			b[4] = b[0] ^ b[1];
			b[5] = b[2] ^ b[3];
			b[6] = b[0] ^ b[2];
			b[7] = b[1] ^ b[3];
			b[8] = b[6] ^ b[7];

			b[9] = ReverseBits32(b[0]);
			b[10] = ReverseBits32(b[1]);
			b[11] = ReverseBits32(b[2]);
			b[12] = ReverseBits32(b[3]);
			b[13] = b[9] ^ b[10];
			b[14] = b[11] ^ b[12];
			b[15] = b[9] ^ b[11];
			b[16] = b[10] ^ b[12];
			b[17] = b[15] ^ b[16];

			c[0] = CarrylessMultiply32(a[0], b[0]);
			c[1] = CarrylessMultiply32(a[1], b[1]);
			c[2] = CarrylessMultiply32(a[2], b[2]);
			c[3] = CarrylessMultiply32(a[3], b[3]);
			c[4] = CarrylessMultiply32(a[4], b[4]);
			c[5] = CarrylessMultiply32(a[5], b[5]);
			c[6] = CarrylessMultiply32(a[6], b[6]);
			c[7] = CarrylessMultiply32(a[7], b[7]);
			c[8] = CarrylessMultiply32(a[8], b[8]);
			c[9] = CarrylessMultiply32(a[9], b[9]);
			c[10] = CarrylessMultiply32(a[10], b[10]);
			c[11] = CarrylessMultiply32(a[11], b[11]);
			c[12] = CarrylessMultiply32(a[12], b[12]);
			c[13] = CarrylessMultiply32(a[13], b[13]);
			c[14] = CarrylessMultiply32(a[14], b[14]);
			c[15] = CarrylessMultiply32(a[15], b[15]);
			c[16] = CarrylessMultiply32(a[16], b[16]);
			c[17] = CarrylessMultiply32(a[17], b[17]);

			c[4] ^= c[0] ^ c[1];
			c[5] ^= c[2] ^ c[3];
			c[8] ^= c[6] ^ c[7];
			c[13] ^= c[9] ^ c[10];
			c[14] ^= c[11] ^ c[12];
			c[17] ^= c[15] ^ c[16];

			uint d0 = c[0];
			uint d1 = c[4] ^ ReverseBits32(c[9]) >> 1;
			uint d2 = c[1] ^ c[0] ^ c[2] ^ c[6] ^ ReverseBits32(c[13]) >> 1;
			uint d3 = c[4] ^ c[5] ^ c[8] ^ ReverseBits32(c[10] ^ c[9] ^ c[11] ^ c[15]) >> 1;
			uint d4 = c[2] ^ c[1] ^ c[3] ^ c[7] ^ ReverseBits32(c[13] ^ c[14] ^ c[17]) >> 1;
			uint d5 = c[5] ^ ReverseBits32(c[11] ^ c[10] ^ c[12] ^ c[16]) >> 1;
			uint d6 = c[3] ^ ReverseBits32(c[14]) >> 1;
			uint d7 = ReverseBits32(c[12]) >> 1;

			z[0] = d0 << 1;
			z[1] = d1 << 1 | d0 >> 31;
			z[2] = d2 << 1 | d1 >> 31;
			z[3] = d3 << 1 | d2 >> 31;
			z[4] = d4 << 1 | d3 >> 31;
			z[5] = d5 << 1 | d4 >> 31;
			z[6] = d6 << 1 | d5 >> 31;
			z[7] = d7 << 1 | d6 >> 31;

			uint low0 = z[0];
			z[4] ^= low0 ^ low0 >> 1 ^ low0 >> 2 ^ low0 >> 7;
			z[3] ^= low0 << 31 ^ low0 << 30 ^ low0 << 25;
			uint low1 = z[1];
			z[5] ^= low1 ^ low1 >> 1 ^ low1 >> 2 ^ low1 >> 7;
			z[4] ^= low1 << 31 ^ low1 << 30 ^ low1 << 25;
			uint low2 = z[2];
			z[6] ^= low2 ^ low2 >> 1 ^ low2 >> 2 ^ low2 >> 7;
			z[5] ^= low2 << 31 ^ low2 << 30 ^ low2 << 25;
			uint low3 = z[3];
			z[7] ^= low3 ^ low3 >> 1 ^ low3 >> 2 ^ low3 >> 7;
			z[6] ^= low3 << 31 ^ low3 << 30 ^ low3 << 25;

			accumulatorHigh = (ulong)z[7] << 32 | z[6];
			accumulatorLow = (ulong)z[5] << 32 | z[4];
		}
		finally
		{
			buffer.ZeroMemory();
		}
	}

	private static uint CarrylessMultiply32(uint x, uint y)
	{
		uint x0 = x & 0x11111111;
		uint x1 = x & 0x22222222;
		uint x2 = x & 0x44444444;
		uint x3 = x & 0x88888888;
		uint y0 = y & 0x11111111;
		uint y1 = y & 0x22222222;
		uint y2 = y & 0x44444444;
		uint y3 = y & 0x88888888;

		uint z0 = x0 * y0 ^ x1 * y3 ^ x2 * y2 ^ x3 * y1;
		uint z1 = x0 * y1 ^ x1 * y0 ^ x2 * y3 ^ x3 * y2;
		uint z2 = x0 * y2 ^ x1 * y1 ^ x2 * y0 ^ x3 * y3;
		uint z3 = x0 * y3 ^ x1 * y2 ^ x2 * y1 ^ x3 * y0;

		return z0 & 0x11111111 | z1 & 0x22222222 | z2 & 0x44444444 | z3 & 0x88888888;
	}

	private static uint ReverseBits32(uint value)
	{
		value = (value & 0x55555555) << 1 | value >> 1 & 0x55555555;
		value = (value & 0x33333333) << 2 | value >> 2 & 0x33333333;
		value = (value & 0x0F0F0F0F) << 4 | value >> 4 & 0x0F0F0F0F;
		return BinaryPrimitives.ReverseEndianness(value);
	}
}
