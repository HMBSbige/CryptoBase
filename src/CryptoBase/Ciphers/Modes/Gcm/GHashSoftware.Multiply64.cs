namespace CryptoBase.Ciphers.Modes.Gcm;

internal static partial class GHashSoftware
{
	internal static void InitializeKey64(ref ulong high, ref ulong low)
	{
		ulong carry = 0UL - (high >> 63);
		high = high << 1 | low >> 63;
		low <<= 1;
		low ^= carry & 1;
		high ^= carry & 0xc200000000000000;
	}

	internal static void Multiply64(ref ulong accumulatorHigh, ref ulong accumulatorLow, ulong keyHigh, ulong keyLow)
	{
		ulong r1 = CarrylessMultiply64(accumulatorLow, keyLow, out ulong lowProduct);
		ulong r3 = CarrylessMultiply64(accumulatorHigh, keyHigh, out ulong highProduct);
		ulong mid1 = CarrylessMultiply64(accumulatorLow ^ accumulatorHigh, keyLow ^ keyHigh, out ulong middleProduct);
		// Copy out results to locals to avoid repeated stack writes during reduction.
		ulong r0 = lowProduct;
		ulong r2 = highProduct;
		ulong mid0 = middleProduct ^ r0 ^ r2;
		mid1 ^= r1 ^ r3;
		r2 ^= mid1;
		r1 ^= mid0;

		r1 ^= r0 << 63 ^ r0 << 62 ^ r0 << 57;
		r2 ^= r0;
		r3 ^= r1;
		r2 ^= r0 >> 1;
		r2 ^= r1 << 63;
		r3 ^= r1 >> 1;
		r2 ^= r0 >> 2;
		r2 ^= r1 << 62;
		r3 ^= r1 >> 2;
		r2 ^= r0 >> 7;
		r2 ^= r1 << 57;
		r3 ^= r1 >> 7;

		accumulatorLow = r2;
		accumulatorHigh = r3;
	}

	private static ulong CarrylessMultiply64(ulong a, ulong b, out ulong low)
	{
		// Handle a's low nibble separately to prevent carries between nibbles.
		ulong a0 = a & 0x1111111111111110;
		ulong a1 = a & 0x2222222222222220;
		ulong a2 = a & 0x4444444444444440;
		ulong a3 = a & 0x8888888888888880;
		ulong b0 = b & 0x1111111111111111;
		ulong b1 = b & 0x2222222222222222;
		ulong b2 = b & 0x4444444444444444;
		ulong b3 = b & 0x8888888888888888;

		ulong c0High = Math.BigMul(a0, b0, out ulong c0Low);
		c0High ^= Math.BigMul(a1, b3, out ulong partLow);
		c0Low ^= partLow;
		c0High ^= Math.BigMul(a2, b2, out partLow);
		c0Low ^= partLow;
		c0High ^= Math.BigMul(a3, b1, out partLow);
		c0Low ^= partLow;

		ulong c1High = Math.BigMul(a0, b1, out ulong c1Low);
		c1High ^= Math.BigMul(a1, b0, out partLow);
		c1Low ^= partLow;
		c1High ^= Math.BigMul(a2, b3, out partLow);
		c1Low ^= partLow;
		c1High ^= Math.BigMul(a3, b2, out partLow);
		c1Low ^= partLow;

		ulong c2High = Math.BigMul(a0, b2, out ulong c2Low);
		c2High ^= Math.BigMul(a1, b1, out partLow);
		c2Low ^= partLow;
		c2High ^= Math.BigMul(a2, b0, out partLow);
		c2Low ^= partLow;
		c2High ^= Math.BigMul(a3, b3, out partLow);
		c2Low ^= partLow;

		ulong c3High = Math.BigMul(a0, b3, out ulong c3Low);
		c3High ^= Math.BigMul(a1, b2, out partLow);
		c3Low ^= partLow;
		c3High ^= Math.BigMul(a2, b1, out partLow);
		c3Low ^= partLow;
		c3High ^= Math.BigMul(a3, b0, out partLow);
		c3Low ^= partLow;

		ulong extra0 = 0UL - (a & 1) & b;
		ulong extra1 = 0UL - (a >> 1 & 1) & b;
		ulong extra2 = 0UL - (a >> 2 & 1) & b;
		ulong extra3 = 0UL - (a >> 3 & 1) & b;
		ulong extraLow = extra0 ^ extra1 << 1 ^ extra2 << 2 ^ extra3 << 3;
		ulong extraHigh = extra1 >> 63 ^ extra2 >> 62 ^ extra3 >> 61;

		low = c0Low & 0x1111111111111111 ^ c1Low & 0x2222222222222222 ^ c2Low & 0x4444444444444444 ^ c3Low & 0x8888888888888888 ^ extraLow;
		return c0High & 0x1111111111111111 ^ c1High & 0x2222222222222222 ^ c2High & 0x4444444444444444 ^ c3High & 0x8888888888888888 ^ extraHigh;
	}
}
