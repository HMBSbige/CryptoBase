using static CryptoBase.EllipticCurves.LimbArithmetic;

namespace CryptoBase.EllipticCurves.SM9;

// Signed windows of a scalar of 64-bit limbs, least significant first.
internal static class SM9Windows
{
	// The number of digits of width w for scalars below 2^bits: ⌊bits/w⌋ + 1, the last holding the top bits mod w and the carry into them.
	internal static int DigitCount(int bits, int width)
	{
		return bits / width + 1;
	}

	// Writes digits d_i in [−2^(w − 1) + 1, 2^(w − 1)] with k = Σ d_i·2^(wi). Window i plus the carry from below, v in [0, 2^w], gives d_i = v and no carry if v ≤ 2^(w − 1), and d_i = v − 2^w and a carry otherwise. The top window holds at most w − 1 bits of k, so it takes the last carry. The carry and digits come from arithmetic on v, not comparisons, and only i decides which limbs are read.
	internal static void Recode(ReadOnlySpan<ulong> limbs, int width, Span<sbyte> digits)
	{
		// Digits up to 2^(w − 1) must fit in an sbyte.
		Debug.Assert(width is > 1 and < 8);

		uint mask = (1u << width) - 1;
		uint half = 1u << width - 1;
		uint carry = 0;

		for (int i = 0; i < digits.Length; ++i)
		{
			uint value = ((uint)ReadBits(limbs, i * width) & mask) + carry;
			carry = half - value >> 31;
			digits[i] = (sbyte)(value - (carry << width));
		}

		Debug.Assert(carry is 0);
	}
}
