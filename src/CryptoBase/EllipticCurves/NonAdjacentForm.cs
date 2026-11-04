using static CryptoBase.EllipticCurves.LimbArithmetic;

namespace CryptoBase.EllipticCurves;

// The NAF of the variable-time products, over scalars of any number of 64-bit limbs.
internal static class NonAdjacentForm
{
	// Writes the NAF of width w of the bits of k from start to start + length − 1, in length + 1 digits, and returns the index of its top nonzero digit, or −1 if there is none. A nonzero digit at i carries out only if the w bits from i plus the carry in exceed 2^(w − 1), which needs a bit at or above i + w − 1, so i + w ≤ length: digit length takes the last carry. The time depends on k, which must be public.
	internal static int Recode(ReadOnlySpan<ulong> limbs, int start, int length, int width, Span<sbyte> digits)
	{
		// Digits up to 2^(w − 1) − 1 must fit in an sbyte.
		Debug.Assert(width is >= 2 and <= 8);
		Debug.Assert(digits.Length == length + 1);

		uint mask = (1u << width) - 1;
		uint carry = 0;
		int top = -1;
		digits.Clear();

		for (int i = 0; i < digits.Length;)
		{
			// The mask leaves out the bits from start + length on.
			uint window = (uint)ReadBits(limbs, start + i) & mask >> Math.Max(width - (length - i), 0);

			if ((window & 1) == carry)
			{
				++i;
				continue;
			}

			uint value = window + carry;
			carry = value >> width - 1;
			digits[i] = (sbyte)(value - (carry << width));
			top = i;
			i += width;
		}

		Debug.Assert(carry is 0);

		return top;
	}
}
