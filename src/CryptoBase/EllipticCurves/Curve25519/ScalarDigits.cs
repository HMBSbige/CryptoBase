using static CryptoBase.EllipticCurves.LimbArithmetic;

namespace CryptoBase.EllipticCurves.Curve25519;

// Digit expansions of scalars of 32 little-endian bytes, which are read as four 64-bit limbs.
internal static class ScalarDigits
{
	internal const int LimbCount = 4;

	internal static void ReadLimbs(ReadOnlySpan<byte> scalar, Span<ulong> limbs)
	{
		Debug.Assert(scalar.Length is 8 * LimbCount && limbs.Length is LimbCount);

		limbs[0] = BinaryPrimitives.ReadUInt64LittleEndian(scalar);
		limbs[1] = BinaryPrimitives.ReadUInt64LittleEndian(scalar.Slice(8));
		limbs[2] = BinaryPrimitives.ReadUInt64LittleEndian(scalar.Slice(16));
		limbs[3] = BinaryPrimitives.ReadUInt64LittleEndian(scalar.Slice(24));
	}

	// The digit beyond ⌊256/w⌋ holds the top 256 mod w bits, if any, and the carry into them.
	internal static int SignedWindowCount(int width)
	{
		return 256 / width + 1;
	}

	// Writes SignedWindowCount(w) digits d_i in [−2^(w − 1) + 1, 2^(w − 1)] with k = Σ d_i·2^(wi). Window i of k plus the carry from below, v in [0, 2^w], gives d_i = v and no carry if v ≤ 2^(w − 1), and d_i = v − 2^w and a carry otherwise. The top window holds at most w − 1 bits of k, so v ≤ 2^(w − 1) there and no carry is lost. The carry and digits come from arithmetic on v, not comparisons, and only i decides which limbs are read.
	internal static void SignedWindows(ReadOnlySpan<ulong> limbs, int width, Span<sbyte> digits)
	{
		// Digits up to 2^(w − 1) must fit in an sbyte.
		Debug.Assert(width is > 1 and < 8);
		Debug.Assert(digits.Length == SignedWindowCount(width));

		uint mask = (1u << width) - 1;
		uint half = 1u << width - 1;
		uint carry = 0;

		for (int i = 0; i < digits.Length; ++i)
		{
			uint value = ((uint)ReadBits(limbs, i * width) & mask) + carry;
			carry = half - value >> 31;
			digits[i] = (sbyte)(value - (carry << width));
		}
	}

	// Writes the NAF of width w of the bits of k from start to start + length − 1, in length + 1 digits, and returns the index of its top nonzero digit, or −1 if there is none. A nonzero digit at i carries out only if the w bits from i plus the carry in exceed 2^(w − 1), which needs a bit at or above i + w − 1, so i + w ≤ length: digit length takes the last carry. The time depends on k, which must be public.
	internal static int NonAdjacentForm(ReadOnlySpan<ulong> limbs, int start, int length, int width, Span<sbyte> digits)
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
