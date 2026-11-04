using static CryptoBase.EllipticCurves.LimbArithmetic;

namespace CryptoBase.EllipticCurves.Curve448;

// Digit expansions of scalars of 56 little-endian bytes, which are read as seven 64-bit limbs.
internal static class ScalarDigits
{
	internal const int LimbCount = 7;

	// The limbs of SignedComb: 450 bits and more fit in eight.
	internal const int CombLimbCount = 8;

	// L = 2^446 − 13818066809895115352007386748515426880336692474882178609894547503885, the order of the base points.
	private static ReadOnlySpan<ulong> Order => [0x2378C292AB5844F3, 0x216CC2728DC58F55, 0xC44EDB49AED63690, 0xFFFFFFFF7CCA23E9, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x3FFFFFFFFFFFFFFF];

	internal static void ReadLimbs(ReadOnlySpan<byte> scalar, Span<ulong> limbs)
	{
		Debug.Assert(scalar.Length is 8 * LimbCount && limbs.Length is LimbCount);

		for (int i = 0; i < LimbCount; ++i)
		{
			limbs[i] = BinaryPrimitives.ReadUInt64LittleEndian(scalar.Slice(8 * i));
		}
	}

	// For the k of limbs and a digit count n of at least 450, writes the k' below 2^n whose bits b_i give k + eL = Σ (2b_i − 1)·2^i over i < n, with e = 1 if k is even and 0 otherwise, so that the sum is odd and ≡ k (mod L): k' = (k + eL − 1)/2 + 2^(n − 1), the first term below 2^448 as k + eL < 2^449. Neither the time nor the addresses depend on k.
	internal static void SignedComb(ReadOnlySpan<ulong> limbs, int digitCount, Span<ulong> result)
	{
		Debug.Assert(limbs.Length is LimbCount && result.Length is CombLimbCount);
		Debug.Assert(digitCount is >= 450 and <= 64 * CombLimbCount);

		ulong even = (limbs[0] & 1) - 1;
		ref ulong k = ref MemoryMarshal.GetReference(limbs);
		ref ulong sum = ref MemoryMarshal.GetReference(result);
		result[LimbCount] = AddLimbs(ref k, ref MemoryMarshal.GetReference(Order), even, ref sum, LimbCount);

		// k + eL is odd, so the shift drops only the 1 of k + eL − 1.
		for (int i = 0; i < CombLimbCount - 1; ++i)
		{
			result[i] = result[i] >> 1 | result[i + 1] << 63;
		}

		result[CombLimbCount - 1] >>= 1;
		result[digitCount - 1 >> 6] |= 1UL << (digitCount - 1 & 63);
	}

	// The t bits of k' at position, position + spacing, …, position + (t − 1)·spacing, least significant first. Only the position decides which limbs are read.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static uint CombIndex(ReadOnlySpan<ulong> limbs, int position, int spacing, int teeth)
	{
		uint index = 0;

		for (int m = 0; m < teeth; ++m)
		{
			int bit = position + m * spacing;
			index |= (uint)(limbs[bit >> 6] >> (bit & 63) & 1) << m;
		}

		return index;
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
