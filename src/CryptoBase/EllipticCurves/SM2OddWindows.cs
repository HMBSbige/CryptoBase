using static CryptoBase.EllipticCurves.LimbArithmetic;

namespace CryptoBase.EllipticCurves;

// The windows of k·P on the two chains of SM2OctoFormulas, whose digits are all odd: for s below 2^260 with bits s_j, the sum of (2s_j − 1)·2^j over j < 260 is 2s − (2^260 − 1), and window i of 5 bits of s, of value w_i, makes the digit d_i = 2w_i − 31, odd and in [−31, 31], so that K = Σ d_i·32^i = 2s − (2^260 − 1). For s = (k + 2^260 − 1)/2 mod n, K ≡ k (mod n). A digit d takes entry (|d| − 1)/2 of a table of P, 3P, …, 31P, negated below 0. No digit is 0, and the digits from the top of a chain down to any window sum to an odd value, never 0, so the windows need no masks for a digit of 0 or for the point at infinity.
internal static class SM2OddWindows
{
	internal const int Width = 5;

	internal const int Count = 52;

	// The digits of a chain of SM2OctoFormulas.
	internal const int HalfCount = Count / 2;

	// (2^260 − 1) mod n.
	private static ReadOnlySpan<ulong> Offset => [0xC440BF6C62ABEDCFUL, 0xDFC2094DE39FAD4AUL, 0x0000000000000008UL, 0x0000001000000000UL];

	// (n + 1)/2, the inverse of 2 mod n.
	private static ReadOnlySpan<ulong> Half => [0xA9DDFA049CEAA092UL, 0xB901EFB590E30295UL, 0xFFFFFFFFFFFFFFFFUL, 0x7FFFFFFF7FFFFFFFUL];

	// The one k at which the sums of the chains of SM2OctoFormulas are equal points for s below n.
	private static ReadOnlySpan<ulong> Exception => [0xD0069914C6FDA21AUL, 0x5C742E8DF5349B13UL, 0x0000000000000007UL, 0x0000000000000000UL];

	// Writes the Count digits of k from s = (k + 2^260 − 1)/2 mod n, which takes n more at Exception: s stays below 2n < 2^260 and K moves by 2n, so K ≡ k (mod n) still. The arithmetic takes the same steps for every k, with masks for the reduction and the exception, and the intermediates are cleared.
	[SkipLocalsInit]
	internal static void Recode(in FieldElement<SM2Order> scalar, Span<sbyte> digits)
	{
		Debug.Assert(digits.Length is Count);

		ReadOnlySpan<ulong> k = FieldElement<SM2Order>.GetLimbs(in scalar);
		ReadOnlySpan<ulong> n = SM2Order.Modulus;
		ReadOnlySpan<ulong> exception = Exception;
		Span<ulong> limbs = stackalloc ulong[9];
		Span<ulong> s = limbs.Slice(0, 5);
		Span<ulong> t = limbs.Slice(5, 4);
		// t = k + Offset mod n: the sum is below 2n, and at least n where it carries or n does not borrow from it.
		ulong carry = AddLimbs(ref MemoryMarshal.GetReference(k), ref MemoryMarshal.GetReference(Offset), ulong.MaxValue, ref t[0], 4);
		ulong borrow = SubtractLimbs(ref t[0], ref MemoryMarshal.GetReference(n), ref s[0], 4);
		SelectLimbs(0 - (carry | borrow ^ 1), ref s[0], ref t[0], ref t[0], 4);
		// s = t/2 mod n: ⌊t/2⌋, plus (n + 1)/2 for an odd t, below n.
		ulong odd = 0 - (t[0] & 1);
		s[0] = t[0] >> 1 | t[1] << 63;
		s[1] = t[1] >> 1 | t[2] << 63;
		s[2] = t[2] >> 1 | t[3] << 63;
		s[3] = t[3] >> 1;
		_ = AddLimbs(ref s[0], ref MemoryMarshal.GetReference(Half), odd, ref s[0], 4);
		ulong mask = ZeroMask(k[0] ^ exception[0] | k[1] ^ exception[1] | k[2] ^ exception[2] | k[3] ^ exception[3]);
		s[4] = AddLimbs(ref s[0], ref MemoryMarshal.GetReference(n), mask, ref s[0], 4);

		for (int i = 0; i < Count; ++i)
		{
			digits[i] = (sbyte)(2 * ((int)ReadBits(s, Width * i) & (1 << Width) - 1) - (1 << Width) + 1);
		}

		limbs.ZeroMemory();
	}

	// Writes the HalfCount digits of an odd k below 2^128, whose sum is k itself: s = (k + 2^130 − 1)/2 = 2^129 + (k − 1)/2 holds the bits of (k − 1)/2, below 2^127, then 0 at bits 127 and 128 and 1 at bit 129, so that K = 2s − (2^130 − 1) = k.
	internal static void RecodeHalf(UInt128 scalar, Span<sbyte> digits)
	{
		Debug.Assert(digits.Length is HalfCount && (scalar & 1) == 1);

		UInt128 half = scalar >> 1;

		for (int i = 0; i < HalfCount - 1; ++i)
		{
			digits[i] = (sbyte)(2 * ((int)(half >> Width * i) & (1 << Width) - 1) - (1 << Width) + 1);
		}

		digits[HalfCount - 1] = (sbyte)(2 * ((int)(half >> Width * (HalfCount - 1)) | 1 << Width - 1) - (1 << Width) + 1);
	}
}
