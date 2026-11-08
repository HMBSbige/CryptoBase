namespace CryptoBase.EllipticCurves.SM9;

// The sign-aligned recoding of four non-negative parts, as SM9Decomposition.DecomposeFrobenius gives them, for a product with four bases B0 to B3 through one table of the eight sums B0 + Σ_(j≥1) u_j·B_j (Faz-Hernández, Longa and Sánchez, "Efficient and secure algorithms for GLV-based scalar multiplication and their implementation on GLV–GLS curves", 2014, Algorithm 1): Σ_i 2^i·s_i·(B0 + Σ_j u_(i,j)·B_j) for digits s_i = ±1 of the odd k0, s_66 = 1, and bits u_(i,j) of the others aligned with them.
// Digit i of k0 is 2·(bit i + 1) − 1 below the top one, which sums to k0. Each other part takes the bit of its current value as u_(i,j), so that subtracting u_(i,j)·s_i leaves it even, and then halves; it stays non-negative and at most (x + 1)/2, so from below 2^66 it reaches 0 at the top digit, whose sign is +1.
// Each position packs u in bits 0 to 2 and a negative sign in bit 3. Only arithmetic on the parts decides the digits, and the positions they go to are fixed.
internal static class SM9FrobeniusRecoding
{
	// Enough for k0 below 2^67 and the other parts below 2^66.
	internal const int Length = 67;

	internal const int TableLength = 8;

	// k0 must be odd.
	internal static void Recode(UInt128 k0, UInt128 k1, UInt128 k2, UInt128 k3, Span<byte> digits)
	{
		Debug.Assert(digits.Length is Length && (k0 & 1) == 1);
		Debug.Assert(k0 >> Length == 0 && (k1 | k2 | k3) >> Length - 1 == 0);

		for (int i = 0; i < Length - 1; ++i)
		{
			// Negative where bit i + 1 is 0.
			digits[i] = (byte)(((uint)(k0 >> i + 1) & 1 ^ 1) << 3);
		}

		digits[Length - 1] = 0;
		Align(ref k1, digits, 0);
		Align(ref k2, digits, 1);
		Align(ref k3, digits, 2);

		Debug.Assert(k1 == 0 && k2 == 0 && k3 == 0);
	}

	// The parts are secret, so the halving and the carry take shifts and LimbArithmetic rather than the operators of UInt128, whose carries may compile to branches.
	private static void Align(ref UInt128 part, Span<byte> digits, int bit)
	{
		ulong low = (ulong)part;
		ulong high = (ulong)(part >> 64);

		for (int i = 0; i < Length; ++i)
		{
			uint u = (uint)low & 1;
			uint negative = (uint)digits[i] >> 3;
			digits[i] |= (byte)(u << bit);
			// A digit −1 is taken away by adding 1 before the halving, as ⌊−1/2⌋ = −1.
			ulong carry = 0;
			low = LimbArithmetic.AddWithCarry(low >> 1 | high << 63, u & negative, ref carry);
			high = (high >> 1) + carry;
		}

		part = new UInt128(high, low);
	}
}
