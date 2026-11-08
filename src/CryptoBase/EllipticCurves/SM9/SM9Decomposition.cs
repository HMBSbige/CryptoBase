using static CryptoBase.EllipticCurves.LimbArithmetic;

namespace CryptoBase.EllipticCurves.SM9;

// Splits a plain scalar k below N into short parts by Babai rounding against short bases B of the lattices {v : Σ v_i·λ^i ≡ 0 (mod N)}, for the endomorphism of G1, φ(x, y) = (βx, y) = [λ]P, and for the Frobenius, which acts on GT as p. With r the first row of N·B⁻¹, the parts are (k, 0, …) − Σ_j β_j·B_j for β_j = round(k·r_j/N), which g_j = round(2^320·r_j/N) gives as ⌊(k·g_j + 2^319)/2^320⌋: k·g_j/2^320 lies within 2^−65 of k·r_j/N, so |k·r_j/N − β_j| ≤ 1/2 + 2^−65 and part i is at most (1/2 + 2^−65)·Σ_j |B_j,i| in magnitude. That keeps the parts within 128 bits, where they are computed modulo 2^128.
// Neither the time nor the addresses depend on k, and the products are erased.
internal static class SM9Decomposition
{
	// The basis of G1 is (−c, −b) and (−b, a) for a = 6t² + 2t, b = 2t + 1 and c = 6t² + 4t + 1, as c + bλ ≡ 0 and b − aλ ≡ 0; r = (−a, −b), so with β0 = round(k·a/N) and β1 = round(k·b/N) the parts are k1 = k − β0·c − β1·b and k2 = β1·a − β0·b, at most (1/2 + 2^−65)·(b + c) and (1/2 + 2^−65)·(a + b) in magnitude, both below 2^126.76.
	private static readonly UInt128 A = new(0xD8000000019062ED, 0xC000B98B0D64696C);

	private static readonly UInt128 B = 0xC000000000B1F315;

	private static readonly UInt128 C = new(0xD8000000019062EE, 0x8000B98B0E165C81);

	private static ReadOnlySpan<ulong> G1RoundA => [0xC14BC82C22D12982, 0x7600F27C8B6E04A8, 0x2F684BDA10C41C30, 0x0000000000000001];

	private static ReadOnlySpan<ulong> G1RoundB => [0x4B859AF419E19310, 0x0DB20A88F17B78D1, 0x0000000000000001, 0x0000000000000000];

	// The basis of the Frobenius: B0 = (2t + 1, 0, 2t, 1), B1 = (2t, t + 1, −t, t), B2 = (t + 1, t, t, −2t) and B3 = (2t + 1, −t, −(t + 1), −t), each of Σ B_j,i·p^i ≡ 0 (mod N) and of determinant −N. The parts are then below 3.5t + 2, 1.5t + 1, 2.5t + 1 and 2t + 1 in magnitude.
	private const ulong T = 0x600000000058F98A;

	private static ReadOnlySpan<ulong> FrobeniusRound0 => [0x72EDBC8E210396A3, 0x7EE62E24005A094E, 0x097BA41AE3EC39C4, 0x71C71C71C6B2FE2D];

	private static ReadOnlySpan<ulong> FrobeniusRound1 => [0xBFAB2DEDE6ED506B, 0x820C3662FC2E483D, 0xDA135840D3281D93, 0x71C71C71C6B2FE2B];

	private static ReadOnlySpan<ulong> FrobeniusRound2 => [0x4B859AF419E19310, 0x0DB20A88F17B78D1, 0x0000000000000001, 0x0000000000000000];

	private static ReadOnlySpan<ulong> FrobeniusRound3 => [0x80F6F61A09BE79EE, 0xF80D28DF879C4CE6, 0x097BA41AE3EC39C3, 0x71C71C71C6B2FE2D];

	// k = k1 + k2·λ (mod N), the parts in two's complement, each below 2^127 in magnitude.
	[SkipLocalsInit]
	internal static void DecomposeG1(in FieldElement<SM9Order> scalar, out UInt128 k1, out UInt128 k2)
	{
		ReadOnlySpan<ulong> k = FieldElement<SM9Order>.GetLimbs(in scalar);
		UInt128 beta0 = RoundedQuotient(k, G1RoundA);
		UInt128 beta1 = RoundedQuotient(k, G1RoundB);
		UInt128 low = new(k[1], k[0]);
		k1 = Subtract(Subtract(low, Multiply(beta0, C)), Multiply(beta1, B));
		k2 = Subtract(Multiply(beta1, A), Multiply(beta0, B));
	}

	// k = Σ k_i·p^i (mod N) with every part non-negative: the rounded parts plus those of 3·(B0 + B1) = (12t + 3, 3t + 3, 3t, 3t + 3), itself ≡ 0, which lifts each above 0 and leaves k0 below 15.5t + 5 < 2^67 and the others below 5.5t + 4 < 2^66.
	[SkipLocalsInit]
	internal static void DecomposeFrobenius(in FieldElement<SM9Order> scalar, out UInt128 k0, out UInt128 k1, out UInt128 k2, out UInt128 k3)
	{
		ReadOnlySpan<ulong> k = FieldElement<SM9Order>.GetLimbs(in scalar);
		UInt128 beta0 = RoundedQuotient(k, FrobeniusRound0);
		UInt128 beta1 = RoundedQuotient(k, FrobeniusRound1);
		UInt128 beta2 = RoundedQuotient(k, FrobeniusRound2);
		UInt128 beta3 = RoundedQuotient(k, FrobeniusRound3);
		UInt128 low = new(k[1], k[0]);
		UInt128 t = T;
		UInt128 twoT = 2 * T;
		UInt128 sum = Add(Add(Multiply(beta0, twoT + 1), Multiply(beta1, twoT)), Add(Multiply(beta2, t + 1), Multiply(beta3, twoT + 1)));
		k0 = Add(Subtract(low, sum), 12 * t + 3);
		sum = Add(Multiply(beta1, t + 1), Multiply(beta2, t));
		k1 = Add(Subtract(Multiply(beta3, t), sum), 3 * t + 3);
		sum = Add(Multiply(beta0, twoT), Multiply(beta2, t));
		k2 = Add(Subtract(Add(Multiply(beta1, t), Multiply(beta3, t + 1)), sum), 3 * t);
		sum = Add(beta0, Multiply(beta1, t));
		k3 = Add(Subtract(Add(Multiply(beta2, twoT), Multiply(beta3, t)), sum), 3 * t + 3);
	}

	// Arithmetic modulo 2^128 on secret values through the carries of LimbArithmetic, which compile to flag reads rather than branches.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static UInt128 Add(UInt128 left, UInt128 right)
	{
		ulong carry = 0;
		ulong low = AddWithCarry((ulong)left, (ulong)right, ref carry);
		ulong high = AddWithCarry((ulong)(left >> 64), (ulong)(right >> 64), ref carry);
		return new UInt128(high, low);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static UInt128 Subtract(UInt128 left, UInt128 right)
	{
		ulong borrow = 0;
		ulong low = SubtractWithBorrow((ulong)left, (ulong)right, ref borrow);
		ulong high = SubtractWithBorrow((ulong)(left >> 64), (ulong)(right >> 64), ref borrow);
		return new UInt128(high, low);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static UInt128 Multiply(UInt128 left, UInt128 right)
	{
		ulong x = (ulong)left;
		ulong y = (ulong)right;
		ulong high = LimbArithmetic.Multiply(x, y, out ulong low) + (ulong)(left >> 64) * y + x * (ulong)(right >> 64);
		return new UInt128(high, low);
	}

	// ⌊(k·g + 2^319)/2^320⌋ modulo 2^128: limbs 5 and 6 of the sum.
	[SkipLocalsInit]
	private static UInt128 RoundedQuotient(ReadOnlySpan<ulong> k, ReadOnlySpan<ulong> g)
	{
		Span<ulong> product = stackalloc ulong[8];
		ref ulong x = ref MemoryMarshal.GetReference(k);
		ref ulong t = ref MemoryMarshal.GetReference(product);
		Unsafe.Add(ref t, 4) = MultiplyLimbs(ref x, g[0], ref t, 4);
		Unsafe.Add(ref t, 5) = MultiplyAddLimbs(ref x, g[1], ref Unsafe.Add(ref t, 1), 4);
		Unsafe.Add(ref t, 6) = MultiplyAddLimbs(ref x, g[2], ref Unsafe.Add(ref t, 2), 4);
		Unsafe.Add(ref t, 7) = MultiplyAddLimbs(ref x, g[3], ref Unsafe.Add(ref t, 3), 4);
		ulong carry = 0;
		_ = AddWithCarry(product[4], 1UL << 63, ref carry);
		ulong low = AddWithCarry(product[5], 0, ref carry);
		ulong high = AddWithCarry(product[6], 0, ref carry);
		product.ZeroMemory();
		return new UInt128(high, low);
	}
}
