namespace CryptoBase.EllipticCurves;

// The field of p = 2^256 − 2^224 − 2^96 + 2^64 − 1 in lanes, as the implementations of ISM2Field29Lanes hold it: each lane of nine vectors L0 to L8 holds one element in unsaturated limbs of radix 2^29, value Σ L_i·2^(29i), with the Montgomery R = 2^261, twice the R of SM2Field52. As p ≡ −1 (mod 2^29), Montgomery reduction needs no multiplication. Every limb stays non-negative, so every shift is logical, which the vectors of x64 have at every width.
// Multiply takes limbs below X on the left and Y on the right with 9·X·Y ≤ 2^64 − 2^54, about 7.1·2^58, and X and Y at most 2^32, as the multipliers read 32 bits: limbs below 2^30 + 2^8 on both sides, or below 7·2^29 against limbs below 2^29 + 65, as a product of values below 2^260 has. It gives limbs 0 and 1 below 2^29, limbs 2 to 7 below 2^29 + 65 and a value below x·y/2^261 + p + 2^226, which bounds limb 8. Row k gathers limb k of the right operand against every limb of the left one; column k is complete after row k, so Montgomery round k follows it: q = t_k mod 2^29, t_k carries into t_(k + 1), and q·(p + 1) = q·(2^256 − 2^224 − 2^96 + 2^64) adds q·2^6 to column k + 2 and q·2^24 to column k + 8 and takes q·2^9 from column k + 3 and q·2^21 from column k + 7. Columns 9 to 16 then carry into the result in two steps, each limb at once: the first leaves limbs below 2^29 + 2^35 and the second below 2^29 + 65, limb 8 taking what both carry out of column 16. The result is (x·y + B + Q·p)/2^261 for some 0 ≤ Q < 2^261 and the bias B below.
// To keep each column non-negative, the columns start with the digits of B = 2^231·p, each from 3 to 15 at least 2^51, above the q·2^9 + q·2^21 < 2^50 + 2^38 that a column loses; B adds less than 2^226 to the result. A column holds at most nine products below X·Y, its digit of B, at most 2^52, q·2^24 < 2^53, q·2^6 < 2^35 and a carry below 2^35, so below 2^64. Square takes limbs below 2^30 + 2^8, with y_i·2y_j for i < j and 2y_j below 2^31 + 2^9, so that each column holds what one of Multiply would; a column that the spreads of a round reach before any product starts from its digit of B.
// Add adds limbs without carries. Subtract adds 4p in limbs at least 2^29 + 254 for limbs 0 to 7 and 2^26 − 2 for limb 8, so its subtrahend must have limbs no larger, which the products give for values below 2^258 − 2^232, and each limb grows by less than 2^30; ConditionalNegate takes the same 4p for values with limbs no larger, such as those of LoadEntries. Reduce takes limbs 0 to 7 below 2^32 and limb 8 below 2^36: it subtracts h·p for h = L8 >> 24, the value from bit 256 up, as h·2^256 − h·(2^224 + 2^96 − 2^64 + 1), so that h·2^256 comes off limb 8 and the rest goes in as h·2^21 at limb 7, h·(2^38 − 2^6) at limb 2 and h at limb 0, all below 2^50; the limbs below 8 then carry up, limbs 0 to 7 below 2^29 and limb 8 below 2^24 + 2^5, as limb 7 and h·2^21 carry less than 2^5 into it, so the value is below 2^256 plus the lower limbs, below 2p.
// LoadEntries takes the values v below p that SM2Field52.Pack writes, v = a·2^260 mod p, and gives 2v = a·2^261 mod 2p, the limbs of 2v below 2^29 and limb 8 below 2^25. Halve goes back: for limbs below 2^63 it adds p to an odd value, which leaves the value even, and halves each limb, bit 0 of the limb above going in as its bit 28, so that the value is exactly half and limb i is below (L_i + p_i)/2 + 2^28, for Reduce. ToField52 then joins the limbs that Reduce leaves, disjoint in their bits, into those of SM2Field52 as the same integer.
internal static class SM2Field29
{
	internal const int Bits = 29;

	internal const ulong Mask = (1UL << Bits) - 1;

	// The bits of limb 8 below 2^256.
	internal const ulong TopMask = (1UL << 24) - 1;

	// The digits b_k of B = 2^231·p at column k: as 2^231·p = 2^487 − 2^455 − 2^327 + 2^295 − 2^231, each column from 3 to 15 borrows 2^23·2^29 from the one above it, b_3 = 2^52 and b_k = 2^52 − 2^23 for k from 4 to 15, less 2^28 at 7, 2^8 at 11 and 2^20 at 15 and plus 2^5 at 10, and b_16 = 2^23 − 2^23 = 0.
	internal const ulong Bias3 = 1UL << 52;
	internal const ulong BiasMiddle = (1UL << 52) - (1UL << 23);
	internal const ulong Bias7 = BiasMiddle - (1UL << 28);
	internal const ulong Bias10 = BiasMiddle + (1UL << 5);
	internal const ulong Bias11 = BiasMiddle - (1UL << 8);
	internal const ulong Bias15 = BiasMiddle - (1UL << 20);

	// 4p in limbs at least 2^29 + 254 for limbs 0 to 7 and limb 8 at 2^26 − 2: the limbs of 4p, each but limb 8 borrowing 2^29 from the one above it.
	internal const ulong FourP0 = 0x3FFFFFFC;
	internal const ulong FourP1 = 0x3FFFFFFE;
	internal const ulong FourP2 = 0x200000FE;
	internal const ulong FourP3 = 0x3FFFF7FF;
	internal const ulong FourPMiddle = 0x3FFFFFFE;
	internal const ulong FourP7 = 0x3F7FFFFE;
	internal const ulong FourP8 = 0x3FFFFFE;

	// The same 4p with limb 2 borrowing a further 2^29 from limb 3, for the differences of products that a fold takes: a + 4p − b for limbs of b no larger than those of a product keeps limb 2 at least 2^29 + 190, more than the h·2^6 that the fold of h = L8 >> 24 takes from it, and limb 3 at least 2^29 − 2114.
	internal const ulong FourPFold2 = FourP2 + (1UL << Bits);
	internal const ulong FourPFold3 = FourP3 - 1;

	// 2^261 mod p = 2^229 + 2^101 − 2^69 + 2^5, 1 in Montgomery form.
	internal const ulong One0 = 1UL << 5;
	internal const ulong One2 = (1UL << 29) - (1UL << 11);
	internal const ulong One3 = (1UL << 14) - 1;
	internal const ulong One7 = 1UL << 26;

	// The limbs of p: 2^29 − 1 at limbs 0, 1 and 4 to 6, and the others.
	internal const ulong PLow = Mask;
	internal const ulong P2 = 0x3F;
	internal const ulong P3 = 0x1FFFFE00;
	internal const ulong P7 = 0x1FDFFFFF;
	internal const ulong P8 = 0xFFFFFF;

	private const ulong Mask52 = (1UL << 52) - 1;

	// The value of nine limbs stride ulongs apart, as Reduce leaves them, limbs 0 to 7 below 2^29 and limb 8 below 2^25, in the limbs of SM2Field52 as the same integer, below 2p in limbs 0 to 3 below 2^52 and limb 4 below 2^49. As the lanes hold a·2^261 and SM2Field52 a·2^260, an element of the lanes goes through Halve and Reduce first.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void ToField52(ref readonly ulong limbs, int stride, out SM2Field52 result)
	{
		ref ulong w = ref Unsafe.AsRef(in limbs);
		ulong w1 = Unsafe.Add(ref w, stride);
		ulong w3 = Unsafe.Add(ref w, 3 * stride);
		ulong w5 = Unsafe.Add(ref w, 5 * stride);
		ulong w7 = Unsafe.Add(ref w, 7 * stride);
		result.L0 = (w | w1 << 29) & Mask52;
		result.L1 = (w1 >> 23 | Unsafe.Add(ref w, 2 * stride) << 6 | w3 << 35) & Mask52;
		result.L2 = (w3 >> 17 | Unsafe.Add(ref w, 4 * stride) << 12 | w5 << 41) & Mask52;
		result.L3 = (w5 >> 11 | Unsafe.Add(ref w, 6 * stride) << 18 | w7 << 47) & Mask52;
		result.L4 = w7 >> 5 | Unsafe.Add(ref w, 8 * stride) << 24;
	}

	// Limb i of every lane lies in the LaneCount ulongs from i·LaneCount on, as the nine vectors hold them.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void ToField52<TField>(in TField value, int lane, out SM2Field52 result) where TField : unmanaged, ISM2Field29Lanes<TField>
	{
		ToField52(in Unsafe.Add(ref Unsafe.As<TField, ulong>(ref Unsafe.AsRef(in value)), lane), TField.LaneCount, out result);
	}
}

// How a product carries columns 9 to 16 into the limbs of the result: in two steps that carry every column at once, or in one pass from limb 0 up, which takes fewer operations but gives the top limbs later. A product that the next step waits for takes the first, and one among products that need not wait for each other the second.
internal interface ISM2Carry
{
	static abstract bool Ripples { get; }
}

internal readonly struct TwoStepCarry : ISM2Carry
{
	public static bool Ripples => false;
}

internal readonly struct RippleCarry : ISM2Carry
{
	public static bool Ripples => true;
}
