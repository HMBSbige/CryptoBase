using static CryptoBase.EllipticCurves.LimbArithmetic;

namespace CryptoBase.EllipticCurves;

// p = 2^521 - 1.
[InlineArray(9)]
internal struct P521Field : IMontgomeryModulus
{
	private ulong _limb;

	public static int LimbCount => 9;

	public static int ByteLength => 66;

	public static int BitLength => 521;

	public static ReadOnlySpan<ulong> Modulus =>
	[
		0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
		0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
		0x00000000000001FFUL,
	];

	public static ReadOnlySpan<ulong> MontgomeryOne =>
	[
		0x0080000000000000UL, 0x0000000000000000UL, 0x0000000000000000UL, 0x0000000000000000UL,
		0x0000000000000000UL, 0x0000000000000000UL, 0x0000000000000000UL, 0x0000000000000000UL,
		0x0000000000000000UL,
	];

	public static ReadOnlySpan<ulong> RSquared =>
	[
		0x0000000000000000UL, 0x0000400000000000UL, 0x0000000000000000UL, 0x0000000000000000UL,
		0x0000000000000000UL, 0x0000000000000000UL, 0x0000000000000000UL, 0x0000000000000000UL,
		0x0000000000000000UL,
	];

	public static ulong NegativeInverse => 0x0000000000000001UL;

	// With x_k = x^(2^k − 1), the table holds x, x_2, x_4 and so on up to x_128. The power goes on to x_512 by 128 ones at a time and to x_519 by 4, 2 and 1, then ends p − 2 = 2^521 − 3 with a zero and a one.
	public static ReadOnlySpan<byte> InversionChain =>
	[
		7,
		1, 0, 2, 1, 4, 2, 8, 3, 16, 4, 32, 5, 64, 6,
		128, 7, 128, 7, 128, 7, 4, 2, 2, 1, 1, 0, 2, 0,
	];

	// R = 2^576 ≡ 2^55, so the reduction is a rotation rather than Montgomery rounds. With h the upper half of t and a·2^55 + b the lower, b < 2^55, t·R⁻¹ ≡ h + a + b·2^466 since 2^−55 ≡ 2^466. v = a + b·2^466 < 2^522 differs from a only in limbs 7 and 8, which give its bit f at 2^521 before the sum, and v ≡ v − f·2^521 + f. The sum h + (v − f·2^521) + f is below 2p: h ≤ p − 1, and v − 2^521 is below 2^521 − 2^466 if f = 1 and v below 2^521 otherwise. It fits the upper limbs with no carry.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ulong Reduce<TSelf>(ref ulong product) where TSelf : struct, IMontgomeryModulus
	{
		ulong t0 = product;
		ulong t8 = Unsafe.Add(ref product, 8);
		// Limbs 7 and 8 of v: those of a, t_7 >> 55 | t_8 << 9 and t_8 >> 55, plus those of b·2^466, t_0 << 18 and b >> 46.
		ulong low = t0 << 18;
		ulong v7 = (Unsafe.Add(ref product, 7) >> 55 | t8 << 9) + low;
		ulong v8 = (t8 >> 55) + (t0 >> 46 & 0x1FF) + Carry(v7, low);
		// f goes into the sum as the carry into limb 0.
		ulong carry = v8 >> 9;
		AddShifted(ref product, 0, ref carry);
		AddShifted(ref product, 1, ref carry);
		AddShifted(ref product, 2, ref carry);
		AddShifted(ref product, 3, ref carry);
		AddShifted(ref product, 4, ref carry);
		AddShifted(ref product, 5, ref carry);
		AddShifted(ref product, 6, ref carry);
		ref ulong h7 = ref Unsafe.Add(ref product, 16);
		h7 = AddWithCarry(h7, v7, ref carry);
		Unsafe.Add(ref h7, 1) += (v8 & 0x1FF) + carry;
		return 0;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void AddShifted(ref ulong t, int i, ref ulong carry)
	{
		ref ulong h = ref Unsafe.Add(ref t, 9 + i);
		h = AddWithCarry(h, Unsafe.Add(ref t, i) >> 55 | Unsafe.Add(ref t, i + 1) << 9, ref carry);
	}
}
