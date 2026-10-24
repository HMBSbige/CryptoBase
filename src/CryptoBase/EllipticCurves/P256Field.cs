using static CryptoBase.EllipticCurves.LimbArithmetic;

namespace CryptoBase.EllipticCurves;

// p = 2^256 - 2^224 + 2^192 + 2^96 - 1.
[InlineArray(4)]
internal struct P256Field : IMontgomeryModulus
{
	private ulong _limb;

	public static int LimbCount => 4;

	public static int ByteLength => 32;

	public static int BitLength => 256;

	public static ReadOnlySpan<ulong> Modulus =>
	[
		0xFFFFFFFFFFFFFFFFUL, 0x00000000FFFFFFFFUL, 0x0000000000000000UL, 0xFFFFFFFF00000001UL,
	];

	public static ReadOnlySpan<ulong> MontgomeryOne =>
	[
		0x0000000000000001UL, 0xFFFFFFFF00000000UL, 0xFFFFFFFFFFFFFFFFUL, 0x00000000FFFFFFFEUL,
	];

	public static ReadOnlySpan<ulong> RSquared =>
	[
		0x0000000000000003UL, 0xFFFFFFFBFFFFFFFFUL, 0xFFFFFFFFFFFFFFFEUL, 0x00000004FFFFFFFDUL,
	];

	public static ulong NegativeInverse => 0x0000000000000001UL;

	// With x_k = x^(2^k − 1), the table holds x, x_2, x_4, x_8, x_16 and x_32. From x_32, the power runs through the rest of p − 2: 31 zeros and a one, 96 zeros, 94 ones, a zero and a one.
	public static ReadOnlySpan<byte> InversionChain =>
	[
		5,
		1, 0, 2, 1, 4, 2, 8, 3, 16, 4,
		32, 0, 128, 5, 32, 5, 16, 4, 8, 3, 4, 2, 2, 1, 2, 0,
	];

	// p ≡ −1 mod 2^64, so the q that clears limb i is t_i, and q·p = q·2^192·(2^64 − 2^32 + 1) + q·2^96 − q. The −q cancels limb i, q·2^96 is q shifted into limbs i + 1 and i + 2, and the rest is one product at limbs i + 3 and i + 4.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ulong Reduce<TSelf>(ref ulong product) where TSelf : struct, IMontgomeryModulus
	{
		ulong carry = 0;
		ReduceRound(ref product, ref carry);
		ReduceRound(ref Unsafe.Add(ref product, 1), ref carry);
		ReduceRound(ref Unsafe.Add(ref product, 2), ref carry);
		ReduceRound(ref Unsafe.Add(ref product, 3), ref carry);
		return carry;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ReduceRound(ref ulong t, ref ulong carry)
	{
		ulong q = t;
		ulong low = q << 32;
		ulong t1 = Unsafe.Add(ref t, 1) + low;
		// Below 2^32 + 1.
		ulong high = (q >> 32) + Carry(t1, low);
		ulong t2 = Unsafe.Add(ref t, 2) + high;
		ulong top = MultiplyAdd(q, 0xFFFFFFFF00000001UL, Unsafe.Add(ref t, 3), Carry(t2, high), out ulong t3);
		Unsafe.Add(ref t, 1) = t1;
		Unsafe.Add(ref t, 2) = t2;
		Unsafe.Add(ref t, 3) = t3;
		Unsafe.Add(ref t, 4) = AddWithCarry(Unsafe.Add(ref t, 4), top, ref carry);
	}
}
