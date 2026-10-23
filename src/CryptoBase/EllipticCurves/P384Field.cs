using static CryptoBase.EllipticCurves.LimbArithmetic;

namespace CryptoBase.EllipticCurves;

// p = 2^384 - 2^128 - 2^96 + 2^32 - 1.
[InlineArray(6)]
internal struct P384Field : IMontgomeryModulus
{
	private ulong _limb;

	public static int LimbCount => 6;

	public static int ByteLength => 48;

	public static int BitLength => 384;

	public static ReadOnlySpan<ulong> Modulus =>
	[
		0x00000000FFFFFFFFUL, 0xFFFFFFFF00000000UL, 0xFFFFFFFFFFFFFFFEUL, 0xFFFFFFFFFFFFFFFFUL,
		0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
	];

	public static ReadOnlySpan<ulong> MontgomeryOne =>
	[
		0xFFFFFFFF00000001UL, 0x00000000FFFFFFFFUL, 0x0000000000000001UL, 0x0000000000000000UL,
		0x0000000000000000UL, 0x0000000000000000UL,
	];

	public static ReadOnlySpan<ulong> RSquared =>
	[
		0xFFFFFFFE00000001UL, 0x0000000200000000UL, 0xFFFFFFFE00000000UL, 0x0000000200000000UL,
		0x0000000000000001UL, 0x0000000000000000UL,
	];

	public static ulong NegativeInverse => 0x0000000100000001UL;

	// With x_k = x^(2^k − 1), the table holds x, x_2, x_3, x_6, x_12, x_15, x_30, x_60 and x_120. The power goes on through x_240 to x_255,
	// then runs through the rest of p − 2: a zero and 32 ones, 64 zeros and 30 ones, a zero and a one.
	public static ReadOnlySpan<byte> InversionChain =>
	[
		8,
		1, 0, 1, 0, 3, 2, 6, 3, 3, 2, 15, 5, 30, 6, 60, 7, 120, 8,
		15, 5, 31, 6, 2, 1, 94, 6, 2, 0,
	];

	// The q that clears limb i is t_i·(2^32 + 1) mod 2^64, and q·p = q·2^384 − q·d for d = 2^128 + 2^96 − 2^32 + 1. For x the six limbs
	// from limb i, x + q·p = (x − q·d) mod 2^384 + (q − β)·2^384 with β the borrow out of x − q·d, so a round subtracts q·d from x, which
	// clears limb i, and adds q − β at limb i + 6.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ulong Reduce<TSelf>(ref ulong product) where TSelf : struct, IMontgomeryModulus
	{
		ulong carry = 0;
		ReduceRound(ref product, ref carry);
		ReduceRound(ref Unsafe.Add(ref product, 1), ref carry);
		ReduceRound(ref Unsafe.Add(ref product, 2), ref carry);
		ReduceRound(ref Unsafe.Add(ref product, 3), ref carry);
		ReduceRound(ref Unsafe.Add(ref product, 4), ref carry);
		ReduceRound(ref Unsafe.Add(ref product, 5), ref carry);
		return carry;
	}

	// q = 0 subtracts nothing, so q − β does not wrap.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ReduceRound(ref ulong t, ref ulong carry)
	{
		ulong q = t + (t << 32);
		// q·d = (q − low) + (low − high)·2^64 + (q + high)·2^128 for q·2^32 = high·2^64 + low. Its limb 0 is t_0, which the subtraction
		// clears, so only the borrow out of it counts.
		ulong low = q << 32;
		ulong high = q >> 32;
		ulong borrow = Borrow(q, low);
		ulong d1 = SubtractWithBorrow(low, high, ref borrow);
		ulong sum = q + high;
		// sum is 0 only for q = 0 and q = 2^64 − 2^32 + 1, for which low − high does not borrow, so this does not wrap.
		ulong d2 = sum - borrow;
		ulong d3 = Carry(sum, q);
		borrow = 0;
		Unsafe.Add(ref t, 1) = SubtractWithBorrow(Unsafe.Add(ref t, 1), d1, ref borrow);
		Unsafe.Add(ref t, 2) = SubtractWithBorrow(Unsafe.Add(ref t, 2), d2, ref borrow);
		Unsafe.Add(ref t, 3) = SubtractWithBorrow(Unsafe.Add(ref t, 3), d3, ref borrow);
		Unsafe.Add(ref t, 4) = SubtractWithBorrow(Unsafe.Add(ref t, 4), 0, ref borrow);
		Unsafe.Add(ref t, 5) = SubtractWithBorrow(Unsafe.Add(ref t, 5), 0, ref borrow);
		Unsafe.Add(ref t, 6) = AddWithCarry(Unsafe.Add(ref t, 6), q - borrow, ref carry);
	}
}
