using static CryptoBase.EllipticCurves.LimbArithmetic;

namespace CryptoBase.EllipticCurves;

// p = 2^384 - 2^128 - 2^96 + 2^32 - 1.
[InlineArray(6)]
internal struct P384Field : ISaturatedField<P384Field>
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

	// The q that clears limb i is t_i·(2^32 + 1) mod 2^64, and q·p = q·2^384 − q·d for d = 2^128 + 2^96 − 2^32 + 1. For x the six limbs from limb i, x + q·p = (x − q·d) mod 2^384 + (q − β)·2^384 with β the borrow out of x − q·d, so a round subtracts q·d from x, which clears limb i, and adds q − β at limb i + 6.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ulong Reduce<TSelf>(ref ulong product) where TSelf : struct, IMontgomeryModulus
	{
		ulong carry = 0;
		ReduceRound(product, ref Unsafe.Add(ref product, 1), ref Unsafe.Add(ref product, 2), ref Unsafe.Add(ref product, 3), ref Unsafe.Add(ref product, 4), ref Unsafe.Add(ref product, 5), ref Unsafe.Add(ref product, 6), ref carry);
		ReduceRound(Unsafe.Add(ref product, 1), ref Unsafe.Add(ref product, 2), ref Unsafe.Add(ref product, 3), ref Unsafe.Add(ref product, 4), ref Unsafe.Add(ref product, 5), ref Unsafe.Add(ref product, 6), ref Unsafe.Add(ref product, 7), ref carry);
		ReduceRound(Unsafe.Add(ref product, 2), ref Unsafe.Add(ref product, 3), ref Unsafe.Add(ref product, 4), ref Unsafe.Add(ref product, 5), ref Unsafe.Add(ref product, 6), ref Unsafe.Add(ref product, 7), ref Unsafe.Add(ref product, 8), ref carry);
		ReduceRound(Unsafe.Add(ref product, 3), ref Unsafe.Add(ref product, 4), ref Unsafe.Add(ref product, 5), ref Unsafe.Add(ref product, 6), ref Unsafe.Add(ref product, 7), ref Unsafe.Add(ref product, 8), ref Unsafe.Add(ref product, 9), ref carry);
		ReduceRound(Unsafe.Add(ref product, 4), ref Unsafe.Add(ref product, 5), ref Unsafe.Add(ref product, 6), ref Unsafe.Add(ref product, 7), ref Unsafe.Add(ref product, 8), ref Unsafe.Add(ref product, 9), ref Unsafe.Add(ref product, 10), ref carry);
		ReduceRound(Unsafe.Add(ref product, 5), ref Unsafe.Add(ref product, 6), ref Unsafe.Add(ref product, 7), ref Unsafe.Add(ref product, 8), ref Unsafe.Add(ref product, 9), ref Unsafe.Add(ref product, 10), ref Unsafe.Add(ref product, 11), ref carry);
		return carry;
	}

	// The product and the rounds of Reduce in locals rather than in memory. Not inlined, as for P256Field.
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void Multiply<TSelf>(ref ulong x, ref ulong y, ref ulong result) where TSelf : struct, IMontgomeryModulus
	{
		MultiplyLimbs(ref x, ref y, out ulong t0, out ulong t1, out ulong t2, out ulong t3, out ulong t4, out ulong t5, out ulong t6, out ulong t7, out ulong t8, out ulong t9, out ulong t10, out ulong t11);
		Reduce(t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, ref result);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void Square<TSelf>(ref ulong x, ref ulong result) where TSelf : struct, IMontgomeryModulus
	{
		SquareLimbs(ref x, out ulong t0, out ulong t1, out ulong t2, out ulong t3, out ulong t4, out ulong t5, out ulong t6, out ulong t7, out ulong t8, out ulong t9, out ulong t10, out ulong t11);
		Reduce(t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, ref result);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Reduce(ulong t0, ulong t1, ulong t2, ulong t3, ulong t4, ulong t5, ulong t6, ulong t7, ulong t8, ulong t9, ulong t10, ulong t11, ref ulong result)
	{
		ulong carry = 0;
		ReduceRound(t0, ref t1, ref t2, ref t3, ref t4, ref t5, ref t6, ref carry);
		ReduceRound(t1, ref t2, ref t3, ref t4, ref t5, ref t6, ref t7, ref carry);
		ReduceRound(t2, ref t3, ref t4, ref t5, ref t6, ref t7, ref t8, ref carry);
		ReduceRound(t3, ref t4, ref t5, ref t6, ref t7, ref t8, ref t9, ref carry);
		ReduceRound(t4, ref t5, ref t6, ref t7, ref t8, ref t9, ref t10, ref carry);
		ReduceRound(t5, ref t6, ref t7, ref t8, ref t9, ref t10, ref t11, ref carry);
		FieldElement<P384Field>.ReduceOnce(t6, t7, t8, t9, t10, t11, carry, ref result);
	}

	// Clears t0 from t0 to t6. q = 0 subtracts nothing, so q − β does not wrap.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ReduceRound(ulong t0, ref ulong t1, ref ulong t2, ref ulong t3, ref ulong t4, ref ulong t5, ref ulong t6, ref ulong carry)
	{
		ulong q = t0 + (t0 << 32);
		// q·d = (q − low) + (low − high)·2^64 + (q + high)·2^128 for q·2^32 = high·2^64 + low. Its limb 0 is t_0, which the subtraction clears, so only the borrow out of it counts.
		ulong low = q << 32;
		ulong high = q >> 32;
		ulong borrow = Borrow(q, low);
		ulong d1 = SubtractWithBorrow(low, high, ref borrow);
		ulong sum = q + high;
		// sum is 0 only for q = 0 and q = 2^64 − 2^32 + 1, for which low − high does not borrow, so this does not wrap.
		ulong d2 = sum - borrow;
		ulong d3 = Carry(sum, q);
		borrow = 0;
		t1 = SubtractWithBorrow(t1, d1, ref borrow);
		t2 = SubtractWithBorrow(t2, d2, ref borrow);
		t3 = SubtractWithBorrow(t3, d3, ref borrow);
		t4 = SubtractWithBorrow(t4, 0, ref borrow);
		t5 = SubtractWithBorrow(t5, 0, ref borrow);
		t6 = AddWithCarry(t6, q - borrow, ref carry);
	}
}
