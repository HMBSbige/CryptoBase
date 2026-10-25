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

	// p ≡ −1 mod 2^64, so the q that clears limb i is t_i, and q·p = q·2^192·(2^64 − 2^32 + 1) + q·2^96 − q. The −q cancels limb i, q·2^96 is q shifted into limbs i + 1 and i + 2, and the rest goes into limbs i + 3 and i + 4.
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

	// The product and the rounds of Reduce in locals, which stay in registers, rather than in memory. Not inlined, as for FieldElement.MontgomeryMultiply.
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void Multiply<TSelf>(ref ulong x, ref ulong y, ref ulong result) where TSelf : struct, IMontgomeryModulus
	{
		MultiplyLimbs(ref x, ref y, out ulong t0, out ulong t1, out ulong t2, out ulong t3, out ulong t4, out ulong t5, out ulong t6, out ulong t7);
		Reduce(t0, t1, t2, t3, t4, t5, t6, t7, ref result);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void Square<TSelf>(ref ulong x, ref ulong result) where TSelf : struct, IMontgomeryModulus
	{
		SquareLimbs(ref x, out ulong t0, out ulong t1, out ulong t2, out ulong t3, out ulong t4, out ulong t5, out ulong t6, out ulong t7);
		Reduce(t0, t1, t2, t3, t4, t5, t6, t7, ref result);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Reduce(ulong t0, ulong t1, ulong t2, ulong t3, ulong t4, ulong t5, ulong t6, ulong t7, ref ulong result)
	{
		ulong carry = 0;
		t4 = AddWithCarry(t4, ReduceRound(t0, ref t1, ref t2, ref t3), ref carry);
		t5 = AddWithCarry(t5, ReduceRound(t1, ref t2, ref t3, ref t4), ref carry);
		t6 = AddWithCarry(t6, ReduceRound(t2, ref t3, ref t4, ref t5), ref carry);
		t7 = AddWithCarry(t7, ReduceRound(t3, ref t4, ref t5, ref t6), ref carry);
		FieldElement<P256Field>.ReduceOnce(t4, t5, t6, t7, carry, ref result);
	}

	// A round of Reduce on the limbs from t on, with the carry into and out of limb 4.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ReduceRound(ref ulong t, ref ulong carry)
	{
		ref ulong t4 = ref Unsafe.Add(ref t, 4);
		t4 = AddWithCarry(t4, ReduceRound(t, ref Unsafe.Add(ref t, 1), ref Unsafe.Add(ref t, 2), ref Unsafe.Add(ref t, 3)), ref carry);
	}

	// Adds q·p to t from limb 0 to 3, which clears limb 0 for q = t0, and returns what goes into limb 4. q·(2^64 − 2^32 + 1) needs no multiplication: for q·2^32 = high·2^64 + low, it is (q − high − β)·2^64 + q − low with β the borrow out of q − low.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong ReduceRound(ulong q, ref ulong t1, ref ulong t2, ref ulong t3)
	{
		ulong low = q << 32;
		ulong high = q >> 32;
		ulong sum1 = t1 + low;
		// Below 2^32 + 1.
		ulong carried = high + Carry(sum1, low);
		ulong sum2 = t2 + carried;
		ulong carry = Carry(sum2, carried);
		ulong productLow = q - low;
		// At most 2^64 − 2^32, so the carries added below do not wrap it.
		ulong top = q - high - Borrow(q, low);
		ulong sum3 = t3 + productLow;
		top += Carry(sum3, productLow);
		sum3 += carry;
		top += Carry(sum3, carry);
		t1 = sum1;
		t2 = sum2;
		t3 = sum3;
		return top;
	}
}
