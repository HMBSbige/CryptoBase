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

	// The rows of the product interleaved with the rounds of Reduce, in locals, which stay in registers, rather than in memory. For x and y below p, the sum before each row is below 2p, so it and the next row stay below 2^64·R and fit five limbs; an x of R − 1 could overflow them, which is why ImportReduced does not come here. Not inlined, as for FieldElement.MontgomeryMultiply.
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void Multiply<TSelf>(ref ulong x, ref ulong y, ref ulong result) where TSelf : struct, IMontgomeryModulus
	{
		ulong x0 = x;
		ulong x1 = Unsafe.Add(ref x, 1);
		ulong x2 = Unsafe.Add(ref x, 2);
		ulong x3 = Unsafe.Add(ref x, 3);
		ulong word = y;
		ulong carry = LimbArithmetic.Multiply(x0, word, out ulong t0);
		carry = MultiplyAdd(x1, word, carry, 0, out ulong t1);
		carry = MultiplyAdd(x2, word, carry, 0, out ulong t2);
		ulong t4 = MultiplyAdd(x3, word, carry, 0, out ulong t3);
		ulong t5 = AddRound(t0, ref t1, ref t2, ref t3, ref t4);
		AddRow(x0, x1, x2, x3, Unsafe.Add(ref y, 1), ref t1, ref t2, ref t3, ref t4, ref t5);
		ulong t6 = AddRound(t1, ref t2, ref t3, ref t4, ref t5);
		AddRow(x0, x1, x2, x3, Unsafe.Add(ref y, 2), ref t2, ref t3, ref t4, ref t5, ref t6);
		ulong t7 = AddRound(t2, ref t3, ref t4, ref t5, ref t6);
		AddRow(x0, x1, x2, x3, Unsafe.Add(ref y, 3), ref t3, ref t4, ref t5, ref t6, ref t7);
		ulong t8 = AddRound(t3, ref t4, ref t5, ref t6, ref t7);
		FieldElement<P256Field>.ReduceOnce(t4, t5, t6, t7, t8, ref result);
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

	// Adds x·word to t0 to t4, the top limb of a sum that the row does not carry out of.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void AddRow(ulong x0, ulong x1, ulong x2, ulong x3, ulong word, ref ulong t0, ref ulong t1, ref ulong t2, ref ulong t3, ref ulong t4)
	{
		ulong carry = MultiplyAdd(x0, word, t0, 0, out t0);
		carry = MultiplyAdd(x1, word, t1, carry, out t1);
		carry = MultiplyAdd(x2, word, t2, carry, out t2);
		t4 += MultiplyAdd(x3, word, t3, carry, out t3);
	}

	// A round of Reduce on the limbs from t on, with the carry into and out of limb 4.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ReduceRound(ref ulong t, ref ulong carry)
	{
		ref ulong t4 = ref Unsafe.Add(ref t, 4);
		t4 = AddWithCarry(t4, ReduceRound(t, ref Unsafe.Add(ref t, 1), ref Unsafe.Add(ref t, 2), ref Unsafe.Add(ref t, 3)), ref carry);
	}

	// A round of Reduce that clears q = t0 from t0 to t4 and returns the carry out of t4.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong AddRound(ulong q, ref ulong t1, ref ulong t2, ref ulong t3, ref ulong t4)
	{
		ulong top = ReduceRound(q, ref t1, ref t2, ref t3);
		ulong sum = t4 + top;
		t4 = sum;
		return Carry(sum, top);
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
