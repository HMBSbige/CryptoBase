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

	// p ≡ −1 mod 2^64, so the q that clears limb i is t_i, and q·p = q·2^192·(2^64 − 2^32 + 1) + q·2^96 − q. The −q cancels limb i, q·2^96 is q shifted into limbs i + 1 and i + 2, and the rest is one product at limbs i + 3 and i + 4.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ulong Reduce<TSelf>(ref ulong product) where TSelf : struct, IMontgomeryModulus
	{
		ulong carry = 0;
		ReduceRound(product, ref Unsafe.Add(ref product, 1), ref Unsafe.Add(ref product, 2), ref Unsafe.Add(ref product, 3), ref Unsafe.Add(ref product, 4), ref carry);
		ReduceRound(Unsafe.Add(ref product, 1), ref Unsafe.Add(ref product, 2), ref Unsafe.Add(ref product, 3), ref Unsafe.Add(ref product, 4), ref Unsafe.Add(ref product, 5), ref carry);
		ReduceRound(Unsafe.Add(ref product, 2), ref Unsafe.Add(ref product, 3), ref Unsafe.Add(ref product, 4), ref Unsafe.Add(ref product, 5), ref Unsafe.Add(ref product, 6), ref carry);
		ReduceRound(Unsafe.Add(ref product, 3), ref Unsafe.Add(ref product, 4), ref Unsafe.Add(ref product, 5), ref Unsafe.Add(ref product, 6), ref Unsafe.Add(ref product, 7), ref carry);
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
		ReduceRound(t0, ref t1, ref t2, ref t3, ref t4, ref carry);
		ReduceRound(t1, ref t2, ref t3, ref t4, ref t5, ref carry);
		ReduceRound(t2, ref t3, ref t4, ref t5, ref t6, ref carry);
		ReduceRound(t3, ref t4, ref t5, ref t6, ref t7, ref carry);
		FieldElement<P256Field>.ReduceOnce(t4, t5, t6, t7, carry, ref result);
	}

	// Clears q = t0 from t0 to t4.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ReduceRound(ulong q, ref ulong t1, ref ulong t2, ref ulong t3, ref ulong t4, ref ulong carry)
	{
		ulong low = q << 32;
		ulong sum1 = t1 + low;
		// Below 2^32 + 1.
		ulong high = (q >> 32) + Carry(sum1, low);
		ulong sum2 = t2 + high;
		ulong top = MultiplyAdd(q, 0xFFFFFFFF00000001UL, t3, Carry(sum2, high), out ulong sum3);
		t1 = sum1;
		t2 = sum2;
		t3 = sum3;
		t4 = AddWithCarry(t4, top, ref carry);
	}
}
