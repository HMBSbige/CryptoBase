using static CryptoBase.EllipticCurves.LimbArithmetic;

namespace CryptoBase.EllipticCurves.SM9;

// The field of p, as SM9Modulus gives it, in five unsaturated limbs, the value Σ L_i·2^(52i), with Montgomery form for R = 2^260. p is just above 0.7119·2^256, so R/p is just above 22.47.
// An element is reduced if limbs 0 to 3 are below 2^52 and its value is below 2.25p, which puts limb 4 below 2^48.7. Every member that gives an element gives a reduced one, except AddUnreduced and SubtractUnreduced, whose callers keep the limbs and values within what the next operation takes; the constants are reduced. Two reduced elements of the same value have the same limbs.
// The products end in Montgomery reduction of a value t, x·y or a sum of products in an SM9FpWide, which gives a value below t/R + p, so below 2.25p for t below 28p²: the product of two reduced elements is below 5.1p², and every other caller states its bound against 28p².
// No member but InvertVariableTime branches on or indexes by a value; masks are 0 or ulong.MaxValue. Any result may be the same variable as an input.
internal struct SM9Fp : ISM9Field<SM9Fp>
{
	internal ulong L0;
	internal ulong L1;
	internal ulong L2;
	internal ulong L3;
	internal ulong L4;

	internal const int ByteLength = 32;

	private const ulong Mask = (1UL << 52) - 1;

	private const ulong P0 = 0x000F9B27E351457D;
	private const ulong P1 = 0x0004B1A7AEEDBE56;
	private const ulong P2 = 0x00058EC74521F293;
	private const ulong P3 = 0x000A6F1D603AB4FF;
	private const ulong P4 = 0x0000B640000002A3;

	private const ulong TwoP0 = 0x000F364FC6A28AFA;
	private const ulong TwoP1 = 0x0009634F5DDB7CAD;
	private const ulong TwoP2 = 0x000B1D8E8A43E526;
	private const ulong TwoP3 = 0x0004DE3AC07569FE;
	private const ulong TwoP4 = 0x00016C8000000547;

	// 3p in limbs that cover those of a reduced element, limbs 0 to 3 above 2^52 and limb 4 above 2.25p/2^208, so that SubtractUnreduced leaves no limb negative. Each is below 2^53.
	private const ulong ThreeP0 = 0x001ED177A9F3D077;
	private const ulong ThreeP1 = 0x001E14F70CC93B03;
	private const ulong ThreeP2 = 0x0010AC55CF65D7B8;
	private const ulong ThreeP3 = 0x001F4D5820B01EFD;
	private const ulong ThreeP4 = 0x000222C0000007E9;

	// 6p in limbs that cover twice those of a reduced element, limbs 0 to 3 at least 2^53 − 2 and limb 4 above 4.5p/2^208, for SumMinusTwice. Each is below 2^54.
	private const ulong SixP0 = 0x002DA2EF53E7A0EE;
	private const ulong SixP1 = 0x002C29EE19927607;
	private const ulong SixP2 = 0x002158AB9ECBAF71;
	private const ulong SixP3 = 0x002E9AB041603DFA;
	private const ulong SixP4 = 0x0004458000000FD3;

	// −p⁻¹ mod 2^52.
	private const ulong NegativeInverse = 0x000BC42C2F2EE42B;

	// ⌊2^59/(P4 + 1)⌋, below 2^12, for the quotient of WeakReduce.
	private const ulong QuotientMultiplier = 0xB3C;

	public static ref readonly SM9Fp One => ref FromConstant(OneLimbs);

	public static ref readonly SM9Fp B => ref FromConstant(FiveLimbs);

	// 2^260 mod p.
	private static ReadOnlySpan<ulong> OneLimbs => [0x0008AA9277040742, 0x0008BB96F791A486, 0x0005BAE00F152757, 0x000A7379BAF4720E, 0x0000567FFFFFC5EF];

	// 5·2^260 mod p.
	private static ReadOnlySpan<ulong> FiveLimbs => [0x000C1E8C8C719950, 0x000246A377FCB9F2, 0x000188D1C125DF8F, 0x000F6325E650D049, 0x000043FFFFFED866];

	// 2^520 mod p, R² for ToMontgomery.
	private static ReadOnlySpan<ulong> RSquaredLimbs => [0x000CAD9360402D43, 0x0009C612699529D4, 0x00072DE2FB5978F9, 0x0005A7D22C6A3891, 0x00006155A6564AA2];

	// 2^520 mod p in 64-bit limbs: the numerator for SafeGcd, which then takes aR to R²/(aR) = a⁻¹R.
	private static ReadOnlySpan<ulong> InverseNumerator => [0x9D4CAD9360402D43, 0x5978F99C61269952, 0x22C6A389172DE2FB, 0x6155A6564AA25A7D];

	// With a = x_i·2^6 and b = y_j·2^6, a·b = x_i·y_j·2^12 splits at bit 52 of x_i·y_j: the high word is x_i·y_j >> 52 and the low word (x_i·y_j mod 2^52)·2^12. For limbs below 2^55 each high word is below 2^58, so a column of at most five low and five high words is below 2^61. The columns need no carries before Reduce.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void Multiply(in SM9Fp left, in SM9Fp right, out SM9Fp result)
	{
		ulong a0 = left.L0 << 6;
		ulong a1 = left.L1 << 6;
		ulong a2 = left.L2 << 6;
		ulong a3 = left.L3 << 6;
		ulong a4 = left.L4 << 6;
		ulong b0 = right.L0 << 6;
		ulong b1 = right.L1 << 6;
		ulong b2 = right.L2 << 6;
		ulong b3 = right.L3 << 6;
		ulong b4 = right.L4 << 6;
		ulong t0 = Low(a0, b0);
		ulong t1 = High(a0, b0) + Low(a0, b1) + Low(a1, b0);
		ulong t2 = High(a0, b1) + High(a1, b0) + Low(a0, b2) + Low(a1, b1) + Low(a2, b0);
		ulong t3 = High(a0, b2) + High(a1, b1) + High(a2, b0) + Low(a0, b3) + Low(a1, b2) + Low(a2, b1) + Low(a3, b0);
		ulong t4 = High(a0, b3) + High(a1, b2) + High(a2, b1) + High(a3, b0) + Low(a0, b4) + Low(a1, b3) + Low(a2, b2) + Low(a3, b1) + Low(a4, b0);
		ulong t5 = High(a0, b4) + High(a1, b3) + High(a2, b2) + High(a3, b1) + High(a4, b0) + Low(a1, b4) + Low(a2, b3) + Low(a3, b2) + Low(a4, b1);
		ulong t6 = High(a1, b4) + High(a2, b3) + High(a3, b2) + High(a4, b1) + Low(a2, b4) + Low(a3, b3) + Low(a4, b2);
		ulong t7 = High(a2, b4) + High(a3, b3) + High(a4, b2) + Low(a3, b4) + Low(a4, b3);
		ulong t8 = High(a3, b4) + High(a4, b3) + Low(a4, b4);
		Reduce(t0, t1, t2, t3, t4, t5, t6, t7, t8, High(a4, b4), out result);
	}

	// As Multiply with right = value. The cross products take d = x_i·2^7 for 2·x_i·x_j, so limbs must be below 2^55 here too.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void Square(in SM9Fp value, out SM9Fp result)
	{
		SquareColumns(in value, out ulong t0, out ulong t1, out ulong t2, out ulong t3, out ulong t4, out ulong t5, out ulong t6, out ulong t7, out ulong t8, out ulong t9);
		Reduce(t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, out result);
	}

	// The columns of Multiply, for a sum of products that one Reduce takes.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void MultiplyWide(in SM9Fp left, in SM9Fp right, out SM9FpWide result)
	{
		ulong a0 = left.L0 << 6;
		ulong a1 = left.L1 << 6;
		ulong a2 = left.L2 << 6;
		ulong a3 = left.L3 << 6;
		ulong a4 = left.L4 << 6;
		ulong b0 = right.L0 << 6;
		ulong b1 = right.L1 << 6;
		ulong b2 = right.L2 << 6;
		ulong b3 = right.L3 << 6;
		ulong b4 = right.L4 << 6;
		result.T0 = Low(a0, b0);
		result.T1 = High(a0, b0) + Low(a0, b1) + Low(a1, b0);
		result.T2 = High(a0, b1) + High(a1, b0) + Low(a0, b2) + Low(a1, b1) + Low(a2, b0);
		result.T3 = High(a0, b2) + High(a1, b1) + High(a2, b0) + Low(a0, b3) + Low(a1, b2) + Low(a2, b1) + Low(a3, b0);
		result.T4 = High(a0, b3) + High(a1, b2) + High(a2, b1) + High(a3, b0) + Low(a0, b4) + Low(a1, b3) + Low(a2, b2) + Low(a3, b1) + Low(a4, b0);
		result.T5 = High(a0, b4) + High(a1, b3) + High(a2, b2) + High(a3, b1) + High(a4, b0) + Low(a1, b4) + Low(a2, b3) + Low(a3, b2) + Low(a4, b1);
		result.T6 = High(a1, b4) + High(a2, b3) + High(a3, b2) + High(a4, b1) + Low(a2, b4) + Low(a3, b3) + Low(a4, b2);
		result.T7 = High(a2, b4) + High(a3, b3) + High(a4, b2) + Low(a3, b4) + Low(a4, b3);
		result.T8 = High(a3, b4) + High(a4, b3) + Low(a4, b4);
		result.T9 = High(a4, b4);
	}

	// The columns of Square.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void SquareWide(in SM9Fp value, out SM9FpWide result)
	{
		SquareColumns(in value, out result.T0, out result.T1, out result.T2, out result.T3, out result.T4, out result.T5, out result.T6, out result.T7, out result.T8, out result.T9);
	}

	// Montgomery reduction of a sum of products: the value of value must not be negative, and its columns may be, within 2^62 in magnitude.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Reduce(in SM9FpWide value, out SM9Fp result)
	{
		Reduce(value.T0, value.T1, value.T2, value.T3, value.T4, value.T5, value.T6, value.T7, value.T8, value.T9, out result);
	}

	// The reduced element of a sum of products whose value lies in (−128p², 342p²), with columns below 2^61.9 in magnitude: Reduce takes it with 128p² added, below 470p², and gives a value below 470p²/R + p < 21.95p, which WeakReduce takes. Not inlined: the tower reduces many sums in each operation, and one copy of the reduction keeps the code of those operations small.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	internal static void ReduceWide(in SM9FpWide value, out SM9Fp result)
	{
		SM9FpWide.AddOffset(in value, out SM9FpWide balanced);
		Reduce(in balanced, out result);
		WeakReduce(in result, out result);
	}

	// Limb by limb, without carries.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void AddUnreduced(in SM9Fp left, in SM9Fp right, out SM9Fp result)
	{
		result.L0 = left.L0 + right.L0;
		result.L1 = left.L1 + right.L1;
		result.L2 = left.L2 + right.L2;
		result.L3 = left.L3 + right.L3;
		result.L4 = left.L4 + right.L4;
	}

	// left + 3p − right limb by limb, for a reduced right: no limb goes negative, and each grows by below 2^53.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void SubtractUnreduced(in SM9Fp left, in SM9Fp right, out SM9Fp result)
	{
		result.L0 = left.L0 + ThreeP0 - right.L0;
		result.L1 = left.L1 + ThreeP1 - right.L1;
		result.L2 = left.L2 + ThreeP2 - right.L2;
		result.L3 = left.L3 + ThreeP3 - right.L3;
		result.L4 = left.L4 + ThreeP4 - right.L4;
	}

	// For limbs below 2^62 whose sum is below 2^260.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Add(in SM9Fp left, in SM9Fp right, out SM9Fp result)
	{
		AddUnreduced(in left, in right, out result);
		WeakReduce(in result, out result);
	}

	// For a reduced right and a left whose limbs are below 2^61 and whose value is below 2^260 − 3p.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Subtract(in SM9Fp left, in SM9Fp right, out SM9Fp result)
	{
		SubtractUnreduced(in left, in right, out result);
		WeakReduce(in result, out result);
	}

	// For a reduced value.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Negate(in SM9Fp value, out SM9Fp result)
	{
		SM9Fp zero = default;
		Subtract(in zero, in value, out result);
	}

	// a + b − 2c for reduced inputs as a + b + 6p − 2c, below 10.5p, with one weak reduction.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void SumMinusTwice(in SM9Fp a, in SM9Fp b, in SM9Fp c, out SM9Fp result)
	{
		result.L0 = a.L0 + b.L0 + SixP0 - 2 * c.L0;
		result.L1 = a.L1 + b.L1 + SixP1 - 2 * c.L1;
		result.L2 = a.L2 + b.L2 + SixP2 - 2 * c.L2;
		result.L3 = a.L3 + b.L3 + SixP3 - 2 * c.L3;
		result.L4 = a.L4 + b.L4 + SixP4 - 2 * c.L4;
		WeakReduce(in result, out result);
	}

	// value·k for limbs whose products with k are below 2^62 and a value whose product with k is below 2^260: k up to 9 for a reduced value.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void MultiplySmall(in SM9Fp value, uint k, out SM9Fp result)
	{
		result.L0 = value.L0 * k;
		result.L1 = value.L1 * k;
		result.L2 = value.L2 * k;
		result.L3 = value.L3 * k;
		result.L4 = value.L4 * k;
		WeakReduce(in result, out result);
	}

	// 15·value as 5·(3·value), for b = 5.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void MultiplyByThreeB(in SM9Fp value, out SM9Fp result)
	{
		MultiplySmall(in value, 3, out result);
		MultiplySmall(in result, 5, out result);
	}

	// For limbs below 2^62 and a value below 2^260. Carrying leaves limbs 0 to 3 below 2^52 and limb 4 = ⌊v/2^208⌋ below 2^52. q is ⌊L4/(P4 + 1)⌋ or one less, as the multiplier falls short of 2^59/(P4 + 1) by under 1 and L4 < 2^52: since p < (P4 + 1)·2^208, qp is at most the value, and the remainder is below 2^208·(1 + L4/(P4 + 1)) + 2p, under 2p + 2^213. The limbs of qp are below 2^57, and the borrows shift arithmetically.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void WeakReduce(in SM9Fp value, out SM9Fp result)
	{
		ulong l0 = value.L0;
		ulong l1 = value.L1 + (l0 >> 52);
		ulong l2 = value.L2 + (l1 >> 52);
		ulong l3 = value.L3 + (l2 >> 52);
		ulong l4 = value.L4 + (l3 >> 52);
		ulong q = l4 * QuotientMultiplier >> 59;
		ulong t0 = (l0 & Mask) - q * P0;
		ulong t1 = (l1 & Mask) - q * P1 + SignedCarry(t0);
		ulong t2 = (l2 & Mask) - q * P2 + SignedCarry(t1);
		ulong t3 = (l3 & Mask) - q * P3 + SignedCarry(t2);
		result.L0 = t0 & Mask;
		result.L1 = t1 & Mask;
		result.L2 = t2 & Mask;
		result.L3 = t3 & Mask;
		result.L4 = l4 - q * P4 + SignedCarry(t3);
	}

	// ulong.MaxValue if the value is 0 mod p and 0 otherwise. Below 2.25p a reduced element is 0 mod p just if its limbs are those of 0, p or 2p.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ulong IsZero(in SM9Fp value)
	{
		ulong zero = value.L0 | value.L1 | value.L2 | value.L3 | value.L4;
		ulong modulus = value.L0 ^ P0 | value.L1 ^ P1 | value.L2 ^ P2 | value.L3 ^ P3 | value.L4 ^ P4;
		ulong twice = value.L0 ^ TwoP0 | value.L1 ^ TwoP1 | value.L2 ^ TwoP2 | value.L3 ^ TwoP3 | value.L4 ^ TwoP4;
		return ZeroMask(zero) | ZeroMask(modulus) | ZeroMask(twice);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ulong AreEqual(in SM9Fp left, in SM9Fp right)
	{
		Subtract(in left, in right, out SM9Fp difference);
		return IsZero(in difference);
	}

	// Limb by limb, which keeps the form of the inputs.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ConditionalSelect(ulong mask, in SM9Fp whenSet, in SM9Fp whenClear, out SM9Fp result)
	{
		result.L0 = Select(mask, whenSet.L0, whenClear.L0);
		result.L1 = Select(mask, whenSet.L1, whenClear.L1);
		result.L2 = Select(mask, whenSet.L2, whenClear.L2);
		result.L3 = Select(mask, whenSet.L3, whenClear.L3);
		result.L4 = Select(mask, whenSet.L4, whenClear.L4);
	}

	internal static void ToMontgomery(in SM9Fp value, out SM9Fp result)
	{
		Multiply(in value, in FromConstant(RSquaredLimbs), out result);
	}

	// 0 gives 0. SafeGcd works on the canonical value in 64-bit limbs.
	public static void Invert(in SM9Fp value, out SM9Fp result)
	{
		ToSaturated(in value, out FieldElement<SM9Modulus> saturated);
		SafeGcd<SM9Modulus>.Invert(in saturated, InverseNumerator, out saturated);
		FromLimbs(FieldElement<SM9Modulus>.GetLimbs(in saturated), out result);
		saturated.ZeroMemory();
	}

	// The time depends on value, which must be public. 0 gives 0.
	public static void InvertVariableTime(in SM9Fp value, out SM9Fp result)
	{
		ToSaturated(in value, out FieldElement<SM9Modulus> saturated);
		SafeGcd<SM9Modulus>.InvertVariableTime(in saturated, InverseNumerator, out saturated);
		FromLimbs(FieldElement<SM9Modulus>.GetLimbs(in saturated), out result);
	}

	// The element of the value of four 64-bit limbs, least significant first, below p.
	internal static void FromLimbs(ReadOnlySpan<ulong> limbs, out SM9Fp result)
	{
		Debug.Assert(limbs.Length is 4);

		ulong w0 = limbs[0];
		ulong w1 = limbs[1];
		ulong w2 = limbs[2];
		ulong w3 = limbs[3];
		result.L0 = w0 & Mask;
		result.L1 = (w0 >> 52 | w1 << 12) & Mask;
		result.L2 = (w1 >> 40 | w2 << 24) & Mask;
		result.L3 = (w2 >> 28 | w3 << 36) & Mask;
		result.L4 = w3 >> 16;
	}

	// Reads 32 big-endian bytes, the plain value; if it is not below p, result is 0.
	internal static bool TryImport(ReadOnlySpan<byte> source, out SM9Fp result)
	{
		bool valid = FieldElement<SM9Modulus>.TryImport(source, out FieldElement<SM9Modulus> value);
		FromLimbs(FieldElement<SM9Modulus>.GetLimbs(in value), out result);
		value.ZeroMemory();
		return valid;
	}

	// Writes value/R mod p, the plain value of a Montgomery form, in 32 big-endian bytes: Reduce on the limbs of value alone, the columns of value·1, leaves below value/R + p, so at most p for a reduced value, which one conditional subtraction of p takes below p.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	internal static void ExportPlain(in SM9Fp value, Span<byte> destination)
	{
		Reduce(value.L0, value.L1, value.L2, value.L3, value.L4, 0, 0, 0, 0, 0, out SM9Fp t);
		SubtractModulus(in t, out t);
		Pack(in t, out FieldElement<SM9Modulus> saturated);
		FieldElement<SM9Modulus>.Export(in saturated, destination);
		t.ZeroMemory();
		saturated.ZeroMemory();
	}

	// The canonical value in four 64-bit limbs. A reduced element is below 2.25p, so two conditional subtractions of p leave it below p.
	private static void ToSaturated(in SM9Fp value, out FieldElement<SM9Modulus> result)
	{
		SubtractModulus(in value, out SM9Fp t);
		SubtractModulus(in t, out t);
		Pack(in t, out result);
		t.ZeroMemory();
	}

	// A value below p in four 64-bit limbs: limbs 0 to 3 below 2^52 and a value below 2^256 pack without overlap.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Pack(in SM9Fp value, out FieldElement<SM9Modulus> result)
	{
		Unsafe.SkipInit(out result);
		ref ulong limbs = ref Unsafe.As<FieldElement<SM9Modulus>, ulong>(ref result);
		limbs = value.L0 | value.L1 << 52;
		Unsafe.Add(ref limbs, 1) = value.L1 >> 12 | value.L2 << 40;
		Unsafe.Add(ref limbs, 2) = value.L2 >> 24 | value.L3 << 28;
		Unsafe.Add(ref limbs, 3) = value.L3 >> 36 | value.L4 << 16;
	}

	// value − p if that is not negative and value otherwise, for a reduced value.
	private static void SubtractModulus(in SM9Fp value, out SM9Fp result)
	{
		ulong d0 = value.L0 - P0;
		ulong d1 = value.L1 - P1 + SignedCarry(d0);
		ulong d2 = value.L2 - P2 + SignedCarry(d1);
		ulong d3 = value.L3 - P3 + SignedCarry(d2);
		ulong d4 = value.L4 - P4 + SignedCarry(d3);
		// All ones if value < p.
		ulong keep = (ulong)((long)d4 >> 63);
		result.L0 = Select(keep, value.L0, d0 & Mask);
		result.L1 = Select(keep, value.L1, d1 & Mask);
		result.L2 = Select(keep, value.L2, d2 & Mask);
		result.L3 = Select(keep, value.L3, d3 & Mask);
		result.L4 = Select(keep, value.L4, d4);
	}

	// The columns of value², with the cross products doubled through d = x_i·2^7.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void SquareColumns(in SM9Fp value, out ulong t0, out ulong t1, out ulong t2, out ulong t3, out ulong t4, out ulong t5, out ulong t6, out ulong t7, out ulong t8, out ulong t9)
	{
		ulong a0 = value.L0 << 6;
		ulong a1 = value.L1 << 6;
		ulong a2 = value.L2 << 6;
		ulong a3 = value.L3 << 6;
		ulong a4 = value.L4 << 6;
		ulong d0 = value.L0 << 7;
		ulong d1 = value.L1 << 7;
		ulong d2 = value.L2 << 7;
		ulong d3 = value.L3 << 7;
		t0 = Low(a0, a0);
		t1 = High(a0, a0) + Low(d0, a1);
		t2 = High(d0, a1) + Low(d0, a2) + Low(a1, a1);
		t3 = High(d0, a2) + High(a1, a1) + Low(d0, a3) + Low(d1, a2);
		t4 = High(d0, a3) + High(d1, a2) + Low(d0, a4) + Low(d1, a3) + Low(a2, a2);
		t5 = High(d0, a4) + High(d1, a3) + High(a2, a2) + Low(d1, a4) + Low(d2, a3);
		t6 = High(d1, a4) + High(d2, a3) + Low(d2, a4) + Low(a3, a3);
		t7 = High(d2, a4) + High(a3, a3) + Low(d3, a4);
		t8 = High(d3, a4) + Low(a4, a4);
		t9 = High(a4, a4);
	}

	// Five Montgomery rounds on t = Σ t_k·2^(52k). Round k takes q = −t_k/p mod 2^52 and adds q·p·2^(52k), whose low word clears column k: as that word is (−t_k) mod 2^52, column k carries ⌈t_k/2^52⌉ = ⌊(t_k + 2^52 − 1)/2^52⌋ out, which the arithmetic shift gives for either sign of t_k, so the low word of q·p0 is not needed. Columns 5 to 9, carried, are the result, (t + Q·p)/2^260 for some 0 ≤ Q < 2^260, below t/R + p. The rounds add below 2^53 + 2^11 to a column each, at most five times, so columns below 2^62 in magnitude stay below 2^63; the last carries shift arithmetically too, and a value that is not negative leaves limb 4 not negative.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Reduce(ulong t0, ulong t1, ulong t2, ulong t3, ulong t4, ulong t5, ulong t6, ulong t7, ulong t8, ulong t9, out SM9Fp result)
	{
		ulong q = Quotient(t0);
		t1 += SignedCarry(t0 + Mask) + High(q, P0 << 6) + Low(q, P1 << 6);
		t2 += High(q, P1 << 6) + Low(q, P2 << 6);
		t3 += High(q, P2 << 6) + Low(q, P3 << 6);
		t4 += High(q, P3 << 6) + Low(q, P4 << 6);
		t5 += High(q, P4 << 6);
		q = Quotient(t1);
		t2 += SignedCarry(t1 + Mask) + High(q, P0 << 6) + Low(q, P1 << 6);
		t3 += High(q, P1 << 6) + Low(q, P2 << 6);
		t4 += High(q, P2 << 6) + Low(q, P3 << 6);
		t5 += High(q, P3 << 6) + Low(q, P4 << 6);
		t6 += High(q, P4 << 6);
		q = Quotient(t2);
		t3 += SignedCarry(t2 + Mask) + High(q, P0 << 6) + Low(q, P1 << 6);
		t4 += High(q, P1 << 6) + Low(q, P2 << 6);
		t5 += High(q, P2 << 6) + Low(q, P3 << 6);
		t6 += High(q, P3 << 6) + Low(q, P4 << 6);
		t7 += High(q, P4 << 6);
		q = Quotient(t3);
		t4 += SignedCarry(t3 + Mask) + High(q, P0 << 6) + Low(q, P1 << 6);
		t5 += High(q, P1 << 6) + Low(q, P2 << 6);
		t6 += High(q, P2 << 6) + Low(q, P3 << 6);
		t7 += High(q, P3 << 6) + Low(q, P4 << 6);
		t8 += High(q, P4 << 6);
		q = Quotient(t4);
		t5 += SignedCarry(t4 + Mask) + High(q, P0 << 6) + Low(q, P1 << 6);
		t6 += High(q, P1 << 6) + Low(q, P2 << 6);
		t7 += High(q, P2 << 6) + Low(q, P3 << 6);
		t8 += High(q, P3 << 6) + Low(q, P4 << 6);
		t9 += High(q, P4 << 6);
		t6 += SignedCarry(t5);
		t7 += SignedCarry(t6);
		t8 += SignedCarry(t7);
		result.L0 = t5 & Mask;
		result.L1 = t6 & Mask;
		result.L2 = t7 & Mask;
		result.L3 = t8 & Mask;
		result.L4 = t9 + SignedCarry(t8);
	}

	// −t/p mod 2^52, shifted left by 6 for Low and High.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong Quotient(ulong t)
	{
		return (t * NegativeInverse & Mask) << 6;
	}

	// (x·y mod 2^52) for a = x·2^6 and b = y·2^6.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong Low(ulong a, ulong b)
	{
		return a * b >> 12;
	}

	// x·y >> 52 for a = x·2^6 and b = y·2^6.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong High(ulong a, ulong b)
	{
		if (Bmi2.X64.IsSupported)
		{
			return Bmi2.X64.MultiplyNoFlags(a, b);
		}

		if (ArmBase.Arm64.IsSupported)
		{
			return ArmBase.Arm64.MultiplyHigh(a, b);
		}

		if (IsMultiplyAccelerated)
		{
			return Math.BigMul(a, b, out _);
		}

		// Math.BigMul would call its software fallback here rather than inline it. One of a and b is below 2^61 and the other below 2^62, so the two cross products of their 32-bit halves and the carry out of the low product sum below 2^64 without a carry.
		ulong aHigh = a >> 32;
		ulong aLow = (uint)a;
		ulong bHigh = b >> 32;
		ulong bLow = (uint)b;
		ulong middle = aHigh * bLow + aLow * bHigh + (aLow * bLow >> 32);
		return aHigh * bHigh + (middle >> 32);
	}

	// ⌊t/2^52⌋ for a t that may be negative.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong SignedCarry(ulong t)
	{
		return (ulong)((long)t >> 52);
	}

	// limbs must be five reduced limbs that live for the whole process, as the data of a constant span does.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static ref readonly SM9Fp FromConstant(ReadOnlySpan<ulong> limbs)
	{
		Debug.Assert(limbs.Length is 5);

		return ref Unsafe.As<ulong, SM9Fp>(ref MemoryMarshal.GetReference(limbs));
	}
}
