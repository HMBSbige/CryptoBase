using static CryptoBase.EllipticCurves.LimbArithmetic;

namespace CryptoBase.EllipticCurves;

// The field of p = 2^384 − 2^128 − 2^96 + 2^32 − 1 in seven unsaturated limbs, the value Σ L_i·2^(56i), with Montgomery form for R = 2^392. Every member takes and gives elements of the form E: limbs 0 to 5 below 2^57 and limb 6 below 2^50, so values below 2^386 + 2^338, just over 4p. The formulas of EcFormulas skip reductions between steps within these limits:
// Multiply takes a left in limbs below 2^63 with a value below 2^392 and a right in limbs below 2^60, and Square limbs below 2^58. Both give limbs 0 to 5 below 2^56 and a value below x·y/2^392 + p; for inputs of E that is below p + 2^381, with limb 6 below 2^48 + 2^45, so a product needs no reduction after it. AddUnreduced adds limbs; SubtractUnreduced adds 5p, whose limbs cover those of E, for a subtrahend of E; and WeakReduce takes limbs below 2^62 to limbs 0 to 5 below 2^56, limb 6 at most 2^48 + 2^6 and a value below 2^384 + 2^342, so below 2p and in E.
// −p⁻¹ ≡ 2^32 + 1 (mod 2^56), as (2^32 − 1)(2^32 + 1) = 2^64 − 1, so Montgomery reduction needs no multiplication.
// For inputs of E the steps of the formulas keep within these limits, and the outputs are of E: X3 and Y3 come from WeakReduce, and Z3 is twice an output of Multiply, which has limbs 0 to 5 below 2^56 and limb 6 below 2^49 for the inputs here. Every input of Multiply has limbs below 5·2^56 and a value below 9p, every input of Square limbs below 3·2^56, every subtrahend of SubtractUnreduced is of E, as outputs of Multiply, Square and WeakReduce and their doubles below 2.2p are, and every input of WeakReduce has limbs below 2^60.
// In Double, γ, β and δ are below 1.1p in limbs below 2^56, and 2γ and 4β below 2.2p in limbs below 2^57. X − δ is below 9p in limbs below 5·2^56 and X + δ below 5.1p in limbs below 3·2^56, so their product is below 1.2p and α below 3.6p in limbs below 3·2^56. α² − 8β is below 11.1p in limbs below 2^59. 4β − X3 is below 7.1p in limbs below 5·2^56, α(4β − X3) below 1.1p, and that less 8γ² below 6.1p in limbs below 2^58.
// In AddDistinct, U1, U2, S1 and S2 are below 1.1p in limbs below 2^56, so H is below 6.1p in limbs below 2^58 and 2R below 12.1p in limbs below 2^59; reduced, both are below 2^384 + 2^342 in limbs below 2^56. Z1·Z2·H is below 1.1p, so Z3 is below 2.1p. I = 4H² is below 4.1p in limbs below 2^58, and J, V and S1·J are below 1.1p. With an affine right, whose coordinates are of E as well, H = X2·Z1² − X1 and 2R = 2(Y2·Z1³ − Y1) have the bounds above, Z1·H is below 1.1p, so Z3 is below 2.1p, and V = X1·I and Y1·J are below 1.1p.
// X3 = R² − J − 2V and Y3 = R(V − X3) − 2·SJ then take R below 2^384 + 2^342 and J, V and SJ below 1.1p, all in limbs below 2^56. R² is below 1.1p and R² − J − 2V below 16.1p in limbs below 10·2^56. V − X3 is below 6.1p in limbs below 2^58, R(V − X3) below 1.1p, and that less 2·SJ below 11.1p in limbs below 2^59.
internal struct P384Field56 : IEcField<P384Field56>
{
	internal ulong L0;
	internal ulong L1;
	internal ulong L2;
	internal ulong L3;
	internal ulong L4;
	internal ulong L5;
	internal ulong L6;

	private const ulong Mask = (1UL << 56) - 1;

	// The limbs of p: 2^32 − 1, 2^56 − 2^40, 2^56 − 2^16 − 1, three of 2^56 − 1 and 2^48 − 1.
	private const ulong P0 = (1UL << 32) - 1;
	private const ulong P1 = Mask - ((1UL << 40) - 1);
	private const ulong P2 = Mask - (1UL << 16);
	private const ulong P6 = (1UL << 48) - 1;

	// 5p in limbs at least 2^57 − 1 for limbs 0 to 5 and 2^50 − 1 for limb 6, the most that limbs of E hold, so that SubtractUnreduced leaves no limb negative; each is below 2^57 + 2^56.
	private const ulong FiveP0 = 0x02000004FFFFFFFB;
	private const ulong FiveP1 = 0x02FFFAFFFFFFFFFE;
	private const ulong FiveP2 = 0x02FFFFFFFFFAFFFD;
	private const ulong FiveP3 = 0x02FFFFFFFFFFFFFD;
	private const ulong FiveP6 = 0x0004FFFFFFFFFFFD;

	public static ReadOnlySpan<ulong> Modulus => P384Field.Modulus;

	public static int ByteLength => 48;

	public static ref readonly P384Field56 One => ref FromConstant(OneLimbs);

	// 2^392 mod p.
	private static ReadOnlySpan<ulong> OneLimbs => [0x00FFFF0000000100, 0x0000FFFFFFFFFFFF, 0x0000000001000000, 0, 0, 0, 0];

	// 2^784 mod p, R² for ToMontgomery.
	private static ReadOnlySpan<ulong> RSquaredLimbs => [0x00FE000000010000, 0x0000000000FFFFFF, 0x0000000000000002, 0x000000FFFFFFFE00, 0x0001000000020000, 0, 0];

	// 2^784 mod p in 64-bit limbs: the numerator for SafeGcd, which then takes aR to R²/(aR) = a⁻¹R.
	private static ReadOnlySpan<ulong> InverseNumerator => [0xFFFE000000010000, 0x000200000000FFFF, 0xFFFE000000000000, 0x000200000000FFFF, 0x0000000000010000, 0];

	public static void FromLimbs(ReadOnlySpan<ulong> limbs, out P384Field56 result)
	{
		Debug.Assert(limbs.Length is 6);

		ulong w0 = limbs[0];
		ulong w1 = limbs[1];
		ulong w2 = limbs[2];
		ulong w3 = limbs[3];
		ulong w4 = limbs[4];
		ulong w5 = limbs[5];
		result.L0 = w0 & Mask;
		result.L1 = (w0 >> 56 | w1 << 8) & Mask;
		result.L2 = (w1 >> 48 | w2 << 16) & Mask;
		result.L3 = (w2 >> 40 | w3 << 24) & Mask;
		result.L4 = (w3 >> 32 | w4 << 32) & Mask;
		result.L5 = (w4 >> 24 | w5 << 40) & Mask;
		result.L6 = w5 >> 16;
	}

	public static bool TryImport(ReadOnlySpan<byte> source, out P384Field56 result)
	{
		bool valid = FieldElement<P384Field>.TryImport(source, out FieldElement<P384Field> value);
		FromLimbs(FieldElement<P384Field>.GetLimbs(in value), out result);
		return valid;
	}

	public static void Export(in P384Field56 value, Span<byte> destination)
	{
		ToSaturated(in value, out FieldElement<P384Field> saturated);
		FieldElement<P384Field>.Export(in saturated, destination);
		saturated.ZeroMemory();
	}

	public static void Add(in P384Field56 left, in P384Field56 right, out P384Field56 result)
	{
		AddUnreduced(in left, in right, out result);
		WeakReduce(in result, out result);
	}

	public static void Subtract(in P384Field56 left, in P384Field56 right, out P384Field56 result)
	{
		SubtractUnreduced(in left, in right, out result);
		WeakReduce(in result, out result);
	}

	public static void Negate(in P384Field56 value, out P384Field56 result)
	{
		P384Field56 zero = default;
		Subtract(in zero, in value, out result);
	}

	// Carrying the left limbs first gives x_i below 2^56, x_6 too as the value is below 2^392. With a_i = x_i·2^8 and a right limb y_j below 2^60, a_i·y_j = x_i·y_j·2^8 < 2^124, so its high half is x_i·y_j >> 56, below 2^60, and its low half (x_i·y_j mod 2^56)·2^8. A column sums at most seven of each, below 2^63 with room for the Montgomery rounds, so all the columns come first without carries and the rounds after.
	// Each column adds one product at a time and each right limb is loaded where it is first used, so that few values are live at once.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void Multiply(in P384Field56 left, in P384Field56 right, out P384Field56 result)
	{
		ulong x = left.L0;
		ulong a0 = x << 8;
		x = left.L1 + (x >> 56);
		ulong a1 = x << 8;
		x = left.L2 + (x >> 56);
		ulong a2 = x << 8;
		x = left.L3 + (x >> 56);
		ulong a3 = x << 8;
		x = left.L4 + (x >> 56);
		ulong a4 = x << 8;
		x = left.L5 + (x >> 56);
		ulong a5 = x << 8;
		x = left.L6 + (x >> 56);
		ulong a6 = x << 8;
		ulong t0 = Low(a0, right.L0);
		ulong t1 = High(a0, right.L0);
		t1 += Low(a0, right.L1);
		t1 += Low(a1, right.L0);
		ulong t2 = High(a0, right.L1);
		t2 += High(a1, right.L0);
		t2 += Low(a0, right.L2);
		t2 += Low(a1, right.L1);
		t2 += Low(a2, right.L0);
		ulong t3 = High(a0, right.L2);
		t3 += High(a1, right.L1);
		t3 += High(a2, right.L0);
		t3 += Low(a0, right.L3);
		t3 += Low(a1, right.L2);
		t3 += Low(a2, right.L1);
		t3 += Low(a3, right.L0);
		ulong t4 = High(a0, right.L3);
		t4 += High(a1, right.L2);
		t4 += High(a2, right.L1);
		t4 += High(a3, right.L0);
		t4 += Low(a0, right.L4);
		t4 += Low(a1, right.L3);
		t4 += Low(a2, right.L2);
		t4 += Low(a3, right.L1);
		t4 += Low(a4, right.L0);
		ulong t5 = High(a0, right.L4);
		t5 += High(a1, right.L3);
		t5 += High(a2, right.L2);
		t5 += High(a3, right.L1);
		t5 += High(a4, right.L0);
		t5 += Low(a0, right.L5);
		t5 += Low(a1, right.L4);
		t5 += Low(a2, right.L3);
		t5 += Low(a3, right.L2);
		t5 += Low(a4, right.L1);
		t5 += Low(a5, right.L0);
		ulong t6 = High(a0, right.L5);
		t6 += High(a1, right.L4);
		t6 += High(a2, right.L3);
		t6 += High(a3, right.L2);
		t6 += High(a4, right.L1);
		t6 += High(a5, right.L0);
		t6 += Low(a0, right.L6);
		t6 += Low(a1, right.L5);
		t6 += Low(a2, right.L4);
		t6 += Low(a3, right.L3);
		t6 += Low(a4, right.L2);
		t6 += Low(a5, right.L1);
		t6 += Low(a6, right.L0);
		ulong t7 = High(a0, right.L6);
		t7 += High(a1, right.L5);
		t7 += High(a2, right.L4);
		t7 += High(a3, right.L3);
		t7 += High(a4, right.L2);
		t7 += High(a5, right.L1);
		t7 += High(a6, right.L0);
		t7 += Low(a1, right.L6);
		t7 += Low(a2, right.L5);
		t7 += Low(a3, right.L4);
		t7 += Low(a4, right.L3);
		t7 += Low(a5, right.L2);
		t7 += Low(a6, right.L1);
		ulong t8 = High(a1, right.L6);
		t8 += High(a2, right.L5);
		t8 += High(a3, right.L4);
		t8 += High(a4, right.L3);
		t8 += High(a5, right.L2);
		t8 += High(a6, right.L1);
		t8 += Low(a2, right.L6);
		t8 += Low(a3, right.L5);
		t8 += Low(a4, right.L4);
		t8 += Low(a5, right.L3);
		t8 += Low(a6, right.L2);
		ulong t9 = High(a2, right.L6);
		t9 += High(a3, right.L5);
		t9 += High(a4, right.L4);
		t9 += High(a5, right.L3);
		t9 += High(a6, right.L2);
		t9 += Low(a3, right.L6);
		t9 += Low(a4, right.L5);
		t9 += Low(a5, right.L4);
		t9 += Low(a6, right.L3);
		ulong t10 = High(a3, right.L6);
		t10 += High(a4, right.L5);
		t10 += High(a5, right.L4);
		t10 += High(a6, right.L3);
		t10 += Low(a4, right.L6);
		t10 += Low(a5, right.L5);
		t10 += Low(a6, right.L4);
		ulong t11 = High(a4, right.L6);
		t11 += High(a5, right.L5);
		t11 += High(a6, right.L4);
		t11 += Low(a5, right.L6);
		t11 += Low(a6, right.L5);
		ulong t12 = High(a5, right.L6);
		t12 += High(a6, right.L5);
		t12 += Low(a6, right.L6);
		Reduce(t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, High(a6, right.L6), out result);
	}

	// Multiply with value as both factors, for limbs below 2^58, which need no carrying first: a_i = x_i·2^4 gives a_i·a_i = x_i²·2^8, and d_i = x_i·2^5 gives the doubled cross product 2·x_i·x_j·2^8 in one product, which keeps each column within the bound of Multiply.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void Square(in P384Field56 value, out P384Field56 result)
	{
		ulong a0 = value.L0 << 4;
		ulong a1 = value.L1 << 4;
		ulong a2 = value.L2 << 4;
		ulong a3 = value.L3 << 4;
		ulong a4 = value.L4 << 4;
		ulong a5 = value.L5 << 4;
		ulong a6 = value.L6 << 4;
		ulong d0 = value.L0 << 5;
		ulong d1 = value.L1 << 5;
		ulong d2 = value.L2 << 5;
		ulong d3 = value.L3 << 5;
		ulong d4 = value.L4 << 5;
		ulong d5 = value.L5 << 5;
		ulong t0 = Low(a0, a0);
		ulong t1 = High(a0, a0) + Low(d0, a1);
		ulong t2 = High(d0, a1) + Low(d0, a2) + Low(a1, a1);
		ulong t3 = High(d0, a2) + High(a1, a1) + Low(d0, a3) + Low(d1, a2);
		ulong t4 = High(d0, a3) + High(d1, a2) + Low(d0, a4) + Low(d1, a3) + Low(a2, a2);
		ulong t5 = High(d0, a4) + High(d1, a3) + High(a2, a2) + Low(d0, a5) + Low(d1, a4) + Low(d2, a3);
		ulong t6 = High(d0, a5) + High(d1, a4) + High(d2, a3) + Low(d0, a6) + Low(d1, a5) + Low(d2, a4) + Low(a3, a3);
		ulong t7 = High(d0, a6) + High(d1, a5) + High(d2, a4) + High(a3, a3) + Low(d1, a6) + Low(d2, a5) + Low(d3, a4);
		ulong t8 = High(d1, a6) + High(d2, a5) + High(d3, a4) + Low(d2, a6) + Low(d3, a5) + Low(a4, a4);
		ulong t9 = High(d2, a6) + High(d3, a5) + High(a4, a4) + Low(d3, a6) + Low(d4, a5);
		ulong t10 = High(d3, a6) + High(d4, a5) + Low(d4, a6) + Low(a5, a5);
		ulong t11 = High(d4, a6) + High(a5, a5) + Low(d5, a6);
		ulong t12 = High(d5, a6) + Low(a6, a6);
		Reduce(t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, High(a6, a6), out result);
	}

	public static void ToMontgomery(in P384Field56 value, out P384Field56 result)
	{
		Multiply(in value, in FromConstant(RSquaredLimbs), out result);
	}

	public static void FromMontgomery(in P384Field56 value, out P384Field56 result)
	{
		P384Field56 one = default;
		one.L0 = 1;
		Multiply(in value, in one, out result);
	}

	// SafeGcd works on the canonical value in 64-bit limbs.
	public static void Invert(in P384Field56 value, out P384Field56 result)
	{
		ToSaturated(in value, out FieldElement<P384Field> saturated);
		SafeGcd<P384Field>.Invert(in saturated, InverseNumerator, out saturated);
		FromLimbs(FieldElement<P384Field>.GetLimbs(in saturated), out result);
		saturated.ZeroMemory();
	}

	public static void InvertVariableTime(in P384Field56 value, out P384Field56 result)
	{
		ToSaturated(in value, out FieldElement<P384Field> saturated);
		SafeGcd<P384Field>.InvertVariableTime(in saturated, InverseNumerator, out saturated);
		FromLimbs(FieldElement<P384Field>.GetLimbs(in saturated), out result);
	}

	public static ulong IsZero(in P384Field56 value)
	{
		WeakReduce(in value, out P384Field56 reduced);
		return IsReducedZero(in reduced);
	}

	public static ulong AreEqual(in P384Field56 left, in P384Field56 right)
	{
		SubtractUnreduced(in left, in right, out P384Field56 difference);
		return IsZero(in difference);
	}

	// The limbs add without carries; the caller keeps them within what the next operation takes.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void AddUnreduced(in P384Field56 left, in P384Field56 right, out P384Field56 result)
	{
		result.L0 = left.L0 + right.L0;
		result.L1 = left.L1 + right.L1;
		result.L2 = left.L2 + right.L2;
		result.L3 = left.L3 + right.L3;
		result.L4 = left.L4 + right.L4;
		result.L5 = left.L5 + right.L5;
		result.L6 = left.L6 + right.L6;
	}

	// left + 5p − right, limb by limb, for right of E: each limb grows by that of 5p, below 2^57 + 2^56, and none goes negative.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void SubtractUnreduced(in P384Field56 left, in P384Field56 right, out P384Field56 result)
	{
		result.L0 = left.L0 + FiveP0 - right.L0;
		result.L1 = left.L1 + FiveP1 - right.L1;
		result.L2 = left.L2 + FiveP2 - right.L2;
		result.L3 = left.L3 + FiveP3 - right.L3;
		result.L4 = left.L4 + FiveP3 - right.L4;
		result.L5 = left.L5 + FiveP3 - right.L5;
		result.L6 = left.L6 + FiveP6 - right.L6;
	}

	// For limbs below 2^62, subtracts h·p with h = L6 >> 48 below 2^14, then carries. h·p = h·2^384 − h·(2^128 + 2^96 − 2^32 + 1), so h·2^384 comes off limb 6, which leaves the value non-negative as it was at least h·2^384, and the rest goes in as h·2^16 at limb 2, h·2^40 at limb 1 and h − h·2^32 at limb 0. Only limb 0 may go negative, above −2^46, so only its carry shifts arithmetically, and it is at least −1: limb 1 gains h·2^40 ≥ 2^40 for h > 0, and h = 0 leaves limb 0 as it was. Limbs 0 to 5 come out below 2^56. Limb 6 keeps L6 mod 2^48, limbs 0 to 5 add below 2^342 + 2^287 and the rest of h·p below 2^143, so the value is below (2^48 − 1)·2^336 + 2^342 + 2^288, under 2^384 + 2^342.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void WeakReduce(in P384Field56 value, out P384Field56 result)
	{
		ulong h = value.L6 >> 48;
		ulong t0 = value.L0 + h - (h << 32);
		ulong t1 = value.L1 + (h << 40) + SignedCarry(t0);
		ulong t2 = value.L2 + (h << 16) + (t1 >> 56);
		ulong t3 = value.L3 + (t2 >> 56);
		ulong t4 = value.L4 + (t3 >> 56);
		ulong t5 = value.L5 + (t4 >> 56);
		result.L0 = t0 & Mask;
		result.L1 = t1 & Mask;
		result.L2 = t2 & Mask;
		result.L3 = t3 & Mask;
		result.L4 = t4 & Mask;
		result.L5 = t5 & Mask;
		result.L6 = (value.L6 & P6) + (t5 >> 56);
	}

	// For the output of WeakReduce: its value is below 2p and its limbs 0 to 5 below 2^56, so it is 0 mod p just if its limbs are those of 0 or of p.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ulong IsReducedZero(in P384Field56 value)
	{
		ulong zero = value.L0 | value.L1 | value.L2 | value.L3 | value.L4 | value.L5 | value.L6;
		ulong modulus = value.L0 ^ P0 | value.L1 ^ P1 | value.L2 ^ P2 | value.L3 ^ Mask | value.L4 ^ Mask | value.L5 ^ Mask | value.L6 ^ P6;
		return ZeroMask(zero) | ZeroMask(modulus);
	}

	// The value mod p in six 64-bit limbs. WeakReduce leaves a value below 2p in limbs 0 to 5 below 2^56, so one conditional subtraction of p gives the canonical value, whose limbs pack without overlap.
	private static void ToSaturated(in P384Field56 value, out FieldElement<P384Field> result)
	{
		WeakReduce(in value, out P384Field56 t);
		ulong d0 = t.L0 - P0;
		ulong d1 = t.L1 - P1 + SignedCarry(d0);
		ulong d2 = t.L2 - P2 + SignedCarry(d1);
		ulong d3 = t.L3 - Mask + SignedCarry(d2);
		ulong d4 = t.L4 - Mask + SignedCarry(d3);
		ulong d5 = t.L5 - Mask + SignedCarry(d4);
		ulong d6 = t.L6 - P6 + SignedCarry(d5);
		// All ones if t < p.
		ulong keep = (ulong)((long)d6 >> 63);
		ulong l0 = Select(keep, t.L0, d0 & Mask);
		ulong l1 = Select(keep, t.L1, d1 & Mask);
		ulong l2 = Select(keep, t.L2, d2 & Mask);
		ulong l3 = Select(keep, t.L3, d3 & Mask);
		ulong l4 = Select(keep, t.L4, d4 & Mask);
		ulong l5 = Select(keep, t.L5, d5 & Mask);
		ulong l6 = Select(keep, t.L6, d6);
		Unsafe.SkipInit(out result);
		ref ulong limbs = ref Unsafe.As<FieldElement<P384Field>, ulong>(ref result);
		limbs = l0 | l1 << 56;
		Unsafe.Add(ref limbs, 1) = l1 >> 8 | l2 << 48;
		Unsafe.Add(ref limbs, 2) = l2 >> 16 | l3 << 40;
		Unsafe.Add(ref limbs, 3) = l3 >> 24 | l4 << 32;
		Unsafe.Add(ref limbs, 4) = l4 >> 32 | l5 << 24;
		Unsafe.Add(ref limbs, 5) = l5 >> 40 | l6 << 16;
		t.ZeroMemory();
	}

	// The Montgomery rounds on t = Σ t_k·2^(56k), one for each of limbs 0 to 6, and limbs 7 to 13 are the result, carried. Every limb but t_0 may go negative, so every carry shifts arithmetically; for columns within the bound of Multiply every limb stays below 2^63 in magnitude. The result is (t + Q·p)/2^392 for some Q < 2^392, so below t/2^392 + p and not negative, with limbs 0 to 5 below 2^56.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Reduce(ulong t0, ulong t1, ulong t2, ulong t3, ulong t4, ulong t5, ulong t6, ulong t7, ulong t8, ulong t9, ulong t10, ulong t11, ulong t12, ulong t13, out P384Field56 result)
	{
		ReduceRound(t0, ref t1, ref t2, ref t3, ref t6, ref t7);
		ReduceRound(t1, ref t2, ref t3, ref t4, ref t7, ref t8);
		ReduceRound(t2, ref t3, ref t4, ref t5, ref t8, ref t9);
		ReduceRound(t3, ref t4, ref t5, ref t6, ref t9, ref t10);
		ReduceRound(t4, ref t5, ref t6, ref t7, ref t10, ref t11);
		ReduceRound(t5, ref t6, ref t7, ref t8, ref t11, ref t12);
		ReduceRound(t6, ref t7, ref t8, ref t9, ref t12, ref t13);
		t8 += SignedCarry(t7);
		t9 += SignedCarry(t8);
		t10 += SignedCarry(t9);
		t11 += SignedCarry(t10);
		t12 += SignedCarry(t11);
		result.L0 = t7 & Mask;
		result.L1 = t8 & Mask;
		result.L2 = t9 & Mask;
		result.L3 = t10 & Mask;
		result.L4 = t11 & Mask;
		result.L5 = t12 & Mask;
		result.L6 = t13 + SignedCarry(t12);
	}

	// Adds q·p at limb 0 for q = t0·(2^32 + 1) mod 2^56, which clears limb 0, and moves its carry into limb 1. With s = t0 + (t0 mod 2^24)·2^32, s ≡ t0·(2^32 + 1) (mod 2^56), so q = s mod 2^56; q ≡ t0 (mod 2^32), so t0 + q·(2^32 − 1) = s − q + (q >> 24)·2^56, which is ⌊s/2^56⌋ + (q >> 24) at limb 1. The rest of q·p, q·(2^384 − 2^128 − 2^96), splits at the limb boundaries: −q·2^96 into −(q mod 2^16)·2^40 at limb 1 and −(q >> 16) at limb 2, −q·2^128 into −(q mod 2^40)·2^16 at limb 2 and −(q >> 40) at limb 3, and q·2^384 into (q mod 2^8)·2^48 at limb 6 and q >> 8 at limb 7.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ReduceRound(ulong t0, ref ulong t1, ref ulong t2, ref ulong t3, ref ulong t6, ref ulong t7)
	{
		ulong s = t0 + (t0 << 40 >> 8);
		ulong q = s & Mask;
		t1 += SignedCarry(s) + (q >> 24) - (q << 48 >> 8);
		t2 -= (q >> 16) + (q << 24 >> 8);
		t3 -= q >> 40;
		t6 += q << 56 >> 8;
		t7 += q >> 8;
	}

	// (x·y mod 2^56) for a·b = x·y·2^8, as for a = x·2^4 and b = y·2^4 or a = x·2^8 and b = y.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong Low(ulong a, ulong b)
	{
		return a * b >> 8;
	}

	// x·y >> 56 for a·b = x·y·2^8, as for a = x·2^4 and b = y·2^4 or a = x·2^8 and b = y.
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

		return Math.BigMul(a, b, out _);
	}

	// ⌊t/2^56⌋ for a t that may be negative.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong SignedCarry(ulong t)
	{
		return (ulong)((long)t >> 56);
	}

	// limbs must be seven canonical limbs that live for the whole process, as the data of a constant span does.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ref readonly P384Field56 FromConstant(ReadOnlySpan<ulong> limbs)
	{
		return ref Unsafe.As<ulong, P384Field56>(ref MemoryMarshal.GetReference(limbs));
	}
}
