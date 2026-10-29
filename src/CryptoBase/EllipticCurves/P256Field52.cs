using static CryptoBase.EllipticCurves.LimbArithmetic;

namespace CryptoBase.EllipticCurves;

// The field of p = 2^256 − 2^224 + 2^192 + 2^96 − 1 in five unsaturated limbs, value Σ L_i·2^(52i), with Montgomery R = 2^260. As p ≡ −1 (mod 2^52), Montgomery reduction needs no multiplication.
// The form E: limbs 0 to 3 below 2^53 and limb 4 below 2^50, so values below 2^258 + 2^210, just over 4p. The IECField members take and give elements of E. The formulas of ECFormulas skip reductions between steps, within these limits:
// Multiply and Square take limbs below 2^56 and give limbs 0 to 3 below 2^52 and a value below x·y/2^260 + p; for inputs of E that is below 2^257 − 2^223, so limb 4 is below 2^49. AddUnreduced adds limbs without carries. SubtractUnreduced adds 5p, so its subtrahend must be of E. WeakReduce takes limbs below 2^62 to limbs 0 to 3 below 2^52, limb 4 below 2^48 + 2^16·⌊L4/2^48⌋ + 2^10 and a value below 2p, so into E.
// For inputs of E the steps of the formulas keep within these limits, and the outputs are of E: X3 and Y3 come from WeakReduce, and Z3 is twice a product of inputs of E, which has limbs 0 to 3 below 2^52 and limb 4 below 2^49. Every input of Multiply and Square has limbs below 2^55, every input of WeakReduce limbs below 2^56, and every subtrahend of SubtractUnreduced is of E. Other intermediate values need not be of E.
// In Double, γ, β and δ are below 2.1p, and 2γ, 4β and 8γ², each twice a product of inputs of E, are of E and below 4.1p. X − δ is below 9.1p in limbs below 2^55 and X + δ below 6.1p in limbs below 2^54. Their product is below 4.4p, so its limb 4 may exceed 2^50 and it is not of E; it goes only into α, below 13.2p in limbs below 2^54, which only Multiply and Square take. α² − 8β is below 21.8p in limbs below 2^55. 4β − X3 is below 9.1p in limbs below 2^55, α(4β − X3) below 8.4p, and that less 8γ² below 13.4p in limbs below 2^54.
// In AddDistinct, U1, U2, S1 and S2 are below 1.6p, so H is below 6.6p in limbs below 2^54 and 2R below 12.8p in limbs below 2^55; reduced, both are below 1.1p in limbs below 2^52. Z1·Z2·H is below 1.2p, so Z3 is below 2.3p. I = 4H² is below 4.3p in limbs below 2^54, not of E, and goes only into Multiply; J, V and S1·J are below 1.4p. With an affine right, whose coordinates are of E as well, H = X2·Z1² − X1 and 2R = 2(Y2·Z1³ − Y1) have the bounds above, Z1·H is below 1.3p, so Z3 is below 2.6p, and V = X1·I and Y1·J are below 2.1p.
// X3 = R² − J − 2V and Y3 = R(V − X3) − 2·SJ then take R below 1.1p and J, V and SJ below 2.1p, in limbs 0 to 3 below 2^52 and limb 4 below 2^50. R² is below 1.1p and R² − J − 2V below 16.1p in limbs below 2^56. V − X3 is below 7.1p in limbs below 2^54, R(V − X3) below 1.5p, and that less 2·SJ below 11.5p in limbs below 2^55.
internal struct P256Field52 : IECField<P256Field52>
{
	internal ulong L0;
	internal ulong L1;
	internal ulong L2;
	internal ulong L3;
	internal ulong L4;

	private const ulong Mask = (1UL << 52) - 1;

	// The limbs of p: 2^52 − 1, 2^44 − 1, 0, 2^36 and 2^48 − 2^16.
	private const ulong P0 = Mask;
	private const ulong P1 = (1UL << 44) - 1;
	private const ulong P3 = 1UL << 36;
	private const ulong P4 = (1UL << 48) - (1UL << 16);

	// 5p with each limb at least the largest limb of E, 2^53 − 1 for limbs 0 to 3 and 2^50 − 1 for limb 4, so that SubtractUnreduced leaves no limb negative.
	private const ulong FiveP0 = 0x002FFFFFFFFFFFFB;
	private const ulong FiveP1 = 0x00204FFFFFFFFFFD;
	private const ulong FiveP2 = 0x002FFFFFFFFFFFFE;
	private const ulong FiveP3 = 0x0020004FFFFFFFFD;
	private const ulong FiveP4 = 0x0004FFFFFFFAFFFE;

	public static ReadOnlySpan<ulong> Modulus => P256Field.Modulus;

	public static int ByteLength => 32;

	public static ref readonly P256Field52 One => ref FromConstant(OneLimbs);

	// 2^260 mod p.
	private static ReadOnlySpan<ulong> OneLimbs => [0x0000000000000010, 0x000F000000000000, 0x000FFFFFFFFFFFFF, 0x000FFEFFFFFFFFFF, 0x00000000000FFFFF];

	// 2^520 mod p, R² for ToMontgomery.
	private static ReadOnlySpan<ulong> RSquaredLimbs => [0x0000000000000300, 0x000FFFFFFFF00000, 0x000FFFFEFFFFFFFB, 0x000FDFFFFFFFFFFF, 0x0000000004FFFFFF];

	// 2^520 mod p in 64-bit limbs: the numerator for SafeGcd, which then takes aR to R²/(aR) = a⁻¹R.
	private static ReadOnlySpan<ulong> InverseNumerator => [0x0000000000000300, 0xFFFFFBFFFFFFFF00, 0xFFFFFFFFFFFFFEFF, 0x000004FFFFFFFDFF];

	// The canonical value in four 64-bit limbs, so that an affine point fills 64 bytes.
	public static int PackedLength => 4;

	public static void FromLimbs(ReadOnlySpan<ulong> limbs, out P256Field52 result)
	{
		Debug.Assert(limbs.Length is 4);

		FromLimbs(limbs[0], limbs[1], limbs[2], limbs[3], out result);
	}

	public static void Pack(in AffinePoint<P256Field52> point, Span<ulong> destination)
	{
		ToSaturated(in point.X, out FieldElement<P256Field> x);
		ToSaturated(in point.Y, out FieldElement<P256Field> y);
		FieldElement<P256Field>.GetLimbs(in x).CopyTo(destination);
		FieldElement<P256Field>.GetLimbs(in y).CopyTo(destination.Slice(PackedLength));
	}

	// The packed Y overlaps the unpacked X, so all eight limbs are read first.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Unpack(ref AffinePoint<P256Field52> point)
	{
		ref ulong limbs = ref Unsafe.As<AffinePoint<P256Field52>, ulong>(ref point);
		ulong x0 = limbs;
		ulong x1 = Unsafe.Add(ref limbs, 1);
		ulong x2 = Unsafe.Add(ref limbs, 2);
		ulong x3 = Unsafe.Add(ref limbs, 3);
		ulong y0 = Unsafe.Add(ref limbs, 4);
		ulong y1 = Unsafe.Add(ref limbs, 5);
		ulong y2 = Unsafe.Add(ref limbs, 6);
		ulong y3 = Unsafe.Add(ref limbs, 7);
		FromLimbs(x0, x1, x2, x3, out point.X);
		FromLimbs(y0, y1, y2, y3, out point.Y);
	}

	public static bool TryImport(ReadOnlySpan<byte> source, out P256Field52 result)
	{
		bool valid = FieldElement<P256Field>.TryImport(source, out FieldElement<P256Field> value);
		FromLimbs(FieldElement<P256Field>.GetLimbs(in value), out result);
		return valid;
	}

	public static void Export(in P256Field52 value, Span<byte> destination)
	{
		ToSaturated(in value, out FieldElement<P256Field> saturated);
		FieldElement<P256Field>.Export(in saturated, destination);
		saturated.ZeroMemory();
	}

	// With a = x_i·2^6 and b = y_j·2^6, a·b = x_i·y_j·2^12 < 2^124 splits at bit 52 of x_i·y_j: the high word is x_i·y_j >> 52 and the low word is (x_i·y_j mod 2^52)·2^12. The column sums of these halves stay below 2^63, so they need no carries before Reduce.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void Multiply(in P256Field52 left, in P256Field52 right, out P256Field52 result)
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

	// As Multiply with right = value. The cross products take d = x_i·2^7 for 2·x_i·x_j.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void Square(in P256Field52 value, out P256Field52 result)
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
		ulong t0 = Low(a0, a0);
		ulong t1 = High(a0, a0) + Low(d0, a1);
		ulong t2 = High(d0, a1) + Low(d0, a2) + Low(a1, a1);
		ulong t3 = High(d0, a2) + High(a1, a1) + Low(d0, a3) + Low(d1, a2);
		ulong t4 = High(d0, a3) + High(d1, a2) + Low(d0, a4) + Low(d1, a3) + Low(a2, a2);
		ulong t5 = High(d0, a4) + High(d1, a3) + High(a2, a2) + Low(d1, a4) + Low(d2, a3);
		ulong t6 = High(d1, a4) + High(d2, a3) + Low(d2, a4) + Low(a3, a3);
		ulong t7 = High(d2, a4) + High(a3, a3) + Low(d3, a4);
		ulong t8 = High(d3, a4) + Low(a4, a4);
		Reduce(t0, t1, t2, t3, t4, t5, t6, t7, t8, High(a4, a4), out result);
	}

	public static void ToMontgomery(in P256Field52 value, out P256Field52 result)
	{
		Multiply(in value, in FromConstant(RSquaredLimbs), out result);
	}

	public static void FromMontgomery(in P256Field52 value, out P256Field52 result)
	{
		P256Field52 one = default;
		one.L0 = 1;
		Multiply(in value, in one, out result);
	}

	// SafeGcd works on the canonical value in 64-bit limbs.
	public static void Invert(in P256Field52 value, out P256Field52 result)
	{
		ToSaturated(in value, out FieldElement<P256Field> saturated);
		SafeGcd<P256Field>.Invert(in saturated, InverseNumerator, out saturated);
		FromLimbs(FieldElement<P256Field>.GetLimbs(in saturated), out result);
		saturated.ZeroMemory();
	}

	public static void InvertVariableTime(in P256Field52 value, out P256Field52 result)
	{
		ToSaturated(in value, out FieldElement<P256Field> saturated);
		SafeGcd<P256Field>.InvertVariableTime(in saturated, InverseNumerator, out saturated);
		FromLimbs(FieldElement<P256Field>.GetLimbs(in saturated), out result);
	}

	// The limbs add without carries; the caller keeps them within what the next operation takes.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void AddUnreduced(in P256Field52 left, in P256Field52 right, out P256Field52 result)
	{
		result.L0 = left.L0 + right.L0;
		result.L1 = left.L1 + right.L1;
		result.L2 = left.L2 + right.L2;
		result.L3 = left.L3 + right.L3;
		result.L4 = left.L4 + right.L4;
	}

	// left + 5p − right, limb by limb, for right of E: no limb goes negative, and each grows by at most its limb of 5p, below 2^53 + 2^52.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void SubtractUnreduced(in P256Field52 left, in P256Field52 right, out P256Field52 result)
	{
		result.L0 = left.L0 + FiveP0 - right.L0;
		result.L1 = left.L1 + FiveP1 - right.L1;
		result.L2 = left.L2 + FiveP2 - right.L2;
		result.L3 = left.L3 + FiveP3 - right.L3;
		result.L4 = left.L4 + FiveP4 - right.L4;
	}

	// For limbs below 2^62: subtracts h·p for h = L4 >> 48, then carries. As h·p = h·2^256 − h·(2^224 − 2^192 − 2^96 + 1), h·2^256 comes off limb 4 and the rest goes in as h·2^16 at limb 4, −h·2^36 at limb 3, −h·2^44 at limb 1 and h at limb 0. The value stays non-negative, as it was at least h·2^256, but limbs 1 and 3 may go negative before the carries, so the carries shift arithmetically. Limbs 0 to 3 come out below 2^52 and the value below 2^256 + 2^218 + h·2^224, so limb 4 below 2^48 + 2^16·h + 2^10, and h < 2^14 puts the value below 2p.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void WeakReduce(in P256Field52 value, out P256Field52 result)
	{
		ulong h = value.L4 >> 48;
		ulong t0 = value.L0 + h;
		ulong t1 = value.L1 - (h << 44);
		ulong t2 = value.L2;
		ulong t3 = value.L3 - (h << 36);
		ulong t4 = (value.L4 & 0xFFFF_FFFF_FFFF) + (h << 16);
		t1 += t0 >> 52;
		t2 += SignedCarry(t1);
		t3 += SignedCarry(t2);
		result.L0 = t0 & Mask;
		result.L1 = t1 & Mask;
		result.L2 = t2 & Mask;
		result.L3 = t3 & Mask;
		result.L4 = t4 + SignedCarry(t3);
	}

	// For the output of WeakReduce: its value is below 2p and its limbs 0 to 3 below 2^52, so it is 0 mod p just if its limbs are those of 0 or of p.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ulong IsReducedZero(in P256Field52 value)
	{
		ulong zero = value.L0 | value.L1 | value.L2 | value.L3 | value.L4;
		ulong modulus = value.L0 ^ P0 | value.L1 ^ P1 | value.L2 | value.L3 ^ P3 | value.L4 ^ P4;
		return ZeroMask(zero) | ZeroMask(modulus);
	}

	// The value mod p in four 64-bit limbs. After WeakReduce the value is below 2p, so one conditional subtraction of p makes it canonical; then limbs 0 to 3 below 2^52 and a value below 2^256 pack without overlap.
	private static void ToSaturated(in P256Field52 value, out FieldElement<P256Field> result)
	{
		WeakReduce(in value, out P256Field52 t);
		ulong d0 = t.L0 - P0;
		ulong d1 = t.L1 - P1 + SignedCarry(d0);
		ulong d2 = t.L2 + SignedCarry(d1);
		ulong d3 = t.L3 - P3 + SignedCarry(d2);
		ulong d4 = t.L4 - P4 + SignedCarry(d3);
		// All ones if t < p.
		ulong keep = (ulong)((long)d4 >> 63);
		ulong l0 = Select(keep, t.L0, d0 & Mask);
		ulong l1 = Select(keep, t.L1, d1 & Mask);
		ulong l2 = Select(keep, t.L2, d2 & Mask);
		ulong l3 = Select(keep, t.L3, d3 & Mask);
		ulong l4 = Select(keep, t.L4, d4);
		Unsafe.SkipInit(out result);
		ref ulong limbs = ref Unsafe.As<FieldElement<P256Field>, ulong>(ref result);
		limbs = l0 | l1 << 52;
		Unsafe.Add(ref limbs, 1) = l1 >> 12 | l2 << 40;
		Unsafe.Add(ref limbs, 2) = l2 >> 24 | l3 << 28;
		Unsafe.Add(ref limbs, 3) = l3 >> 36 | l4 << 16;
		t.ZeroMemory();
	}

	// The value of four 64-bit limbs below p.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FromLimbs(ulong w0, ulong w1, ulong w2, ulong w3, out P256Field52 result)
	{
		result.L0 = w0 & Mask;
		result.L1 = (w0 >> 52 | w1 << 12) & Mask;
		result.L2 = (w1 >> 40 | w2 << 24) & Mask;
		result.L3 = (w2 >> 28 | w3 << 36) & Mask;
		result.L4 = w3 >> 16;
	}

	// Five Montgomery rounds on t = Σ t_k·2^(52k). As p ≡ −1 (mod 2^52), round k takes q = t_k mod 2^52 and adds q·p = q·(p + 1) − q: the −q clears limb k, leaving its carry, and Spread adds q·(p + 1) to the limbs above. Limbs 5 to 9, carried, are the result. Limbs 0 to 3 of t never go negative, limbs 4 to 9 may, so their carries shift arithmetically; for inputs below 2^56 every limb stays below 2^63 in magnitude. The result is (t + Q·p)/2^260 for some 0 ≤ Q < 2^260, so non-negative and below t/2^260 + p, with limbs 0 to 3 below 2^52.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Reduce(ulong t0, ulong t1, ulong t2, ulong t3, ulong t4, ulong t5, ulong t6, ulong t7, ulong t8, ulong t9, out P256Field52 result)
	{
		// t0 is below 2^52, so it is q itself and carries nothing.
		ulong q = t0;
		t1 += Spread1(q);
		t2 += Spread2(q);
		t3 += Spread3(q);
		t4 += Spread4(q);
		t5 += Spread5(q);
		q = t1 & Mask;
		t2 += (t1 >> 52) + Spread1(q);
		t3 += Spread2(q);
		t4 += Spread3(q);
		t5 += Spread4(q);
		t6 += Spread5(q);
		q = t2 & Mask;
		t3 += (t2 >> 52) + Spread1(q);
		t4 += Spread2(q);
		t5 += Spread3(q);
		t6 += Spread4(q);
		t7 += Spread5(q);
		q = t3 & Mask;
		t4 += (t3 >> 52) + Spread1(q);
		t5 += Spread2(q);
		t6 += Spread3(q);
		t7 += Spread4(q);
		t8 += Spread5(q);
		q = t4 & Mask;
		t5 += SignedCarry(t4) + Spread1(q);
		t6 += Spread2(q);
		t7 += Spread3(q);
		t8 += Spread4(q);
		t9 += Spread5(q);
		t6 += SignedCarry(t5);
		t7 += SignedCarry(t6);
		t8 += SignedCarry(t7);
		result.L0 = t5 & Mask;
		result.L1 = t6 & Mask;
		result.L2 = t7 & Mask;
		result.L3 = t8 & Mask;
		result.L4 = t9 + SignedCarry(t8);
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

		// Math.BigMul would call its software fallback here rather than inline it. One of a and b is below 2^62 and the other below 2^63, so the two cross products of their 32-bit halves and the carry out of the low product sum below 2^64 without a carry.
		ulong aHigh = a >> 32;
		ulong aLow = (uint)a;
		ulong bHigh = b >> 32;
		ulong bLow = (uint)b;
		ulong middle = aHigh * bLow + aLow * bHigh + (aLow * bLow >> 32);
		return aHigh * bHigh + (middle >> 32);
	}

	// Spread1 to Spread5 give limbs i + 1 to i + 5 of q·(p + 1) for q below 2^52 at limb i: p + 1 = 2^96 + 2^192 + 2^256 − 2^224 is 2^44 at limb i + 1, 2^36 at limb i + 3 and 2^48 − 2^16 at limb i + 4, and each shifted q splits at the limb boundary. Only Spread4 can be negative.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong Spread1(ulong q)
	{
		return (q & 0xFF) << 44;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong Spread2(ulong q)
	{
		return q >> 8;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong Spread3(ulong q)
	{
		return (q & 0xFFFF) << 36;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong Spread4(ulong q)
	{
		return (q >> 16) + ((q & 0xF) << 48) - (q << 28 >> 12);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong Spread5(ulong q)
	{
		return (q >> 4) - (q >> 36);
	}

	// ⌊t/2^52⌋ for a t that may be negative.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong SignedCarry(ulong t)
	{
		return (ulong)((long)t >> 52);
	}

	// limbs must be five canonical limbs that live for the whole process, as the data of a constant span does.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ref readonly P256Field52 FromConstant(ReadOnlySpan<ulong> limbs)
	{
		return ref Unsafe.As<ulong, P256Field52>(ref MemoryMarshal.GetReference(limbs));
	}
}
