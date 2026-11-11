using System.Diagnostics.CodeAnalysis;
using static CryptoBase.EllipticCurves.LimbArithmetic;

namespace CryptoBase.EllipticCurves.Curve25519;

// The field of p = 2^255 − 19 in five unsaturated limbs, value Σ L_i·2^(51i). As 2^255 ≡ 19 (mod p), what carries out of limb 4 comes back into limb 0 times 19.
// An element is tight if limb 0 is below 2^51 + 2^18 and limbs 1 to 4 below 2^51 + 2^13. Every member that gives an element gives a tight one, and the constants are tight, except Add, Subtract and SubtractFromFourP, which do not carry, and Reduce, which gives the canonical element: limbs below 2^51 and a value below p. Every limb of a tight element is below that of 2p, so Subtract may take it as its right operand.
// The callers of Add, Subtract and SubtractFromFourP keep the limbs within what the next operation takes: below 2^54 for Multiply, Square, MultiplySmall and PowerP58, and below 2^63 for the members that reduce first, which are Carry, Reduce, the zero and sign tests, the inversions and the encodings.
// No member but InvertVariableTime branches on or indexes by a value; masks are 0 or ulong.MaxValue. Any result may be the same variable as an input.
internal struct Field25519
{
	internal ulong L0;
	internal ulong L1;
	internal ulong L2;
	internal ulong L3;
	internal ulong L4;

	internal const int ByteLength = 32;

	private const ulong Mask = (1UL << 51) - 1;

	// The limbs of 2p = 2^256 − 38 and 4p = 2^257 − 76, each at least the largest limb of a tight element or, for 4p, of a sum of two.
	private const ulong TwoP0 = (1UL << 52) - 38;
	private const ulong TwoP = (1UL << 52) - 2;
	private const ulong FourP0 = (1UL << 53) - 76;
	private const ulong FourP = (1UL << 53) - 4;

	internal static ref readonly Field25519 One => ref FromConstant(OneLimbs);

	// 2^((p − 1)/4), a square root of −1.
	internal static ref readonly Field25519 SqrtMinusOne => ref FromConstant(SqrtMinusOneLimbs);

	private static ReadOnlySpan<ulong> OneLimbs => [1, 0, 0, 0, 0];

	private static ReadOnlySpan<ulong> SqrtMinusOneLimbs => [0x00061B274A0EA0B0, 0x0000D5A5FC8F189D, 0x0007EF5E9CBD0C60, 0x00078595A6804C9E, 0x0002B8324804FC1D];

	// Reads 32 little-endian bytes without bit 255, which X25519 ignores and the Edwards encoding uses for the sign of x. A value of p or more is kept as it is, with limbs below 2^51; the arithmetic reduces it.
	internal static void FromBytes(ReadOnlySpan<byte> source, out Field25519 result)
	{
		Debug.Assert(source.Length is ByteLength);

		ulong w0 = BinaryPrimitives.ReadUInt64LittleEndian(source);
		ulong w1 = BinaryPrimitives.ReadUInt64LittleEndian(source.Slice(8));
		ulong w2 = BinaryPrimitives.ReadUInt64LittleEndian(source.Slice(16));
		ulong w3 = BinaryPrimitives.ReadUInt64LittleEndian(source.Slice(24));
		result.L0 = w0 & Mask;
		result.L1 = (w0 >> 51 | w1 << 13) & Mask;
		result.L2 = (w1 >> 38 | w2 << 26) & Mask;
		result.L3 = (w2 >> 25 | w3 << 39) & Mask;
		result.L4 = w3 >> 12 & Mask;
	}

	// Writes the canonical value in 32 little-endian bytes, bit 255 clear.
	internal static void ToBytes(in Field25519 value, Span<byte> destination)
	{
		Debug.Assert(destination.Length is ByteLength);

		Reduce(in value, out Field25519 r);
		BinaryPrimitives.WriteUInt64LittleEndian(destination, r.L0 | r.L1 << 51);
		BinaryPrimitives.WriteUInt64LittleEndian(destination.Slice(8), r.L1 >> 13 | r.L2 << 38);
		BinaryPrimitives.WriteUInt64LittleEndian(destination.Slice(16), r.L2 >> 26 | r.L3 << 25);
		BinaryPrimitives.WriteUInt64LittleEndian(destination.Slice(24), r.L3 >> 39 | r.L4 << 12);
		r.ZeroMemory();
	}

	// The canonical value in four 64-bit limbs, least significant first.
	internal static void ToLimbs(in Field25519 value, Span<ulong> destination)
	{
		Debug.Assert(destination.Length is 4);

		Reduce(in value, out Field25519 r);
		destination[0] = r.L0 | r.L1 << 51;
		destination[1] = r.L1 >> 13 | r.L2 << 38;
		destination[2] = r.L2 >> 26 | r.L3 << 25;
		destination[3] = r.L3 >> 39 | r.L4 << 12;
		r.ZeroMemory();
	}

	// The element of four 64-bit limbs of a value below 2^255, as ToLimbs writes them.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void FromLimbs(ulong w0, ulong w1, ulong w2, ulong w3, out Field25519 result)
	{
		result.L0 = w0 & Mask;
		result.L1 = (w0 >> 51 | w1 << 13) & Mask;
		result.L2 = (w1 >> 38 | w2 << 26) & Mask;
		result.L3 = (w2 >> 25 | w3 << 39) & Mask;
		result.L4 = w3 >> 12;
	}

	// For limbs below 2^51, as FromBytes gives: ulong.MaxValue if the value is below p and 0 otherwise. The values from p to 2^255 − 1 are those to which adding 19 carries out of bit 254.
	internal static ulong IsBelowModulus(in Field25519 value)
	{
		ulong carry = value.L0 + 19 >> 51;
		carry = value.L1 + carry >> 51;
		carry = value.L2 + carry >> 51;
		carry = value.L3 + carry >> 51;
		carry = value.L4 + carry >> 51;
		return carry - 1;
	}

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	internal static void Multiply(in Field25519 left, in Field25519 right, out Field25519 result)
	{
		MultiplyCore(in left, in right, out result, true);
	}

	// Multiply inlined, for formulas that keep the values between their products in registers, where the high word of a 64-bit product takes one instruction, mulx or umulh. Elsewhere it takes four multiplications and spills, so the formulas call Multiply there, whose copy alone sets outOfLine. The test names the instruction sets rather than a property so that the JIT folds it before it reads the call, and the address of result never reaches a call where the product is inlined. With a = x_i·2^6 and b = y_j·2^7, a·b = x_i·y_j·2^13 splits at bit 51 of x_i·y_j: the high word is x_i·y_j >> 51 and the low word is (x_i·y_j mod 2^51)·2^13. For limbs below 2^54 the high words are below 2^57, so the columns t_k of the product, each a sum of at most nine halves, stay below 5·2^57 + 2^53, and the folded t_k + 19·t_(k+5) below 97·2^57 < 2^64.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	[SuppressMessage("ReSharper", "ArrangeRedundantParentheses", Justification = "The parentheses balance the column sums, and the JIT adds in the order they give.")]
	internal static void MultiplyCore(in Field25519 left, in Field25519 right, out Field25519 result, bool outOfLine = false)
	{
		if (!outOfLine && !(Bmi2.X64.IsSupported || ArmBase.Arm64.IsSupported))
		{
			Multiply(in left, in right, out result);
			return;
		}

		ulong a0 = left.L0 << 6;
		ulong a1 = left.L1 << 6;
		ulong a2 = left.L2 << 6;
		ulong a3 = left.L3 << 6;
		ulong a4 = left.L4 << 6;
		ulong b0 = right.L0 << 7;
		ulong b1 = right.L1 << 7;
		ulong b2 = right.L2 << 7;
		ulong b3 = right.L3 << 7;
		ulong b4 = right.L4 << 7;
		ulong t0 = Low(a0, b0);
		ulong t1 = High(a0, b0) + (Low(a0, b1) + Low(a1, b0));
		ulong t2 = (High(a0, b1) + High(a1, b0)) + (Low(a0, b2) + Low(a1, b1)) + Low(a2, b0);
		ulong t3 = (High(a0, b2) + High(a1, b1)) + (High(a2, b0) + Low(a0, b3)) + ((Low(a1, b2) + Low(a2, b1)) + Low(a3, b0));
		ulong t4 = ((High(a0, b3) + High(a1, b2)) + (High(a2, b1) + High(a3, b0))) + ((Low(a0, b4) + Low(a1, b3)) + (Low(a2, b2) + Low(a3, b1))) + Low(a4, b0);
		ulong t5 = ((High(a0, b4) + High(a1, b3)) + (High(a2, b2) + High(a3, b1))) + ((High(a4, b0) + Low(a1, b4)) + (Low(a2, b3) + Low(a3, b2))) + Low(a4, b1);
		ulong t6 = (High(a1, b4) + High(a2, b3)) + (High(a3, b2) + High(a4, b1)) + ((Low(a2, b4) + Low(a3, b3)) + Low(a4, b2));
		ulong t7 = (High(a2, b4) + High(a3, b3)) + (High(a4, b2) + Low(a3, b4)) + Low(a4, b3);
		ulong t8 = (High(a3, b4) + High(a4, b3)) + Low(a4, b4);
		ulong t9 = High(a4, b4);
		Carry(t0 + 19 * t5, t1 + 19 * t6, t2 + 19 * t7, t3 + 19 * t8, t4 + 19 * t9, out result);
	}

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	internal static void Square(in Field25519 value, out Field25519 result)
	{
		SquareCore(in value, out result, true);
	}

	// value^(2^count) for count ≥ 1, with the squares inlined into the loop on every platform, so that each one takes the last in registers.
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	internal static void SquareTimes(in Field25519 value, int count, out Field25519 result)
	{
		Debug.Assert(count >= 1);

		Field25519 t = value;

		for (int i = 0; i < count; ++i)
		{
			SquareCore(in t, out t, true);
		}

		result = t;
	}

	// Square inlined where MultiplyCore is, and with outOfLine set; as MultiplyCore with right = value, a square takes a_i·b_i, and the doubled cross product 2·x_i·x_j takes b_i·b_j = x_i·x_j·2^14. The high words of those are below 2^58, and the columns keep the bounds of Multiply.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	[SuppressMessage("ReSharper", "ArrangeRedundantParentheses", Justification = "The parentheses balance the column sums, and the JIT adds in the order they give.")]
	internal static void SquareCore(in Field25519 value, out Field25519 result, bool outOfLine = false)
	{
		if (!outOfLine && !(Bmi2.X64.IsSupported || ArmBase.Arm64.IsSupported))
		{
			Square(in value, out result);
			return;
		}

		ulong a0 = value.L0 << 6;
		ulong a1 = value.L1 << 6;
		ulong a2 = value.L2 << 6;
		ulong a3 = value.L3 << 6;
		ulong a4 = value.L4 << 6;
		ulong b0 = value.L0 << 7;
		ulong b1 = value.L1 << 7;
		ulong b2 = value.L2 << 7;
		ulong b3 = value.L3 << 7;
		ulong b4 = value.L4 << 7;
		ulong t0 = Low(a0, b0);
		ulong t1 = High(a0, b0) + Low(b0, b1);
		ulong t2 = High(b0, b1) + (Low(b0, b2) + Low(a1, b1));
		ulong t3 = (High(b0, b2) + High(a1, b1)) + (Low(b0, b3) + Low(b1, b2));
		ulong t4 = (High(b0, b3) + High(b1, b2)) + (Low(b0, b4) + Low(b1, b3)) + Low(a2, b2);
		ulong t5 = (High(b0, b4) + High(b1, b3)) + (High(a2, b2) + Low(b1, b4)) + Low(b2, b3);
		ulong t6 = (High(b1, b4) + High(b2, b3)) + (Low(b2, b4) + Low(a3, b3));
		ulong t7 = (High(b2, b4) + High(a3, b3)) + Low(b3, b4);
		ulong t8 = High(b3, b4) + Low(a4, b4);
		ulong t9 = High(a4, b4);
		Carry(t0 + 19 * t5, t1 + 19 * t6, t2 + 19 * t7, t3 + 19 * t8, t4 + 19 * t9, out result);
	}

	// value·c for c below 2^17 and limbs below 2^54. Each limb times c splits at bit 51 as in Multiply, into a part below 2^51 and one below 2^20, the part above limb 4 back at limb 0 times 19; one carry then leaves the limbs tight.
	internal static void MultiplySmall(in Field25519 value, uint c, out Field25519 result)
	{
		Debug.Assert(c < 1u << 17);

		ulong b = (ulong)c << 7;
		ulong a0 = value.L0 << 6;
		ulong a1 = value.L1 << 6;
		ulong a2 = value.L2 << 6;
		ulong a3 = value.L3 << 6;
		ulong a4 = value.L4 << 6;
		Field25519 product;
		product.L0 = Low(a0, b) + 19 * High(a4, b);
		product.L1 = Low(a1, b) + High(a0, b);
		product.L2 = Low(a2, b) + High(a1, b);
		product.L3 = Low(a3, b) + High(a2, b);
		product.L4 = Low(a4, b) + High(a3, b);
		Carry(in product, out result);
	}

	// Limb by limb, without carries.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Add(in Field25519 left, in Field25519 right, out Field25519 result)
	{
		result.L0 = left.L0 + right.L0;
		result.L1 = left.L1 + right.L1;
		result.L2 = left.L2 + right.L2;
		result.L3 = left.L3 + right.L3;
		result.L4 = left.L4 + right.L4;
	}

	// left + 2p − right limb by limb, for a right whose limbs are at most those of 2p, as a tight one's are: no limb goes negative, and each grows by below 2^52.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Subtract(in Field25519 left, in Field25519 right, out Field25519 result)
	{
		result.L0 = left.L0 + TwoP0 - right.L0;
		result.L1 = left.L1 + TwoP - right.L1;
		result.L2 = left.L2 + TwoP - right.L2;
		result.L3 = left.L3 + TwoP - right.L3;
		result.L4 = left.L4 + TwoP - right.L4;
	}

	// left + 4p − right limb by limb, for a right whose limbs are at most those of 4p, as those of a sum of two tight elements are: each limb grows by below 2^53.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void SubtractFromFourP(in Field25519 left, in Field25519 right, out Field25519 result)
	{
		result.L0 = left.L0 + FourP0 - right.L0;
		result.L1 = left.L1 + FourP - right.L1;
		result.L2 = left.L2 + FourP - right.L2;
		result.L3 = left.L3 + FourP - right.L3;
		result.L4 = left.L4 + FourP - right.L4;
	}

	// 2p − value, carried, for limbs at most those of 2p.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Negate(in Field25519 value, out Field25519 result)
	{
		Field25519 difference;
		difference.L0 = TwoP0 - value.L0;
		difference.L1 = TwoP - value.L1;
		difference.L2 = TwoP - value.L2;
		difference.L3 = TwoP - value.L3;
		difference.L4 = TwoP - value.L4;
		Carry(in difference, out result);
	}

	// Any limbs to a tight element: each limb keeps its low 51 bits and gains the carry out of the one below, limb 0 that of limb 4 times 19. The carries are below 2^13, so limb 0 ends below 2^51 + 19·2^13 and the others below 2^51 + 2^13.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Carry(in Field25519 value, out Field25519 result)
	{
		ulong c0 = value.L0 >> 51;
		ulong c1 = value.L1 >> 51;
		ulong c2 = value.L2 >> 51;
		ulong c3 = value.L3 >> 51;
		ulong c4 = value.L4 >> 51;
		result.L0 = (value.L0 & Mask) + 19 * c4;
		result.L1 = (value.L1 & Mask) + c0;
		result.L2 = (value.L2 & Mask) + c1;
		result.L3 = (value.L3 & Mask) + c2;
		result.L4 = (value.L4 & Mask) + c3;
	}

	// The canonical value. Carry leaves a tight element, below 2p, and q = 1 just if it is p or more, which is where adding 19 carries out of bit 254 through the limbs. Adding 19q and dropping bit 255 then subtracts qp: the sum is below 2^256, and its bit 255 is q.
	internal static void Reduce(in Field25519 value, out Field25519 result)
	{
		Carry(in value, out Field25519 t);
		ulong q = t.L0 + 19 >> 51;
		q = t.L1 + q >> 51;
		q = t.L2 + q >> 51;
		q = t.L3 + q >> 51;
		q = t.L4 + q >> 51;
		ulong l0 = t.L0 + 19 * q;
		ulong l1 = t.L1 + (l0 >> 51);
		ulong l2 = t.L2 + (l1 >> 51);
		ulong l3 = t.L3 + (l2 >> 51);
		ulong l4 = t.L4 + (l3 >> 51);
		result.L0 = l0 & Mask;
		result.L1 = l1 & Mask;
		result.L2 = l2 & Mask;
		result.L3 = l3 & Mask;
		result.L4 = l4 & Mask;
	}

	// ulong.MaxValue if the value is 0 mod p and 0 otherwise.
	internal static ulong IsZero(in Field25519 value)
	{
		Reduce(in value, out Field25519 r);
		return ZeroMask(r.L0 | r.L1 | r.L2 | r.L3 | r.L4);
	}

	// ulong.MaxValue if the canonical value is odd, which RFC 8032 calls negative, and 0 otherwise.
	internal static ulong IsNegative(in Field25519 value)
	{
		Reduce(in value, out Field25519 r);
		return 0 - (r.L0 & 1);
	}

	// For a right whose limbs are at most those of 2p.
	internal static ulong AreEqual(in Field25519 left, in Field25519 right)
	{
		Subtract(in left, in right, out Field25519 difference);
		return IsZero(in difference);
	}

	// Limb by limb, which keeps the form of the inputs.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void ConditionalSelect(ulong mask, in Field25519 whenSet, in Field25519 whenClear, out Field25519 result)
	{
		result.L0 = Select(mask, whenSet.L0, whenClear.L0);
		result.L1 = Select(mask, whenSet.L1, whenClear.L1);
		result.L2 = Select(mask, whenSet.L2, whenClear.L2);
		result.L3 = Select(mask, whenSet.L3, whenClear.L3);
		result.L4 = Select(mask, whenSet.L4, whenClear.L4);
	}

	// Swaps left and right where mask is set. They must be different variables.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void ConditionalSwap(ulong mask, ref Field25519 left, ref Field25519 right)
	{
		ulong t0 = (left.L0 ^ right.L0) & mask;
		ulong t1 = (left.L1 ^ right.L1) & mask;
		ulong t2 = (left.L2 ^ right.L2) & mask;
		ulong t3 = (left.L3 ^ right.L3) & mask;
		ulong t4 = (left.L4 ^ right.L4) & mask;
		left.L0 ^= t0;
		left.L1 ^= t1;
		left.L2 ^= t2;
		left.L3 ^= t3;
		left.L4 ^= t4;
		right.L0 ^= t0;
		right.L1 ^= t1;
		right.L2 ^= t2;
		right.L3 ^= t3;
		right.L4 ^= t4;
	}

	// For limbs at most those of 2p; the result is tight either way.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void ConditionalNegate(ulong mask, ref Field25519 value)
	{
		Negate(in value, out Field25519 negated);
		Carry(in value, out value);
		ConditionalSelect(mask, in negated, in value, out value);
	}

	// 1/value, and 0 for 0, by SafeGcd on the canonical value. Neither the time nor the addresses depend on value.
	[SkipLocalsInit]
	internal static void Invert(in Field25519 value, out Field25519 result)
	{
		Span<ulong> limbs = stackalloc ulong[4];
		ToLimbs(in value, limbs);
		SafeGcd<Curve25519Modulus>.Invert(in AsElement(limbs), Curve25519Modulus.One, out FieldElement<Curve25519Modulus> inverse);
		FromElement(in inverse, out result);
		limbs.ZeroMemory();
		inverse.ZeroMemory();
	}

	// As above for a public value: the time depends on it.
	[SkipLocalsInit]
	internal static void InvertVariableTime(in Field25519 value, out Field25519 result)
	{
		Span<ulong> limbs = stackalloc ulong[4];
		ToLimbs(in value, limbs);
		SafeGcd<Curve25519Modulus>.InvertVariableTime(in AsElement(limbs), Curve25519Modulus.One, out FieldElement<Curve25519Modulus> inverse);
		FromElement(in inverse, out result);
	}

	// value^((p − 5)/8) = value^(2^252 − 3) = (value^(2^250 − 1))^4·value: 251 squarings and 11 products, by way of value^11 and value^(2^(5k) − 1).
	internal static void PowerP58(in Field25519 value, out Field25519 result)
	{
		Square(in value, out Field25519 t0);
		SquareTimes(in t0, 2, out Field25519 t1);
		Multiply(in value, in t1, out t1);
		Multiply(in t0, in t1, out t0);
		Square(in t0, out t0);
		Multiply(in t1, in t0, out t1);
		SquareTimes(in t1, 5, out t0);
		Multiply(in t0, in t1, out t1);
		SquareTimes(in t1, 10, out t0);
		Multiply(in t0, in t1, out t0);
		SquareTimes(in t0, 20, out Field25519 t2);
		Multiply(in t2, in t0, out t0);
		SquareTimes(in t0, 10, out t0);
		Multiply(in t0, in t1, out t1);
		SquareTimes(in t1, 50, out t0);
		Multiply(in t0, in t1, out t0);
		SquareTimes(in t0, 100, out t2);
		Multiply(in t2, in t0, out t0);
		SquareTimes(in t0, 50, out t0);
		Multiply(in t0, in t1, out t0);
		SquareTimes(in t0, 2, out t0);
		Multiply(in t0, in value, out result);
		t0.ZeroMemory();
		t1.ZeroMemory();
		t2.ZeroMemory();
	}

	// Sets result to an r with v·r² = u and returns ulong.MaxValue if there is one; returns 0 otherwise. For v ≠ 0 that is whether u/v is a square; for v = 0 only u = 0 has one, the root 0. u must be tight. As p ≡ 5 (mod 8), r = u·v³·(u·v⁷)^((p − 5)/8) = (u/v)^((p + 3)/8) has r⁴ = (u/v)²·(u/v)^((p − 1)/2), so for a square u/v, v·r² is u or −u, and in the second case r·sqrt(−1) is a root.
	internal static ulong SqrtRatio(in Field25519 u, in Field25519 v, out Field25519 result)
	{
		Square(in v, out Field25519 v3);
		Multiply(in v3, in v, out v3);
		Square(in v3, out Field25519 r);
		Multiply(in r, in v, out r);
		Multiply(in r, in u, out r);
		PowerP58(in r, out r);
		Multiply(in r, in v3, out r);
		Multiply(in r, in u, out r);
		Square(in r, out Field25519 check);
		Multiply(in check, in v, out check);
		ulong correct = AreEqual(in check, in u);
		Negate(in u, out Field25519 negated);
		ulong flipped = AreEqual(in check, in negated);
		Multiply(in r, in SqrtMinusOne, out Field25519 rotated);
		ConditionalSelect(flipped, in rotated, in r, out result);
		v3.ZeroMemory();
		r.ZeroMemory();
		check.ZeroMemory();
		negated.ZeroMemory();
		rotated.ZeroMemory();
		return correct | flipped;
	}

	// The four limbs of ToLimbs, read as the element of SafeGcd, which holds them as they are.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ref readonly FieldElement<Curve25519Modulus> AsElement(Span<ulong> limbs)
	{
		return ref Unsafe.As<ulong, FieldElement<Curve25519Modulus>>(ref MemoryMarshal.GetReference(limbs));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FromElement(in FieldElement<Curve25519Modulus> value, out Field25519 result)
	{
		ReadOnlySpan<ulong> limbs = FieldElement<Curve25519Modulus>.GetLimbs(in value);
		FromLimbs(limbs[0], limbs[1], limbs[2], limbs[3], out result);
	}

	// Carries r_0 to r_4, each below 2^64, all at once, as the public Carry does: each limb keeps its low 51 bits and gains the carry out of the one below, below 2^13, limb 0 that of limb 4 times 19, which leaves a tight element.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Carry(ulong r0, ulong r1, ulong r2, ulong r3, ulong r4, out Field25519 result)
	{
		result.L0 = (r0 & Mask) + 19 * (r4 >> 51);
		result.L1 = (r1 & Mask) + (r0 >> 51);
		result.L2 = (r2 & Mask) + (r1 >> 51);
		result.L3 = (r3 & Mask) + (r2 >> 51);
		result.L4 = (r4 & Mask) + (r3 >> 51);
	}

	// (x·y mod 2^51) for a = x·2^6 and b = y·2^7.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong Low(ulong a, ulong b)
	{
		return a * b >> 13;
	}

	// x·y >> 51 for a = x·2^6 and b = y·2^7.
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

		// Math.BigMul would call its software fallback here rather than inline it. Both a and b are below 2^62, so the two cross products of their 32-bit halves and the carry out of the low product sum below 2^64 without a carry.
		ulong aHigh = a >> 32;
		ulong aLow = (uint)a;
		ulong bHigh = b >> 32;
		ulong bLow = (uint)b;
		ulong middle = aHigh * bLow + aLow * bHigh + (aLow * bLow >> 32);
		return aHigh * bHigh + (middle >> 32);
	}

	// limbs must be five tight limbs that live for the whole process, as the data of a constant span does.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static ref readonly Field25519 FromConstant(ReadOnlySpan<ulong> limbs)
	{
		Debug.Assert(limbs.Length is 5);

		return ref Unsafe.As<ulong, Field25519>(ref MemoryMarshal.GetReference(limbs));
	}
}
