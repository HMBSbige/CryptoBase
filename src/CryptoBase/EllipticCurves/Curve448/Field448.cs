using System.Diagnostics.CodeAnalysis;
using static CryptoBase.EllipticCurves.LimbArithmetic;

namespace CryptoBase.EllipticCurves.Curve448;

// The field of p = 2^448 − 2^224 − 1 in eight unsaturated limbs, value Σ L_i·2^(56i). As 2^448 ≡ 2^224 + 1 (mod p), what carries out of limb 7 comes back into limbs 0 and 4.
// An element is tight if every limb is below 2^56 + 2^9. Every member that gives an element gives a tight one, and the constants are tight, except Add, Subtract and SubtractFromFourP, which do not carry, and Reduce, which gives the canonical element: limbs below 2^56 and a value below p. Every limb of a tight element is below that of 2p, so Subtract may take it as its right operand.
// Multiply takes limbs below x·2^56 on the left and y·2^56 on the right for any x, y ≤ 8 with xy ≤ 12.25, such as a sum of two tight elements, below 2^57 + 2^10, by a difference of two, below 3·2^56 + 2^9, or the latter by a sum of two less a third, below 4·2^56 + 2^10. Square takes limbs below 3.5·2^56, those of a difference included. The callers of Add, Subtract and SubtractFromFourP keep the limbs within what the next operation takes; Carry, Reduce, the zero and sign tests, the inversions and the encodings take any limbs.
// No member but InvertVariableTime branches on or indexes by a value; masks are 0 or ulong.MaxValue. Any result may be the same variable as an input.
internal struct Field448
{
	internal ulong L0;
	internal ulong L1;
	internal ulong L2;
	internal ulong L3;
	internal ulong L4;
	internal ulong L5;
	internal ulong L6;
	internal ulong L7;

	internal const int ByteLength = 56;

	private const ulong Mask = (1UL << 56) - 1;

	// The limbs of 2p and 4p; limb 4 of p is 2^56 − 2, one less than the others. Each limb of 2p is at least the largest limb of a tight element, and each of 4p that of a sum of two.
	private const ulong TwoP = (1UL << 57) - 2;
	private const ulong TwoP4 = (1UL << 57) - 4;
	private const ulong FourP = (1UL << 58) - 4;
	private const ulong FourP4 = (1UL << 58) - 8;

	// The radix of the limbs of IField448Lanes, two to each limb here.
	private const int HalfBits = 28;
	private const ulong HalfMask = (1UL << HalfBits) - 1;

	internal static ref readonly Field448 One => ref FromConstant(OneLimbs);

	private static ReadOnlySpan<ulong> OneLimbs => [1, 0, 0, 0, 0, 0, 0, 0];

	// Reads 56 little-endian bytes, all 448 bits, as X448 takes them. A value of p or more is kept as it is, with limbs below 2^56; the arithmetic reduces it.
	internal static void FromBytes(ReadOnlySpan<byte> source, out Field448 result)
	{
		Debug.Assert(source.Length is ByteLength);

		ulong w0 = BinaryPrimitives.ReadUInt64LittleEndian(source);
		ulong w1 = BinaryPrimitives.ReadUInt64LittleEndian(source.Slice(8));
		ulong w2 = BinaryPrimitives.ReadUInt64LittleEndian(source.Slice(16));
		ulong w3 = BinaryPrimitives.ReadUInt64LittleEndian(source.Slice(24));
		ulong w4 = BinaryPrimitives.ReadUInt64LittleEndian(source.Slice(32));
		ulong w5 = BinaryPrimitives.ReadUInt64LittleEndian(source.Slice(40));
		ulong w6 = BinaryPrimitives.ReadUInt64LittleEndian(source.Slice(48));
		FromLimbs(w0, w1, w2, w3, w4, w5, w6, out result);
	}

	// Writes the canonical value in 56 little-endian bytes.
	internal static void ToBytes(in Field448 value, Span<byte> destination)
	{
		Debug.Assert(destination.Length is ByteLength);

		Reduce(in value, out Field448 r);
		BinaryPrimitives.WriteUInt64LittleEndian(destination, r.L0 | r.L1 << 56);
		BinaryPrimitives.WriteUInt64LittleEndian(destination.Slice(8), r.L1 >> 8 | r.L2 << 48);
		BinaryPrimitives.WriteUInt64LittleEndian(destination.Slice(16), r.L2 >> 16 | r.L3 << 40);
		BinaryPrimitives.WriteUInt64LittleEndian(destination.Slice(24), r.L3 >> 24 | r.L4 << 32);
		BinaryPrimitives.WriteUInt64LittleEndian(destination.Slice(32), r.L4 >> 32 | r.L5 << 24);
		BinaryPrimitives.WriteUInt64LittleEndian(destination.Slice(40), r.L5 >> 40 | r.L6 << 16);
		BinaryPrimitives.WriteUInt64LittleEndian(destination.Slice(48), r.L6 >> 48 | r.L7 << 8);
		r.ZeroMemory();
	}

	// The canonical value in seven 64-bit limbs, least significant first.
	internal static void ToLimbs(in Field448 value, Span<ulong> destination)
	{
		Debug.Assert(destination.Length is 7);

		Reduce(in value, out Field448 r);
		destination[0] = r.L0 | r.L1 << 56;
		destination[1] = r.L1 >> 8 | r.L2 << 48;
		destination[2] = r.L2 >> 16 | r.L3 << 40;
		destination[3] = r.L3 >> 24 | r.L4 << 32;
		destination[4] = r.L4 >> 32 | r.L5 << 24;
		destination[5] = r.L5 >> 40 | r.L6 << 16;
		destination[6] = r.L6 >> 48 | r.L7 << 8;
		r.ZeroMemory();
	}

	// The element of seven 64-bit limbs, as ToLimbs writes them, with limbs below 2^56.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void FromLimbs(ulong w0, ulong w1, ulong w2, ulong w3, ulong w4, ulong w5, ulong w6, out Field448 result)
	{
		result.L0 = w0 & Mask;
		result.L1 = (w0 >> 56 | w1 << 8) & Mask;
		result.L2 = (w1 >> 48 | w2 << 16) & Mask;
		result.L3 = (w2 >> 40 | w3 << 24) & Mask;
		result.L4 = (w3 >> 32 | w4 << 32) & Mask;
		result.L5 = (w4 >> 24 | w5 << 40) & Mask;
		result.L6 = (w5 >> 16 | w6 << 48) & Mask;
		result.L7 = w6 >> 8;
	}

	// The limbs of two lanes from their 56-bit limbs w0 to w7, carried as Field448x4Avx2.Create carries them.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void ToRadix28(Vector128<ulong> w0, Vector128<ulong> w1, Vector128<ulong> w2, Vector128<ulong> w3, Vector128<ulong> w4, Vector128<ulong> w5, Vector128<ulong> w6, Vector128<ulong> w7, ref Vector128<ulong> result)
	{
		Vector128<ulong> mask = Vector128.Create(HalfMask);
		Vector128<ulong> top = w7 >> 2 * HalfBits;
		result = (w0 & mask) + top;
		Unsafe.Add(ref result, 1) = w0 >> HalfBits & mask;
		Unsafe.Add(ref result, 2) = (w1 & mask) + (w0 >> 2 * HalfBits);
		Unsafe.Add(ref result, 3) = w1 >> HalfBits & mask;
		Unsafe.Add(ref result, 4) = (w2 & mask) + (w1 >> 2 * HalfBits);
		Unsafe.Add(ref result, 5) = w2 >> HalfBits & mask;
		Unsafe.Add(ref result, 6) = (w3 & mask) + (w2 >> 2 * HalfBits);
		Unsafe.Add(ref result, 7) = w3 >> HalfBits & mask;
		Unsafe.Add(ref result, 8) = (w4 & mask) + (w3 >> 2 * HalfBits) + top;
		Unsafe.Add(ref result, 9) = w4 >> HalfBits & mask;
		Unsafe.Add(ref result, 10) = (w5 & mask) + (w4 >> 2 * HalfBits);
		Unsafe.Add(ref result, 11) = w5 >> HalfBits & mask;
		Unsafe.Add(ref result, 12) = (w6 & mask) + (w5 >> 2 * HalfBits);
		Unsafe.Add(ref result, 13) = w6 >> HalfBits & mask;
		Unsafe.Add(ref result, 14) = (w7 & mask) + (w6 >> 2 * HalfBits);
		Unsafe.Add(ref result, 15) = w7 >> HalfBits & mask;
	}

	// One lane, carried limb by limb from limb 0 to limb 15, whose carry, below 2^5, comes back into limbs 0 and 8; pairs of limbs then join into the 56-bit limbs.
	internal static void FromRadix28<TLanes>(in TLanes value, int lane, out Field448 result) where TLanes : struct, IField448Lanes<TLanes>
	{
		Span<ulong> carried = stackalloc ulong[16];
		ulong carry = 0;

		for (int i = 0; i < carried.Length; ++i)
		{
			ulong sum = TLanes.Limb(in value, i, lane) + carry;
			carried[i] = sum & HalfMask;
			carry = sum >> HalfBits;
		}

		carried[0] += carry;
		carried[8] += carry;
		result.L0 = carried[0] + (carried[1] << HalfBits);
		result.L1 = carried[2] + (carried[3] << HalfBits);
		result.L2 = carried[4] + (carried[5] << HalfBits);
		result.L3 = carried[6] + (carried[7] << HalfBits);
		result.L4 = carried[8] + (carried[9] << HalfBits);
		result.L5 = carried[10] + (carried[11] << HalfBits);
		result.L6 = carried[12] + (carried[13] << HalfBits);
		result.L7 = carried[14] + (carried[15] << HalfBits);
		carried.ZeroMemory();
	}

	// For limbs below 2^56, as FromBytes gives: ulong.MaxValue if the value is below p and 0 otherwise. The values from p to 2^448 − 1 are those to which adding 2^224 + 1 carries out of bit 447.
	internal static ulong IsBelowModulus(in Field448 value)
	{
		ulong carry = value.L0 + 1 >> 56;
		carry = value.L1 + carry >> 56;
		carry = value.L2 + carry >> 56;
		carry = value.L3 + carry >> 56;
		carry = value.L4 + 1 + carry >> 56;
		carry = value.L5 + carry >> 56;
		carry = value.L6 + carry >> 56;
		carry = value.L7 + carry >> 56;
		return carry - 1;
	}

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	internal static void Multiply(in Field448 left, in Field448 right, out Field448 result)
	{
		MultiplyCore(in left, in right, out result);
	}

	// Karatsuba over φ = 2^224, whose square is φ + 1 (mod p): with x = x0 + x1·φ and y = y0 + y1·φ, x·y ≡ x0·y0 + x1·y1 + ((x0 + x1)(y0 + y1) − x0·y0)·φ, three products P1 = x0·y0, P2 = x1·y1 and P3 = (x0 + x1)(y0 + y1) of four limbs each. Each limb product splits at bit 56: with a = x_i·2^4 and b = y_j·2^4, a·b = x_i·y_j·2^8, whose high word is x_i·y_j >> 56 and whose low word is (x_i·y_j mod 2^56)·2^8. Column k of a half product sums the low halves of degree k and the high halves of degree k − 1, and the columns r of the result are s_i(P1) − s_(i+4)(P1) + s_i(P2) + s_(i+4)(P3) and s_i(P3) − s_i(P1) + s_(i+4)(P2) + s_(i+4)(P3) for i < 4, the columns of (P3 − P1)·φ from 8 on coming back at 0 and 4.
	// Each limb product of P3 is at least the one of P1 in its place, and so is its high half, so the only negative parts are low halves of P1, at most four in a column; the limbs of 4p, 4·(2^56 − 1), added in, cover them exactly. For limb bounds x·2^56 and y·2^56, the largest column, r_4, stays below (11 + 20xy)·2^56 ≤ 2^64, and x, y ≤ 8 keep the shifted sums of P3 below 2^64. Carry then leaves a tight element.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void MultiplyCore(in Field448 left, in Field448 right, out Field448 result)
	{
		HalfProduct(left.L0 << 4, left.L1 << 4, left.L2 << 4, left.L3 << 4, right.L0 << 4, right.L1 << 4, right.L2 << 4, right.L3 << 4, out ulong p0, out ulong p1, out ulong p2, out ulong p3, out ulong p4, out ulong p5, out ulong p6, out ulong p7);
		HalfProduct(left.L4 << 4, left.L5 << 4, left.L6 << 4, left.L7 << 4, right.L4 << 4, right.L5 << 4, right.L6 << 4, right.L7 << 4, out ulong q0, out ulong q1, out ulong q2, out ulong q3, out ulong q4, out ulong q5, out ulong q6, out ulong q7);
		HalfProduct(left.L0 + left.L4 << 4, left.L1 + left.L5 << 4, left.L2 + left.L6 << 4, left.L3 + left.L7 << 4, right.L0 + right.L4 << 4, right.L1 + right.L5 << 4, right.L2 + right.L6 << 4, right.L3 + right.L7 << 4, out ulong s0, out ulong s1, out ulong s2, out ulong s3, out ulong s4, out ulong s5, out ulong s6, out ulong s7);
		Combine(p0, p1, p2, p3, p4, p5, p6, p7, q0, q1, q2, q3, q4, q5, q6, q7, s0, s1, s2, s3, s4, s5, s6, s7, out result);
	}

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	internal static void Square(in Field448 value, out Field448 result)
	{
		SquareCore(in value, out result);
	}

	// value^(2^count) for count ≥ 1, with the squares inlined into the loop, so that each one takes the last without a call.
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	internal static void SquareTimes(in Field448 value, int count, out Field448 result)
	{
		Debug.Assert(count >= 1);

		Field448 t = value;

		for (int i = 0; i < count; ++i)
		{
			SquareCore(in t, out t);
		}

		result = t;
	}

	// MultiplyCore with right = value: the half products are squares, whose doubled cross products 2·x_i·x_j take d_i·a_j with d_i = x_i·2^5, so each needs one limb product; the columns keep the bounds of Multiply with x = y.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void SquareCore(in Field448 value, out Field448 result)
	{
		HalfSquare(value.L0 << 4, value.L1 << 4, value.L2 << 4, value.L3 << 4, out ulong p0, out ulong p1, out ulong p2, out ulong p3, out ulong p4, out ulong p5, out ulong p6, out ulong p7);
		HalfSquare(value.L4 << 4, value.L5 << 4, value.L6 << 4, value.L7 << 4, out ulong q0, out ulong q1, out ulong q2, out ulong q3, out ulong q4, out ulong q5, out ulong q6, out ulong q7);
		HalfSquare(value.L0 + value.L4 << 4, value.L1 + value.L5 << 4, value.L2 + value.L6 << 4, value.L3 + value.L7 << 4, out ulong s0, out ulong s1, out ulong s2, out ulong s3, out ulong s4, out ulong s5, out ulong s6, out ulong s7);
		Combine(p0, p1, p2, p3, p4, p5, p6, p7, q0, q1, q2, q3, q4, q5, q6, q7, s0, s1, s2, s3, s4, s5, s6, s7, out result);
	}

	// value·c for c below 2^17 and limbs below 2^58. Each limb times c splits at bit 56 as in Multiply, into a part below 2^56 and one below 2^19, the part above limb 7 back at limbs 0 and 4; one carry then leaves the limbs tight.
	internal static void MultiplySmall(in Field448 value, uint c, out Field448 result)
	{
		Debug.Assert(c < 1u << 17);

		ulong b = (ulong)c << 4;
		ulong a0 = value.L0 << 4;
		ulong a1 = value.L1 << 4;
		ulong a2 = value.L2 << 4;
		ulong a3 = value.L3 << 4;
		ulong a4 = value.L4 << 4;
		ulong a5 = value.L5 << 4;
		ulong a6 = value.L6 << 4;
		ulong a7 = value.L7 << 4;
		ulong top = High(a7, b);
		Carry(Low(a0, b) + top, Low(a1, b) + High(a0, b), Low(a2, b) + High(a1, b), Low(a3, b) + High(a2, b), Low(a4, b) + High(a3, b) + top, Low(a5, b) + High(a4, b), Low(a6, b) + High(a5, b), Low(a7, b) + High(a6, b), out result);
	}

	// Limb by limb, without carries.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Add(in Field448 left, in Field448 right, out Field448 result)
	{
		result.L0 = left.L0 + right.L0;
		result.L1 = left.L1 + right.L1;
		result.L2 = left.L2 + right.L2;
		result.L3 = left.L3 + right.L3;
		result.L4 = left.L4 + right.L4;
		result.L5 = left.L5 + right.L5;
		result.L6 = left.L6 + right.L6;
		result.L7 = left.L7 + right.L7;
	}

	// left + 2p − right limb by limb, for a right whose limbs are at most those of 2p, as a tight one's are: no limb goes negative, and each grows by below 2^57.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Subtract(in Field448 left, in Field448 right, out Field448 result)
	{
		result.L0 = left.L0 + TwoP - right.L0;
		result.L1 = left.L1 + TwoP - right.L1;
		result.L2 = left.L2 + TwoP - right.L2;
		result.L3 = left.L3 + TwoP - right.L3;
		result.L4 = left.L4 + TwoP4 - right.L4;
		result.L5 = left.L5 + TwoP - right.L5;
		result.L6 = left.L6 + TwoP - right.L6;
		result.L7 = left.L7 + TwoP - right.L7;
	}

	// left + 4p − right limb by limb, for a right whose limbs are at most those of 4p, as those of a sum of two tight elements are: each limb grows by below 2^58.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void SubtractFromFourP(in Field448 left, in Field448 right, out Field448 result)
	{
		result.L0 = left.L0 + FourP - right.L0;
		result.L1 = left.L1 + FourP - right.L1;
		result.L2 = left.L2 + FourP - right.L2;
		result.L3 = left.L3 + FourP - right.L3;
		result.L4 = left.L4 + FourP4 - right.L4;
		result.L5 = left.L5 + FourP - right.L5;
		result.L6 = left.L6 + FourP - right.L6;
		result.L7 = left.L7 + FourP - right.L7;
	}

	// 2p − value, carried, for limbs at most those of 2p.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Negate(in Field448 value, out Field448 result)
	{
		Carry(TwoP - value.L0, TwoP - value.L1, TwoP - value.L2, TwoP - value.L3, TwoP4 - value.L4, TwoP - value.L5, TwoP - value.L6, TwoP - value.L7, out result);
	}

	// Any limbs to a tight element: each limb keeps its low 56 bits and gains the carry out of the one below, limbs 0 and 4 that of limb 7 as well. The carries are below 2^8, so limb 4 ends below 2^56 + 2^9 and the others below 2^56 + 2^8.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Carry(in Field448 value, out Field448 result)
	{
		Carry(value.L0, value.L1, value.L2, value.L3, value.L4, value.L5, value.L6, value.L7, out result);
	}

	// The canonical value. Carry leaves a tight element, below 2^448 + 2^402 and so below 2p, and q = 1 just if it is p or more, which is where adding 2^224 + 1 carries out of bit 447 through the limbs. Adding q·(2^224 + 1) and dropping bit 448 then subtracts qp.
	internal static void Reduce(in Field448 value, out Field448 result)
	{
		Carry(in value, out Field448 t);
		ulong q = t.L0 + 1 >> 56;
		q = t.L1 + q >> 56;
		q = t.L2 + q >> 56;
		q = t.L3 + q >> 56;
		q = t.L4 + 1 + q >> 56;
		q = t.L5 + q >> 56;
		q = t.L6 + q >> 56;
		q = t.L7 + q >> 56;
		ulong l0 = t.L0 + q;
		ulong l1 = t.L1 + (l0 >> 56);
		ulong l2 = t.L2 + (l1 >> 56);
		ulong l3 = t.L3 + (l2 >> 56);
		ulong l4 = t.L4 + q + (l3 >> 56);
		ulong l5 = t.L5 + (l4 >> 56);
		ulong l6 = t.L6 + (l5 >> 56);
		ulong l7 = t.L7 + (l6 >> 56);
		result.L0 = l0 & Mask;
		result.L1 = l1 & Mask;
		result.L2 = l2 & Mask;
		result.L3 = l3 & Mask;
		result.L4 = l4 & Mask;
		result.L5 = l5 & Mask;
		result.L6 = l6 & Mask;
		result.L7 = l7 & Mask;
	}

	// ulong.MaxValue if the value is 0 mod p and 0 otherwise. The canonical copy is erased, as the value may be secret.
	internal static ulong IsZero(in Field448 value)
	{
		Reduce(in value, out Field448 r);
		ulong bits = r.L0 | r.L1 | r.L2 | r.L3 | r.L4 | r.L5 | r.L6 | r.L7;
		r.ZeroMemory();
		return ZeroMask(bits);
	}

	// ulong.MaxValue if the canonical value is odd, which RFC 8032 calls negative, and 0 otherwise. The canonical copy is erased, as with IsZero.
	internal static ulong IsNegative(in Field448 value)
	{
		Reduce(in value, out Field448 r);
		ulong negative = 0 - (r.L0 & 1);
		r.ZeroMemory();
		return negative;
	}

	// For a right whose limbs are at most those of 2p.
	internal static ulong AreEqual(in Field448 left, in Field448 right)
	{
		Subtract(in left, in right, out Field448 difference);
		return IsZero(in difference);
	}

	// Limb by limb, which keeps the form of the inputs.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void ConditionalSelect(ulong mask, in Field448 whenSet, in Field448 whenClear, out Field448 result)
	{
		result.L0 = Select(mask, whenSet.L0, whenClear.L0);
		result.L1 = Select(mask, whenSet.L1, whenClear.L1);
		result.L2 = Select(mask, whenSet.L2, whenClear.L2);
		result.L3 = Select(mask, whenSet.L3, whenClear.L3);
		result.L4 = Select(mask, whenSet.L4, whenClear.L4);
		result.L5 = Select(mask, whenSet.L5, whenClear.L5);
		result.L6 = Select(mask, whenSet.L6, whenClear.L6);
		result.L7 = Select(mask, whenSet.L7, whenClear.L7);
	}

	// Swaps left and right where mask is set. They must be different variables.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void ConditionalSwap(ulong mask, ref Field448 left, ref Field448 right)
	{
		ulong t0 = (left.L0 ^ right.L0) & mask;
		ulong t1 = (left.L1 ^ right.L1) & mask;
		ulong t2 = (left.L2 ^ right.L2) & mask;
		ulong t3 = (left.L3 ^ right.L3) & mask;
		ulong t4 = (left.L4 ^ right.L4) & mask;
		ulong t5 = (left.L5 ^ right.L5) & mask;
		ulong t6 = (left.L6 ^ right.L6) & mask;
		ulong t7 = (left.L7 ^ right.L7) & mask;
		left.L0 ^= t0;
		left.L1 ^= t1;
		left.L2 ^= t2;
		left.L3 ^= t3;
		left.L4 ^= t4;
		left.L5 ^= t5;
		left.L6 ^= t6;
		left.L7 ^= t7;
		right.L0 ^= t0;
		right.L1 ^= t1;
		right.L2 ^= t2;
		right.L3 ^= t3;
		right.L4 ^= t4;
		right.L5 ^= t5;
		right.L6 ^= t6;
		right.L7 ^= t7;
	}

	// For limbs at most those of 2p; the result is tight either way.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void ConditionalNegate(ulong mask, ref Field448 value)
	{
		Negate(in value, out Field448 negated);
		Carry(in value, out value);
		ConditionalSelect(mask, in negated, in value, out value);
	}

	// 1/value, and 0 for 0, by SafeGcd on the canonical value. Neither the time nor the addresses depend on value.
	[SkipLocalsInit]
	internal static void Invert(in Field448 value, out Field448 result)
	{
		Span<ulong> limbs = stackalloc ulong[7];
		ToLimbs(in value, limbs);
		SafeGcd<Curve448Modulus>.Invert(in AsElement(limbs), Curve448Modulus.One, out FieldElement<Curve448Modulus> inverse);
		FromElement(in inverse, out result);
		limbs.ZeroMemory();
		inverse.ZeroMemory();
	}

	// As above for a public value: the time depends on it.
	[SkipLocalsInit]
	internal static void InvertVariableTime(in Field448 value, out Field448 result)
	{
		Span<ulong> limbs = stackalloc ulong[7];
		ToLimbs(in value, limbs);
		SafeGcd<Curve448Modulus>.InvertVariableTime(in AsElement(limbs), Curve448Modulus.One, out FieldElement<Curve448Modulus> inverse);
		FromElement(in inverse, out result);
	}

	// value^((p − 3)/4) = value^(2^446 − 2^222 − 1) = value^((2^223 − 1)·2^223 + 2^222 − 1): 445 squarings and 12 products, by way of a_k = value^(2^k − 1) for k = 2, 3, 6, 9, 18, 19, 37, 74, 111, 222 and 223, each from two before it as a_(m + n) = a_m^(2^n)·a_n.
	internal static void PowerP34(in Field448 value, out Field448 result)
	{
		Square(in value, out Field448 t1);
		Multiply(in value, in t1, out Field448 t2);
		Square(in t2, out t1);
		Multiply(in value, in t1, out t2);
		SquareTimes(in t2, 3, out t1);
		Multiply(in t2, in t1, out Field448 t0);
		SquareTimes(in t0, 3, out t1);
		Multiply(in t2, in t1, out t0);
		SquareTimes(in t0, 9, out t2);
		Multiply(in t0, in t2, out t1);
		Square(in t1, out t0);
		Multiply(in value, in t0, out t2);
		SquareTimes(in t2, 18, out t0);
		Multiply(in t1, in t0, out t2);
		SquareTimes(in t2, 37, out t0);
		Multiply(in t2, in t0, out t1);
		SquareTimes(in t1, 37, out t0);
		Multiply(in t2, in t0, out t1);
		SquareTimes(in t1, 111, out t0);
		Multiply(in t1, in t0, out t2);
		Square(in t2, out t0);
		Multiply(in value, in t0, out t1);
		SquareTimes(in t1, 223, out t0);
		Multiply(in t2, in t0, out result);
		t0.ZeroMemory();
		t1.ZeroMemory();
		t2.ZeroMemory();
	}

	// Sets result to an r with v·r² = u and returns ulong.MaxValue if there is one; returns 0 otherwise. For v ≠ 0 that is whether u/v is a square; for v = 0 only u = 0 has one, the root 0. u must be tight. As p ≡ 3 (mod 4), r = u³v·(u⁵v³)^((p − 3)/4) (RFC 8032 §5.2.3) has v·r² = u·(uv)^((p − 1)/2), which is u just when u/v is a square or u = 0.
	internal static ulong SqrtRatio(in Field448 u, in Field448 v, out Field448 result)
	{
		Multiply(in u, in v, out Field448 uv);
		Square(in u, out Field448 r);
		Multiply(in r, in uv, out Field448 u3v);
		Square(in uv, out uv);
		Multiply(in u3v, in uv, out r);
		PowerP34(in r, out r);
		Multiply(in r, in u3v, out r);
		Square(in r, out Field448 check);
		Multiply(in check, in v, out check);
		ulong found = AreEqual(in check, in u);
		result = r;
		uv.ZeroMemory();
		r.ZeroMemory();
		u3v.ZeroMemory();
		check.ZeroMemory();
		return found;
	}

	// The seven limbs of ToLimbs, read as the element of SafeGcd, which holds them as they are.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ref readonly FieldElement<Curve448Modulus> AsElement(Span<ulong> limbs)
	{
		return ref Unsafe.As<ulong, FieldElement<Curve448Modulus>>(ref MemoryMarshal.GetReference(limbs));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FromElement(in FieldElement<Curve448Modulus> value, out Field448 result)
	{
		ReadOnlySpan<ulong> limbs = FieldElement<Curve448Modulus>.GetLimbs(in value);
		FromLimbs(limbs[0], limbs[1], limbs[2], limbs[3], limbs[4], limbs[5], limbs[6], out result);
	}

	// The columns of a product of four limbs by four: column k sums the low halves of the limb products of degree k and the high halves of degree k − 1. The parentheses balance the sums, which the JIT adds in that order. ARM64 adds them row by row instead, which on x64 would spill the eight sums that the rows keep live.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	[SuppressMessage("ReSharper", "ArrangeRedundantParentheses", Justification = "The parentheses balance the column sums, and the JIT adds in the order they give.")]
	private static void HalfProduct(ulong a0, ulong a1, ulong a2, ulong a3, ulong b0, ulong b1, ulong b2, ulong b3, out ulong s0, out ulong s1, out ulong s2, out ulong s3, out ulong s4, out ulong s5, out ulong s6, out ulong s7)
	{
		if (ArmBase.Arm64.IsSupported)
		{
			s0 = Low(a0, b0);
			s1 = High(a0, b0) + Low(a0, b1);
			s2 = High(a0, b1) + Low(a0, b2);
			s3 = High(a0, b2) + Low(a0, b3);
			s4 = High(a0, b3);
			s1 += Low(a1, b0);
			s2 += High(a1, b0) + Low(a1, b1);
			s3 += High(a1, b1) + Low(a1, b2);
			s4 += High(a1, b2) + Low(a1, b3);
			s5 = High(a1, b3);
			s2 += Low(a2, b0);
			s3 += High(a2, b0) + Low(a2, b1);
			s4 += High(a2, b1) + Low(a2, b2);
			s5 += High(a2, b2) + Low(a2, b3);
			s6 = High(a2, b3);
			s3 += Low(a3, b0);
			s4 += High(a3, b0) + Low(a3, b1);
			s5 += High(a3, b1) + Low(a3, b2);
			s6 += High(a3, b2) + Low(a3, b3);
			s7 = High(a3, b3);
			return;
		}

		s0 = Low(a0, b0);
		s1 = High(a0, b0) + (Low(a0, b1) + Low(a1, b0));
		s2 = (High(a0, b1) + High(a1, b0)) + (Low(a0, b2) + Low(a1, b1)) + Low(a2, b0);
		s3 = (High(a0, b2) + High(a1, b1)) + (High(a2, b0) + Low(a0, b3)) + ((Low(a1, b2) + Low(a2, b1)) + Low(a3, b0));
		s4 = ((High(a0, b3) + High(a1, b2)) + (High(a2, b1) + High(a3, b0))) + ((Low(a1, b3) + Low(a2, b2)) + Low(a3, b1));
		s5 = (High(a1, b3) + High(a2, b2)) + (High(a3, b1) + Low(a2, b3)) + Low(a3, b2);
		s6 = (High(a2, b3) + High(a3, b2)) + Low(a3, b3);
		s7 = High(a3, b3);
	}

	// HalfProduct of four limbs by themselves, with the doubled cross products from d_i = 2a_i, row by row on ARM64 as there.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	[SuppressMessage("ReSharper", "ArrangeRedundantParentheses", Justification = "The parentheses balance the column sums, and the JIT adds in the order they give.")]
	private static void HalfSquare(ulong a0, ulong a1, ulong a2, ulong a3, out ulong s0, out ulong s1, out ulong s2, out ulong s3, out ulong s4, out ulong s5, out ulong s6, out ulong s7)
	{
		ulong d0 = a0 << 1;
		ulong d1 = a1 << 1;
		ulong d2 = a2 << 1;

		if (ArmBase.Arm64.IsSupported)
		{
			s0 = Low(a0, a0);
			s1 = High(a0, a0) + Low(d0, a1);
			s2 = High(d0, a1) + Low(d0, a2);
			s3 = High(d0, a2) + Low(d0, a3);
			s4 = High(d0, a3);
			s2 += Low(a1, a1);
			s3 += High(a1, a1) + Low(d1, a2);
			s4 += High(d1, a2) + Low(d1, a3);
			s5 = High(d1, a3);
			s4 += Low(a2, a2);
			s5 += High(a2, a2) + Low(d2, a3);
			s6 = High(d2, a3) + Low(a3, a3);
			s7 = High(a3, a3);
			return;
		}

		s0 = Low(a0, a0);
		s1 = High(a0, a0) + Low(d0, a1);
		s2 = High(d0, a1) + (Low(d0, a2) + Low(a1, a1));
		s3 = (High(d0, a2) + High(a1, a1)) + (Low(d0, a3) + Low(d1, a2));
		s4 = (High(d0, a3) + High(d1, a2)) + (Low(d1, a3) + Low(a2, a2));
		s5 = (High(d1, a3) + High(a2, a2)) + Low(d2, a3);
		s6 = High(d2, a3) + Low(a3, a3);
		s7 = High(a3, a3);
	}

	// The columns of the result from those of P1 = x0·y0 in p, P2 = x1·y1 in q and P3 = (x0 + x1)(y0 + y1) in s, with 4p added in, then carried.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Combine(ulong p0, ulong p1, ulong p2, ulong p3, ulong p4, ulong p5, ulong p6, ulong p7, ulong q0, ulong q1, ulong q2, ulong q3, ulong q4, ulong q5, ulong q6, ulong q7, ulong s0, ulong s1, ulong s2, ulong s3, ulong s4, ulong s5, ulong s6, ulong s7, out Field448 result)
	{
		ulong r0 = p0 - p4 + q0 + s4 + FourP;
		ulong r1 = p1 - p5 + q1 + s5 + FourP;
		ulong r2 = p2 - p6 + q2 + s6 + FourP;
		ulong r3 = p3 - p7 + q3 + s7 + FourP;
		ulong r4 = s0 - p0 + q4 + s4 + FourP4;
		ulong r5 = s1 - p1 + q5 + s5 + FourP;
		ulong r6 = s2 - p2 + q6 + s6 + FourP;
		ulong r7 = s3 - p3 + q7 + s7 + FourP;
		Carry(r0, r1, r2, r3, r4, r5, r6, r7, out result);
	}

	// Carries r_0 to r_7, each below 2^64, all at once, as the public Carry does.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Carry(ulong r0, ulong r1, ulong r2, ulong r3, ulong r4, ulong r5, ulong r6, ulong r7, out Field448 result)
	{
		ulong top = r7 >> 56;
		result.L0 = (r0 & Mask) + top;
		result.L1 = (r1 & Mask) + (r0 >> 56);
		result.L2 = (r2 & Mask) + (r1 >> 56);
		result.L3 = (r3 & Mask) + (r2 >> 56);
		result.L4 = (r4 & Mask) + (r3 >> 56) + top;
		result.L5 = (r5 & Mask) + (r4 >> 56);
		result.L6 = (r6 & Mask) + (r5 >> 56);
		result.L7 = (r7 & Mask) + (r6 >> 56);
	}

	// (x·y mod 2^56) for a = x·2^4 and b = y·2^4.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong Low(ulong a, ulong b)
	{
		return a * b >> 8;
	}

	// x·y >> 56 for a = x·2^4 and b = y·2^4. The intrinsics are called here rather than through LimbArithmetic, whose extra inlining level leads the JIT to spill more of the column sums.
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

	// limbs must be eight tight limbs that live for the whole process, as the data of a constant span does.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static ref readonly Field448 FromConstant(ReadOnlySpan<ulong> limbs)
	{
		Debug.Assert(limbs.Length is 8);

		return ref Unsafe.As<ulong, Field448>(ref MemoryMarshal.GetReference(limbs));
	}
}
