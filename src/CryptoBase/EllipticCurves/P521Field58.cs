using static CryptoBase.EllipticCurves.LimbArithmetic;

namespace CryptoBase.EllipticCurves;

// The field of p = 2^521 − 1 in nine unsaturated limbs, the value Σ L_i·2^(58i). Montgomery form takes R = 1, so it is the plain value, and as 2^521 ≡ 1 (mod p) the reduction needs no multiplication.
// Every member takes and gives the form E: limbs 0 to 7 below 2^58 and limb 8 below 2^57 + 2^6, so values below 2^521 + 2^470 < 2p. An element is of size s if its limbs 0 to 7 are below s·2^58 and limb 8 below s·(2^57 + 2^6); E is size 1.
// The formulas in P521Field58.Formulas.cs skip reductions between steps and keep the sizes within these limits: Multiply takes sizes a and b up to 6 with ab ≤ 6, so Square takes sizes up to √6, and both give E; AddUnreduced adds sizes; SubtractUnreduced adds 2p, so 2 to the size, for a subtrahend of E; WeakReduce takes limbs below 2^64 − 2^7, so sizes up to 63, to E.
internal partial struct P521Field58 : IEcField<P521Field58>
{
	internal ulong L0;
	internal ulong L1;
	internal ulong L2;
	internal ulong L3;
	internal ulong L4;
	internal ulong L5;
	internal ulong L6;
	internal ulong L7;
	internal ulong L8;

	private const ulong Mask = (1UL << 58) - 1;

	// The limbs of p are Mask for limbs 0 to 7 and TopMask for limb 8.
	private const ulong TopMask = (1UL << 57) - 1;

	// The limbs of 2p, 2^59 − 2 for limbs 0 to 7 and 2^58 − 2 for limb 8: each at least the matching limb of E, so that SubtractUnreduced leaves no limb negative.
	private const ulong TwoP = 2 * Mask;
	private const ulong TwoPTop = 2 * TopMask;

	public static ReadOnlySpan<ulong> Modulus => P521Field.Modulus;

	public static int ByteLength => 66;

	public static ref readonly P521Field58 One => ref Unsafe.As<ulong, P521Field58>(ref MemoryMarshal.GetReference(InverseNumerator));

	// 1 in 64-bit limbs, the SafeGcd numerator R² for R = 1. The same limbs are 1 in this representation, so One reads them too.
	private static ReadOnlySpan<ulong> InverseNumerator => [1, 0, 0, 0, 0, 0, 0, 0, 0];

	public static void FromLimbs(ReadOnlySpan<ulong> limbs, out P521Field58 result)
	{
		Debug.Assert(limbs.Length is 9);

		ulong w0 = limbs[0];
		ulong w1 = limbs[1];
		ulong w2 = limbs[2];
		ulong w3 = limbs[3];
		ulong w4 = limbs[4];
		ulong w5 = limbs[5];
		ulong w6 = limbs[6];
		ulong w7 = limbs[7];
		ulong w8 = limbs[8];
		result.L0 = w0 & Mask;
		result.L1 = (w0 >> 58 | w1 << 6) & Mask;
		result.L2 = (w1 >> 52 | w2 << 12) & Mask;
		result.L3 = (w2 >> 46 | w3 << 18) & Mask;
		result.L4 = (w3 >> 40 | w4 << 24) & Mask;
		result.L5 = (w4 >> 34 | w5 << 30) & Mask;
		result.L6 = (w5 >> 28 | w6 << 36) & Mask;
		result.L7 = (w6 >> 22 | w7 << 42) & Mask;
		result.L8 = w7 >> 16 | w8 << 48;
	}

	public static bool TryImport(ReadOnlySpan<byte> source, out P521Field58 result)
	{
		bool valid = FieldElement<P521Field>.TryImport(source, out FieldElement<P521Field> value);
		FromLimbs(FieldElement<P521Field>.GetLimbs(in value), out result);
		return valid;
	}

	public static void Export(in P521Field58 value, Span<byte> destination)
	{
		ToSaturated(in value, out FieldElement<P521Field> saturated);
		FieldElement<P521Field>.Export(in saturated, destination);
		saturated.ZeroMemory();
	}

	public static void Add(in P521Field58 left, in P521Field58 right, out P521Field58 result)
	{
		AddUnreduced(in left, in right, out result);
		WeakReduce(in result, out result);
	}

	public static void Subtract(in P521Field58 left, in P521Field58 right, out P521Field58 result)
	{
		SubtractUnreduced(in left, in right, out result);
		WeakReduce(in result, out result);
	}

	public static void Negate(in P521Field58 value, out P521Field58 result)
	{
		P521Field58 zero = default;
		Subtract(in zero, in value, out result);
	}

	// Both operands are shifted left by 3: for limbs x_i and y_j below 2^61, x_i·2^3 · y_j·2^3 < 2^128, so High gives x_i·y_j >> 58 and Low gives x_i·y_j mod 2^58. Column k sums the Low of the pairs with i + j = k and the High of those with i + j = k − 1, at most nine of each. For sizes a and b, a High is below ab·2^58, or ab·2^58·(1/2 + 2^−52) with limb 8, which enters one column at most twice, so the Highs sum to below 8ab·2^58·(1 + 2^−50) and the column to below 58·2^58 for ab ≤ 6, within 64 bits. Columns 0 to 7 hold at most eight Lows and seven Highs, so below 50·2^58, and column 17 is below 2^60.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Multiply(in P521Field58 left, in P521Field58 right, out P521Field58 result)
	{
		if (Bmi2.X64.IsSupported)
		{
			MultiplyThroughMemory(in left, in right, out result);
		}
		else
		{
			MultiplyInRegisters(in left, in right, out result);
		}
	}

	// The columns go to Reduce. This is the form for Arm64, which has registers for all eighteen shifted limbs, and for x64 without BMI2, where each High is a call.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void MultiplyInRegisters(in P521Field58 left, in P521Field58 right, out P521Field58 result)
	{
		ulong a0 = left.L0 << 3;
		ulong a1 = left.L1 << 3;
		ulong a2 = left.L2 << 3;
		ulong a3 = left.L3 << 3;
		ulong a4 = left.L4 << 3;
		ulong a5 = left.L5 << 3;
		ulong a6 = left.L6 << 3;
		ulong a7 = left.L7 << 3;
		ulong a8 = left.L8 << 3;
		ulong b0 = right.L0 << 3;
		ulong b1 = right.L1 << 3;
		ulong b2 = right.L2 << 3;
		ulong b3 = right.L3 << 3;
		ulong b4 = right.L4 << 3;
		ulong b5 = right.L5 << 3;
		ulong b6 = right.L6 << 3;
		ulong b7 = right.L7 << 3;
		ulong b8 = right.L8 << 3;
		ulong t0 = Low(a0, b0);
		ulong t1 = High(a0, b0) + Low(a0, b1) + Low(a1, b0);
		ulong t2 = High(a0, b1) + High(a1, b0) + Low(a0, b2) + Low(a1, b1) + Low(a2, b0);
		ulong t3 = High(a0, b2) + High(a1, b1) + High(a2, b0) + Low(a0, b3) + Low(a1, b2) + Low(a2, b1) + Low(a3, b0);
		ulong t4 = High(a0, b3) + High(a1, b2) + High(a2, b1) + High(a3, b0) + Low(a0, b4) + Low(a1, b3) + Low(a2, b2) + Low(a3, b1) + Low(a4, b0);
		ulong t5 = High(a0, b4) + High(a1, b3) + High(a2, b2) + High(a3, b1) + High(a4, b0) + Low(a0, b5) + Low(a1, b4) + Low(a2, b3) + Low(a3, b2) + Low(a4, b1) + Low(a5, b0);
		ulong t6 = High(a0, b5) + High(a1, b4) + High(a2, b3) + High(a3, b2) + High(a4, b1) + High(a5, b0) + Low(a0, b6) + Low(a1, b5) + Low(a2, b4) + Low(a3, b3) + Low(a4, b2) + Low(a5, b1) + Low(a6, b0);
		ulong t7 = High(a0, b6) + High(a1, b5) + High(a2, b4) + High(a3, b3) + High(a4, b2) + High(a5, b1) + High(a6, b0) + Low(a0, b7) + Low(a1, b6) + Low(a2, b5) + Low(a3, b4) + Low(a4, b3) + Low(a5, b2) + Low(a6, b1) + Low(a7, b0);
		ulong t8 = High(a0, b7) + High(a1, b6) + High(a2, b5) + High(a3, b4) + High(a4, b3) + High(a5, b2) + High(a6, b1) + High(a7, b0) + Low(a0, b8) + Low(a1, b7) + Low(a2, b6) + Low(a3, b5) + Low(a4, b4) + Low(a5, b3) + Low(a6, b2) + Low(a7, b1) + Low(a8, b0);
		ulong t9 = High(a0, b8) + High(a1, b7) + High(a2, b6) + High(a3, b5) + High(a4, b4) + High(a5, b3) + High(a6, b2) + High(a7, b1) + High(a8, b0) + Low(a1, b8) + Low(a2, b7) + Low(a3, b6) + Low(a4, b5) + Low(a5, b4) + Low(a6, b3) + Low(a7, b2) + Low(a8, b1);
		ulong t10 = High(a1, b8) + High(a2, b7) + High(a3, b6) + High(a4, b5) + High(a5, b4) + High(a6, b3) + High(a7, b2) + High(a8, b1) + Low(a2, b8) + Low(a3, b7) + Low(a4, b6) + Low(a5, b5) + Low(a6, b4) + Low(a7, b3) + Low(a8, b2);
		ulong t11 = High(a2, b8) + High(a3, b7) + High(a4, b6) + High(a5, b5) + High(a6, b4) + High(a7, b3) + High(a8, b2) + Low(a3, b8) + Low(a4, b7) + Low(a5, b6) + Low(a6, b5) + Low(a7, b4) + Low(a8, b3);
		ulong t12 = High(a3, b8) + High(a4, b7) + High(a5, b6) + High(a6, b5) + High(a7, b4) + High(a8, b3) + Low(a4, b8) + Low(a5, b7) + Low(a6, b6) + Low(a7, b5) + Low(a8, b4);
		ulong t13 = High(a4, b8) + High(a5, b7) + High(a6, b6) + High(a7, b5) + High(a8, b4) + Low(a5, b8) + Low(a6, b7) + Low(a7, b6) + Low(a8, b5);
		ulong t14 = High(a5, b8) + High(a6, b7) + High(a7, b6) + High(a8, b5) + Low(a6, b8) + Low(a7, b7) + Low(a8, b6);
		ulong t15 = High(a6, b8) + High(a7, b7) + High(a8, b6) + Low(a7, b8) + Low(a8, b7);
		ulong t16 = High(a7, b8) + High(a8, b7) + Low(a8, b8);
		Reduce(t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15, t16, High(a8, b8), out result);
	}

	// The x64 registers do not hold all eighteen shifted limbs, so those of left stay in memory, in s_9 to s_17, where they are operands of the products. The columns go to s_0 to s_8 as they finish, and columns 9 to 17 fold in there by the steps of Reduce, so that only two columns are open at a time.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	[SkipLocalsInit]
	private static void MultiplyThroughMemory(in P521Field58 left, in P521Field58 right, out P521Field58 result)
	{
		Unsafe.SkipInit(out Scratch scratch);
		ref ulong s = ref scratch[0];
		Unsafe.Add(ref s, 9) = left.L0 << 3;
		Unsafe.Add(ref s, 10) = left.L1 << 3;
		Unsafe.Add(ref s, 11) = left.L2 << 3;
		Unsafe.Add(ref s, 12) = left.L3 << 3;
		Unsafe.Add(ref s, 13) = left.L4 << 3;
		Unsafe.Add(ref s, 14) = left.L5 << 3;
		Unsafe.Add(ref s, 15) = left.L6 << 3;
		Unsafe.Add(ref s, 16) = left.L7 << 3;
		Unsafe.Add(ref s, 17) = left.L8 << 3;
		ulong b0 = right.L0 << 3;
		ulong b1 = right.L1 << 3;
		ulong b2 = right.L2 << 3;
		ulong b3 = right.L3 << 3;
		ulong b4 = right.L4 << 3;
		ulong b5 = right.L5 << 3;
		ulong b6 = right.L6 << 3;
		ulong b7 = right.L7 << 3;
		ulong b8 = right.L8 << 3;
		ulong column = Low(Unsafe.Add(ref s, 9), b0);
		ulong high = High(Unsafe.Add(ref s, 9), b0);
		s = column;
		column = high;
		ulong x = Unsafe.Add(ref s, 9);
		high = High(x, b1);
		column += Low(x, b1);
		x = Unsafe.Add(ref s, 10);
		high += High(x, b0);
		column += Low(x, b0);
		Unsafe.Add(ref s, 1) = column;
		column = high;
		x = Unsafe.Add(ref s, 9);
		high = High(x, b2);
		column += Low(x, b2);
		x = Unsafe.Add(ref s, 10);
		high += High(x, b1);
		column += Low(x, b1);
		x = Unsafe.Add(ref s, 11);
		high += High(x, b0);
		column += Low(x, b0);
		Unsafe.Add(ref s, 2) = column;
		column = high;
		x = Unsafe.Add(ref s, 9);
		high = High(x, b3);
		column += Low(x, b3);
		x = Unsafe.Add(ref s, 10);
		high += High(x, b2);
		column += Low(x, b2);
		x = Unsafe.Add(ref s, 11);
		high += High(x, b1);
		column += Low(x, b1);
		x = Unsafe.Add(ref s, 12);
		high += High(x, b0);
		column += Low(x, b0);
		Unsafe.Add(ref s, 3) = column;
		column = high;
		x = Unsafe.Add(ref s, 9);
		high = High(x, b4);
		column += Low(x, b4);
		x = Unsafe.Add(ref s, 10);
		high += High(x, b3);
		column += Low(x, b3);
		x = Unsafe.Add(ref s, 11);
		high += High(x, b2);
		column += Low(x, b2);
		x = Unsafe.Add(ref s, 12);
		high += High(x, b1);
		column += Low(x, b1);
		x = Unsafe.Add(ref s, 13);
		high += High(x, b0);
		column += Low(x, b0);
		Unsafe.Add(ref s, 4) = column;
		column = high;
		x = Unsafe.Add(ref s, 9);
		high = High(x, b5);
		column += Low(x, b5);
		x = Unsafe.Add(ref s, 10);
		high += High(x, b4);
		column += Low(x, b4);
		x = Unsafe.Add(ref s, 11);
		high += High(x, b3);
		column += Low(x, b3);
		x = Unsafe.Add(ref s, 12);
		high += High(x, b2);
		column += Low(x, b2);
		x = Unsafe.Add(ref s, 13);
		high += High(x, b1);
		column += Low(x, b1);
		x = Unsafe.Add(ref s, 14);
		high += High(x, b0);
		column += Low(x, b0);
		Unsafe.Add(ref s, 5) = column;
		column = high;
		x = Unsafe.Add(ref s, 9);
		high = High(x, b6);
		column += Low(x, b6);
		x = Unsafe.Add(ref s, 10);
		high += High(x, b5);
		column += Low(x, b5);
		x = Unsafe.Add(ref s, 11);
		high += High(x, b4);
		column += Low(x, b4);
		x = Unsafe.Add(ref s, 12);
		high += High(x, b3);
		column += Low(x, b3);
		x = Unsafe.Add(ref s, 13);
		high += High(x, b2);
		column += Low(x, b2);
		x = Unsafe.Add(ref s, 14);
		high += High(x, b1);
		column += Low(x, b1);
		x = Unsafe.Add(ref s, 15);
		high += High(x, b0);
		column += Low(x, b0);
		Unsafe.Add(ref s, 6) = column;
		column = high;
		x = Unsafe.Add(ref s, 9);
		high = High(x, b7);
		column += Low(x, b7);
		x = Unsafe.Add(ref s, 10);
		high += High(x, b6);
		column += Low(x, b6);
		x = Unsafe.Add(ref s, 11);
		high += High(x, b5);
		column += Low(x, b5);
		x = Unsafe.Add(ref s, 12);
		high += High(x, b4);
		column += Low(x, b4);
		x = Unsafe.Add(ref s, 13);
		high += High(x, b3);
		column += Low(x, b3);
		x = Unsafe.Add(ref s, 14);
		high += High(x, b2);
		column += Low(x, b2);
		x = Unsafe.Add(ref s, 15);
		high += High(x, b1);
		column += Low(x, b1);
		x = Unsafe.Add(ref s, 16);
		high += High(x, b0);
		column += Low(x, b0);
		Unsafe.Add(ref s, 7) = column;
		column = high;
		x = Unsafe.Add(ref s, 9);
		high = High(x, b8);
		column += Low(x, b8);
		x = Unsafe.Add(ref s, 10);
		high += High(x, b7);
		column += Low(x, b7);
		x = Unsafe.Add(ref s, 11);
		high += High(x, b6);
		column += Low(x, b6);
		x = Unsafe.Add(ref s, 12);
		high += High(x, b5);
		column += Low(x, b5);
		x = Unsafe.Add(ref s, 13);
		high += High(x, b4);
		column += Low(x, b4);
		x = Unsafe.Add(ref s, 14);
		high += High(x, b3);
		column += Low(x, b3);
		x = Unsafe.Add(ref s, 15);
		high += High(x, b2);
		column += Low(x, b2);
		x = Unsafe.Add(ref s, 16);
		high += High(x, b1);
		column += Low(x, b1);
		x = Unsafe.Add(ref s, 17);
		high += High(x, b0);
		column += Low(x, b0);
		Unsafe.Add(ref s, 8) = column;
		ulong carry = column >> 58;
		column = high;
		x = Unsafe.Add(ref s, 10);
		high = High(x, b8);
		column += Low(x, b8);
		x = Unsafe.Add(ref s, 11);
		high += High(x, b7);
		column += Low(x, b7);
		x = Unsafe.Add(ref s, 12);
		high += High(x, b6);
		column += Low(x, b6);
		x = Unsafe.Add(ref s, 13);
		high += High(x, b5);
		column += Low(x, b5);
		x = Unsafe.Add(ref s, 14);
		high += High(x, b4);
		column += Low(x, b4);
		x = Unsafe.Add(ref s, 15);
		high += High(x, b3);
		column += Low(x, b3);
		x = Unsafe.Add(ref s, 16);
		high += High(x, b2);
		column += Low(x, b2);
		x = Unsafe.Add(ref s, 17);
		high += High(x, b1);
		column += Low(x, b1);
		s += 2 * ((column & Mask) + carry);
		carry = column >> 58;
		column = high;
		x = Unsafe.Add(ref s, 11);
		high = High(x, b8);
		column += Low(x, b8);
		x = Unsafe.Add(ref s, 12);
		high += High(x, b7);
		column += Low(x, b7);
		x = Unsafe.Add(ref s, 13);
		high += High(x, b6);
		column += Low(x, b6);
		x = Unsafe.Add(ref s, 14);
		high += High(x, b5);
		column += Low(x, b5);
		x = Unsafe.Add(ref s, 15);
		high += High(x, b4);
		column += Low(x, b4);
		x = Unsafe.Add(ref s, 16);
		high += High(x, b3);
		column += Low(x, b3);
		x = Unsafe.Add(ref s, 17);
		high += High(x, b2);
		column += Low(x, b2);
		Unsafe.Add(ref s, 1) += 2 * ((column & Mask) + carry);
		carry = column >> 58;
		column = high;
		x = Unsafe.Add(ref s, 12);
		high = High(x, b8);
		column += Low(x, b8);
		x = Unsafe.Add(ref s, 13);
		high += High(x, b7);
		column += Low(x, b7);
		x = Unsafe.Add(ref s, 14);
		high += High(x, b6);
		column += Low(x, b6);
		x = Unsafe.Add(ref s, 15);
		high += High(x, b5);
		column += Low(x, b5);
		x = Unsafe.Add(ref s, 16);
		high += High(x, b4);
		column += Low(x, b4);
		x = Unsafe.Add(ref s, 17);
		high += High(x, b3);
		column += Low(x, b3);
		Unsafe.Add(ref s, 2) += 2 * ((column & Mask) + carry);
		carry = column >> 58;
		column = high;
		x = Unsafe.Add(ref s, 13);
		high = High(x, b8);
		column += Low(x, b8);
		x = Unsafe.Add(ref s, 14);
		high += High(x, b7);
		column += Low(x, b7);
		x = Unsafe.Add(ref s, 15);
		high += High(x, b6);
		column += Low(x, b6);
		x = Unsafe.Add(ref s, 16);
		high += High(x, b5);
		column += Low(x, b5);
		x = Unsafe.Add(ref s, 17);
		high += High(x, b4);
		column += Low(x, b4);
		Unsafe.Add(ref s, 3) += 2 * ((column & Mask) + carry);
		carry = column >> 58;
		column = high;
		x = Unsafe.Add(ref s, 14);
		high = High(x, b8);
		column += Low(x, b8);
		x = Unsafe.Add(ref s, 15);
		high += High(x, b7);
		column += Low(x, b7);
		x = Unsafe.Add(ref s, 16);
		high += High(x, b6);
		column += Low(x, b6);
		x = Unsafe.Add(ref s, 17);
		high += High(x, b5);
		column += Low(x, b5);
		Unsafe.Add(ref s, 4) += 2 * ((column & Mask) + carry);
		carry = column >> 58;
		column = high;
		x = Unsafe.Add(ref s, 15);
		high = High(x, b8);
		column += Low(x, b8);
		x = Unsafe.Add(ref s, 16);
		high += High(x, b7);
		column += Low(x, b7);
		x = Unsafe.Add(ref s, 17);
		high += High(x, b6);
		column += Low(x, b6);
		Unsafe.Add(ref s, 5) += 2 * ((column & Mask) + carry);
		carry = column >> 58;
		column = high;
		x = Unsafe.Add(ref s, 16);
		high = High(x, b8);
		column += Low(x, b8);
		x = Unsafe.Add(ref s, 17);
		high += High(x, b7);
		column += Low(x, b7);
		Unsafe.Add(ref s, 6) += 2 * ((column & Mask) + carry);
		carry = column >> 58;
		column = high;
		x = Unsafe.Add(ref s, 17);
		high = High(x, b8);
		column += Low(x, b8);
		Unsafe.Add(ref s, 7) += 2 * ((column & Mask) + carry);
		carry = column >> 58;
		column = high;
		Unsafe.Add(ref s, 8) = (Unsafe.Add(ref s, 8) & Mask) + 2 * (column + carry);
		Carry(s, Unsafe.Add(ref s, 1), Unsafe.Add(ref s, 2), Unsafe.Add(ref s, 3), Unsafe.Add(ref s, 4), Unsafe.Add(ref s, 5), Unsafe.Add(ref s, 6), Unsafe.Add(ref s, 7), Unsafe.Add(ref s, 8), out result);
	}

	// Multiply with right = value, so its bounds hold. Each cross product 2·x_i·x_j takes d_i = x_i·2^4, for limbs below 2^60, and gives one Low in place of two and a High, 2·x_i·x_j >> 58, within the bound of the two it replaces.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void Square(in P521Field58 value, out P521Field58 result)
	{
		ulong a0 = value.L0 << 3;
		ulong a1 = value.L1 << 3;
		ulong a2 = value.L2 << 3;
		ulong a3 = value.L3 << 3;
		ulong a4 = value.L4 << 3;
		ulong a5 = value.L5 << 3;
		ulong a6 = value.L6 << 3;
		ulong a7 = value.L7 << 3;
		ulong a8 = value.L8 << 3;
		ulong d0 = value.L0 << 4;
		ulong d1 = value.L1 << 4;
		ulong d2 = value.L2 << 4;
		ulong d3 = value.L3 << 4;
		ulong d4 = value.L4 << 4;
		ulong d5 = value.L5 << 4;
		ulong d6 = value.L6 << 4;
		ulong d7 = value.L7 << 4;
		ulong t0 = Low(a0, a0);
		ulong t1 = High(a0, a0) + Low(d0, a1);
		ulong t2 = High(d0, a1) + Low(d0, a2) + Low(a1, a1);
		ulong t3 = High(d0, a2) + High(a1, a1) + Low(d0, a3) + Low(d1, a2);
		ulong t4 = High(d0, a3) + High(d1, a2) + Low(d0, a4) + Low(d1, a3) + Low(a2, a2);
		ulong t5 = High(d0, a4) + High(d1, a3) + High(a2, a2) + Low(d0, a5) + Low(d1, a4) + Low(d2, a3);
		ulong t6 = High(d0, a5) + High(d1, a4) + High(d2, a3) + Low(d0, a6) + Low(d1, a5) + Low(d2, a4) + Low(a3, a3);
		ulong t7 = High(d0, a6) + High(d1, a5) + High(d2, a4) + High(a3, a3) + Low(d0, a7) + Low(d1, a6) + Low(d2, a5) + Low(d3, a4);
		ulong t8 = High(d0, a7) + High(d1, a6) + High(d2, a5) + High(d3, a4) + Low(d0, a8) + Low(d1, a7) + Low(d2, a6) + Low(d3, a5) + Low(a4, a4);
		ulong t9 = High(d0, a8) + High(d1, a7) + High(d2, a6) + High(d3, a5) + High(a4, a4) + Low(d1, a8) + Low(d2, a7) + Low(d3, a6) + Low(d4, a5);
		ulong t10 = High(d1, a8) + High(d2, a7) + High(d3, a6) + High(d4, a5) + Low(d2, a8) + Low(d3, a7) + Low(d4, a6) + Low(a5, a5);
		ulong t11 = High(d2, a8) + High(d3, a7) + High(d4, a6) + High(a5, a5) + Low(d3, a8) + Low(d4, a7) + Low(d5, a6);
		ulong t12 = High(d3, a8) + High(d4, a7) + High(d5, a6) + Low(d4, a8) + Low(d5, a7) + Low(a6, a6);
		ulong t13 = High(d4, a8) + High(d5, a7) + High(a6, a6) + Low(d5, a8) + Low(d6, a7);
		ulong t14 = High(d5, a8) + High(d6, a7) + Low(d6, a8) + Low(a7, a7);
		ulong t15 = High(d6, a8) + High(a7, a7) + Low(d7, a8);
		ulong t16 = High(d7, a8) + Low(a8, a8);
		Reduce(t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15, t16, High(a8, a8), out result);
	}

	// R = 1.
	public static void ToMontgomery(in P521Field58 value, out P521Field58 result)
	{
		result = value;
	}

	public static void FromMontgomery(in P521Field58 value, out P521Field58 result)
	{
		result = value;
	}

	// SafeGcd works on the canonical value in 64-bit limbs.
	public static void Invert(in P521Field58 value, out P521Field58 result)
	{
		ToSaturated(in value, out FieldElement<P521Field> saturated);
		SafeGcd<P521Field>.Invert(in saturated, InverseNumerator, out saturated);
		FromLimbs(FieldElement<P521Field>.GetLimbs(in saturated), out result);
		saturated.ZeroMemory();
	}

	public static void InvertVariableTime(in P521Field58 value, out P521Field58 result)
	{
		ToSaturated(in value, out FieldElement<P521Field> saturated);
		SafeGcd<P521Field>.InvertVariableTime(in saturated, InverseNumerator, out saturated);
		FromLimbs(FieldElement<P521Field>.GetLimbs(in saturated), out result);
	}

	public static ulong IsZero(in P521Field58 value)
	{
		WeakReduce(in value, out P521Field58 reduced);
		return IsReducedZero(in reduced);
	}

	public static ulong AreEqual(in P521Field58 left, in P521Field58 right)
	{
		SubtractUnreduced(in left, in right, out P521Field58 difference);
		return IsZero(in difference);
	}

	// The limbs add without carries; the caller keeps them within what the next operation takes.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void AddUnreduced(in P521Field58 left, in P521Field58 right, out P521Field58 result)
	{
		result.L0 = left.L0 + right.L0;
		result.L1 = left.L1 + right.L1;
		result.L2 = left.L2 + right.L2;
		result.L3 = left.L3 + right.L3;
		result.L4 = left.L4 + right.L4;
		result.L5 = left.L5 + right.L5;
		result.L6 = left.L6 + right.L6;
		result.L7 = left.L7 + right.L7;
		result.L8 = left.L8 + right.L8;
	}

	// left + 2p − right, limb by limb, for right of E: no limb goes negative.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void SubtractUnreduced(in P521Field58 left, in P521Field58 right, out P521Field58 result)
	{
		result.L0 = left.L0 + TwoP - right.L0;
		result.L1 = left.L1 + TwoP - right.L1;
		result.L2 = left.L2 + TwoP - right.L2;
		result.L3 = left.L3 + TwoP - right.L3;
		result.L4 = left.L4 + TwoP - right.L4;
		result.L5 = left.L5 + TwoP - right.L5;
		result.L6 = left.L6 + TwoP - right.L6;
		result.L7 = left.L7 + TwoP - right.L7;
		result.L8 = left.L8 + TwoPTop - right.L8;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void WeakReduce(in P521Field58 value, out P521Field58 result)
	{
		Carry(value.L0, value.L1, value.L2, value.L3, value.L4, value.L5, value.L6, value.L7, value.L8, out result);
	}

	// For the output of WeakReduce: its value is below 2p and its limbs 0 to 7 below 2^58, so it is 0 mod p just if its limbs are those of 0 or of p.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ulong IsReducedZero(in P521Field58 value)
	{
		ulong zero = value.L0 | value.L1 | value.L2 | value.L3 | value.L4 | value.L5 | value.L6 | value.L7 | value.L8;
		ulong modulus = value.L0 ^ Mask | value.L1 ^ Mask | value.L2 ^ Mask | value.L3 ^ Mask | value.L4 ^ Mask | value.L5 ^ Mask | value.L6 ^ Mask | value.L7 ^ Mask | value.L8 ^ TopMask;
		return ZeroMask(zero) | ZeroMask(modulus);
	}

	// The value mod p in nine 64-bit limbs. WeakReduce leaves a value below 2p, so one conditional subtraction of p makes it canonical; limbs 0 to 7 are then below 2^58 and limb 8 below 2^57, so they pack without overlap.
	private static void ToSaturated(in P521Field58 value, out FieldElement<P521Field> result)
	{
		WeakReduce(in value, out P521Field58 t);
		ulong d0 = t.L0 - Mask;
		ulong d1 = t.L1 - Mask + SignedCarry(d0);
		ulong d2 = t.L2 - Mask + SignedCarry(d1);
		ulong d3 = t.L3 - Mask + SignedCarry(d2);
		ulong d4 = t.L4 - Mask + SignedCarry(d3);
		ulong d5 = t.L5 - Mask + SignedCarry(d4);
		ulong d6 = t.L6 - Mask + SignedCarry(d5);
		ulong d7 = t.L7 - Mask + SignedCarry(d6);
		ulong d8 = t.L8 - TopMask + SignedCarry(d7);
		// All ones if t < p.
		ulong keep = (ulong)((long)d8 >> 63);
		ulong l0 = Select(keep, t.L0, d0 & Mask);
		ulong l1 = Select(keep, t.L1, d1 & Mask);
		ulong l2 = Select(keep, t.L2, d2 & Mask);
		ulong l3 = Select(keep, t.L3, d3 & Mask);
		ulong l4 = Select(keep, t.L4, d4 & Mask);
		ulong l5 = Select(keep, t.L5, d5 & Mask);
		ulong l6 = Select(keep, t.L6, d6 & Mask);
		ulong l7 = Select(keep, t.L7, d7 & Mask);
		ulong l8 = Select(keep, t.L8, d8);
		Unsafe.SkipInit(out result);
		ref ulong limbs = ref Unsafe.As<FieldElement<P521Field>, ulong>(ref result);
		limbs = l0 | l1 << 58;
		Unsafe.Add(ref limbs, 1) = l1 >> 6 | l2 << 52;
		Unsafe.Add(ref limbs, 2) = l2 >> 12 | l3 << 46;
		Unsafe.Add(ref limbs, 3) = l3 >> 18 | l4 << 40;
		Unsafe.Add(ref limbs, 4) = l4 >> 24 | l5 << 34;
		Unsafe.Add(ref limbs, 5) = l5 >> 30 | l6 << 28;
		Unsafe.Add(ref limbs, 6) = l6 >> 36 | l7 << 22;
		Unsafe.Add(ref limbs, 7) = l7 >> 42 | l8 << 16;
		Unsafe.Add(ref limbs, 8) = l8 >> 48;
		t.ZeroMemory();
	}

	// Takes the product columns t_k, at 2^(58k), to E, for columns below 2^64, columns 0 to 7 below 50·2^58 and column 17 below 2^60. Column k + 9 stands at 2^522 ≡ 2 times the place of column k, so columns 9 to 17 fold in doubled, after one carry step that brings columns 9 to 16 below 2^58 + 2^6 and column 8 below 2^58: the folded columns are then below 2^64 − 2^7, as Carry requires.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Reduce(ulong t0, ulong t1, ulong t2, ulong t3, ulong t4, ulong t5, ulong t6, ulong t7, ulong t8, ulong t9, ulong t10, ulong t11, ulong t12, ulong t13, ulong t14, ulong t15, ulong t16, ulong t17, out P521Field58 result)
	{
		ulong u9 = (t9 & Mask) + (t8 >> 58);
		ulong u10 = (t10 & Mask) + (t9 >> 58);
		ulong u11 = (t11 & Mask) + (t10 >> 58);
		ulong u12 = (t12 & Mask) + (t11 >> 58);
		ulong u13 = (t13 & Mask) + (t12 >> 58);
		ulong u14 = (t14 & Mask) + (t13 >> 58);
		ulong u15 = (t15 & Mask) + (t14 >> 58);
		ulong u16 = (t16 & Mask) + (t15 >> 58);
		ulong u17 = t17 + (t16 >> 58);
		Carry(t0 + 2 * u9, t1 + 2 * u10, t2 + 2 * u11, t3 + 2 * u12, t4 + 2 * u13, t5 + 2 * u14, t6 + 2 * u15, t7 + 2 * u16, (t8 & Mask) + 2 * u17, out result);
	}

	// For limbs below 2^64 − 2^7: t8 >> 57, below 2^7, moves from limb 8 to limb 0, as 2^521 ≡ 1, and then the carries, each below 2^6, run from limb 0 up to limb 8 without overflow. Limbs 0 to 7 come out below 2^58 and limb 8 below 2^57 + 2^6, so in E.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Carry(ulong t0, ulong t1, ulong t2, ulong t3, ulong t4, ulong t5, ulong t6, ulong t7, ulong t8, out P521Field58 result)
	{
		t0 += t8 >> 57;
		t1 += t0 >> 58;
		t2 += t1 >> 58;
		t3 += t2 >> 58;
		t4 += t3 >> 58;
		t5 += t4 >> 58;
		t6 += t5 >> 58;
		t7 += t6 >> 58;
		result.L0 = t0 & Mask;
		result.L1 = t1 & Mask;
		result.L2 = t2 & Mask;
		result.L3 = t3 & Mask;
		result.L4 = t4 & Mask;
		result.L5 = t5 & Mask;
		result.L6 = t6 & Mask;
		result.L7 = t7 & Mask;
		result.L8 = (t8 & TopMask) + (t7 >> 58);
	}

	// (x·y mod 2^58) for a = x·2^3 and b = y·2^3.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong Low(ulong a, ulong b)
	{
		return a * b >> 6;
	}

	// x·y >> 58 for a = x·2^3 and b = y·2^3.
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

	// ⌊t/2^58⌋ for a t that may be negative.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong SignedCarry(ulong t)
	{
		return (ulong)((long)t >> 58);
	}

	// For MultiplyThroughMemory: the columns in 0 to 8 and the shifted limbs of left in 9 to 17.
	[InlineArray(18)]
	private struct Scratch
	{
		private ulong _limb;
	}
}
