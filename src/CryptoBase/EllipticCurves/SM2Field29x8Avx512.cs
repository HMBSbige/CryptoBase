namespace CryptoBase.EllipticCurves;

// The lanes of SM2Field29 in the eight lanes of Vector512.
internal struct SM2Field29x8Avx512 : ISM2Field29Lanes<SM2Field29x8Avx512>
{
	internal Vector512<ulong> L0;
	internal Vector512<ulong> L1;
	internal Vector512<ulong> L2;
	internal Vector512<ulong> L3;
	internal Vector512<ulong> L4;
	internal Vector512<ulong> L5;
	internal Vector512<ulong> L6;
	internal Vector512<ulong> L7;
	internal Vector512<ulong> L8;

	// vshufi64x2 controls: blocks 0 and 2 of the first source then of the second, and blocks 1 and 3.
	private const byte EvenBlocks = 0b10_00_10_00;
	private const byte OddBlocks = 0b11_01_11_01;

	public static bool IsSupported => Avx512F.IsSupported && Vector512.IsHardwareAccelerated;

	public static int LaneCount => Vector512<ulong>.Count;

	public static void One(out SM2Field29x8Avx512 result)
	{
		Vector512<ulong> zero = Vector512<ulong>.Zero;
		result.L0 = Vector512.Create(SM2Field29.One0);
		result.L1 = zero;
		result.L2 = Vector512.Create(SM2Field29.One2);
		result.L3 = Vector512.Create(SM2Field29.One3);
		result.L4 = zero;
		result.L5 = zero;
		result.L6 = zero;
		result.L7 = Vector512.Create(SM2Field29.One7);
		result.L8 = zero;
	}

	// The rows and rounds of SM2Field29.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Multiply(in SM2Field29x8Avx512 left, in SM2Field29x8Avx512 right, out SM2Field29x8Avx512 result)
	{
		Multiply<TwoStepCarry>(in left, in right, out result);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void MultiplyRipple(in SM2Field29x8Avx512 left, in SM2Field29x8Avx512 right, out SM2Field29x8Avx512 result)
	{
		Multiply<RippleCarry>(in left, in right, out result);
	}

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void Multiply<TCarry>(in SM2Field29x8Avx512 left, in SM2Field29x8Avx512 right, out SM2Field29x8Avx512 result) where TCarry : struct, ISM2Carry
	{
		Vector512<ulong> mask = Vector512.Create(SM2Field29.Mask);

		Vector512<ulong> y = right.L0;
		Vector512<ulong> z0 = M(left.L0, y);
		Vector512<ulong> z1 = M(left.L1, y);
		Vector512<ulong> z2 = M(left.L2, y);
		Vector512<ulong> z3 = M(left.L3, y) + Vector512.Create(SM2Field29.Bias3);
		Vector512<ulong> z4 = M(left.L4, y) + Vector512.Create(SM2Field29.BiasMiddle);
		Vector512<ulong> z5 = M(left.L5, y) + Vector512.Create(SM2Field29.BiasMiddle);
		Vector512<ulong> z6 = M(left.L6, y) + Vector512.Create(SM2Field29.BiasMiddle);
		Vector512<ulong> z7 = M(left.L7, y) + Vector512.Create(SM2Field29.Bias7);
		Vector512<ulong> z8 = M(left.L8, y) + Vector512.Create(SM2Field29.BiasMiddle);
		Vector512<ulong> q = z0 & mask;
		z1 += z0 >> SM2Field29.Bits;
		z2 += q << 6;
		z3 -= q << 9;
		z7 -= q << 21;
		z8 += q << 24;

		y = right.L1;
		z1 += M(left.L0, y);
		z2 += M(left.L1, y);
		z3 += M(left.L2, y);
		z4 += M(left.L3, y);
		z5 += M(left.L4, y);
		z6 += M(left.L5, y);
		z7 += M(left.L6, y);
		z8 += M(left.L7, y);
		Vector512<ulong> z9 = M(left.L8, y) + Vector512.Create(SM2Field29.BiasMiddle);
		q = z1 & mask;
		z2 += z1 >> SM2Field29.Bits;
		z3 += q << 6;
		z4 -= q << 9;
		z8 -= q << 21;
		z9 += q << 24;

		y = right.L2;
		z2 += M(left.L0, y);
		z3 += M(left.L1, y);
		z4 += M(left.L2, y);
		z5 += M(left.L3, y);
		z6 += M(left.L4, y);
		z7 += M(left.L5, y);
		z8 += M(left.L6, y);
		z9 += M(left.L7, y);
		Vector512<ulong> z10 = M(left.L8, y) + Vector512.Create(SM2Field29.Bias10);
		q = z2 & mask;
		z3 += z2 >> SM2Field29.Bits;
		z4 += q << 6;
		z5 -= q << 9;
		z9 -= q << 21;
		z10 += q << 24;

		y = right.L3;
		z3 += M(left.L0, y);
		z4 += M(left.L1, y);
		z5 += M(left.L2, y);
		z6 += M(left.L3, y);
		z7 += M(left.L4, y);
		z8 += M(left.L5, y);
		z9 += M(left.L6, y);
		z10 += M(left.L7, y);
		Vector512<ulong> z11 = M(left.L8, y) + Vector512.Create(SM2Field29.Bias11);
		q = z3 & mask;
		z4 += z3 >> SM2Field29.Bits;
		z5 += q << 6;
		z6 -= q << 9;
		z10 -= q << 21;
		z11 += q << 24;

		y = right.L4;
		z4 += M(left.L0, y);
		z5 += M(left.L1, y);
		z6 += M(left.L2, y);
		z7 += M(left.L3, y);
		z8 += M(left.L4, y);
		z9 += M(left.L5, y);
		z10 += M(left.L6, y);
		z11 += M(left.L7, y);
		Vector512<ulong> z12 = M(left.L8, y) + Vector512.Create(SM2Field29.BiasMiddle);
		q = z4 & mask;
		z5 += z4 >> SM2Field29.Bits;
		z6 += q << 6;
		z7 -= q << 9;
		z11 -= q << 21;
		z12 += q << 24;

		y = right.L5;
		z5 += M(left.L0, y);
		z6 += M(left.L1, y);
		z7 += M(left.L2, y);
		z8 += M(left.L3, y);
		z9 += M(left.L4, y);
		z10 += M(left.L5, y);
		z11 += M(left.L6, y);
		z12 += M(left.L7, y);
		Vector512<ulong> z13 = M(left.L8, y) + Vector512.Create(SM2Field29.BiasMiddle);
		q = z5 & mask;
		z6 += z5 >> SM2Field29.Bits;
		z7 += q << 6;
		z8 -= q << 9;
		z12 -= q << 21;
		z13 += q << 24;

		y = right.L6;
		z6 += M(left.L0, y);
		z7 += M(left.L1, y);
		z8 += M(left.L2, y);
		z9 += M(left.L3, y);
		z10 += M(left.L4, y);
		z11 += M(left.L5, y);
		z12 += M(left.L6, y);
		z13 += M(left.L7, y);
		Vector512<ulong> z14 = M(left.L8, y) + Vector512.Create(SM2Field29.BiasMiddle);
		q = z6 & mask;
		z7 += z6 >> SM2Field29.Bits;
		z8 += q << 6;
		z9 -= q << 9;
		z13 -= q << 21;
		z14 += q << 24;

		y = right.L7;
		z7 += M(left.L0, y);
		z8 += M(left.L1, y);
		z9 += M(left.L2, y);
		z10 += M(left.L3, y);
		z11 += M(left.L4, y);
		z12 += M(left.L5, y);
		z13 += M(left.L6, y);
		z14 += M(left.L7, y);
		Vector512<ulong> z15 = M(left.L8, y) + Vector512.Create(SM2Field29.Bias15);
		q = z7 & mask;
		z8 += z7 >> SM2Field29.Bits;
		z9 += q << 6;
		z10 -= q << 9;
		z14 -= q << 21;
		z15 += q << 24;

		y = right.L8;
		z8 += M(left.L0, y);
		z9 += M(left.L1, y);
		z10 += M(left.L2, y);
		z11 += M(left.L3, y);
		z12 += M(left.L4, y);
		z13 += M(left.L5, y);
		z14 += M(left.L6, y);
		z15 += M(left.L7, y);
		Vector512<ulong> z16 = M(left.L8, y);
		q = z8 & mask;
		z9 += z8 >> SM2Field29.Bits;
		z10 += q << 6;
		z11 -= q << 9;
		z15 -= q << 21;
		z16 += q << 24;

		if (TCarry.Ripples)
		{
			z10 += z9 >> SM2Field29.Bits;
			result.L0 = z9 & mask;
			z11 += z10 >> SM2Field29.Bits;
			result.L1 = z10 & mask;
			z12 += z11 >> SM2Field29.Bits;
			result.L2 = z11 & mask;
			z13 += z12 >> SM2Field29.Bits;
			result.L3 = z12 & mask;
			z14 += z13 >> SM2Field29.Bits;
			result.L4 = z13 & mask;
			z15 += z14 >> SM2Field29.Bits;
			result.L5 = z14 & mask;
			z16 += z15 >> SM2Field29.Bits;
			result.L6 = z15 & mask;
			result.L7 = z16 & mask;
			result.L8 = z16 >> SM2Field29.Bits;
			return;
		}

		Vector512<ulong> c9 = z9 >> SM2Field29.Bits;
		Vector512<ulong> c10 = z10 >> SM2Field29.Bits;
		Vector512<ulong> c11 = z11 >> SM2Field29.Bits;
		Vector512<ulong> c12 = z12 >> SM2Field29.Bits;
		Vector512<ulong> c13 = z13 >> SM2Field29.Bits;
		Vector512<ulong> c14 = z14 >> SM2Field29.Bits;
		Vector512<ulong> c15 = z15 >> SM2Field29.Bits;
		Vector512<ulong> c16 = z16 >> SM2Field29.Bits;
		z9 &= mask;
		z10 = (z10 & mask) + c9;
		z11 = (z11 & mask) + c10;
		z12 = (z12 & mask) + c11;
		z13 = (z13 & mask) + c12;
		z14 = (z14 & mask) + c13;
		z15 = (z15 & mask) + c14;
		z16 = (z16 & mask) + c15;
		Vector512<ulong> d10 = z10 >> SM2Field29.Bits;
		Vector512<ulong> d11 = z11 >> SM2Field29.Bits;
		Vector512<ulong> d12 = z12 >> SM2Field29.Bits;
		Vector512<ulong> d13 = z13 >> SM2Field29.Bits;
		Vector512<ulong> d14 = z14 >> SM2Field29.Bits;
		Vector512<ulong> d15 = z15 >> SM2Field29.Bits;
		Vector512<ulong> d16 = z16 >> SM2Field29.Bits;
		result.L0 = z9;
		result.L1 = z10 & mask;
		result.L2 = (z11 & mask) + d10;
		result.L3 = (z12 & mask) + d11;
		result.L4 = (z13 & mask) + d12;
		result.L5 = (z14 & mask) + d13;
		result.L6 = (z15 & mask) + d14;
		result.L7 = (z16 & mask) + d15;
		result.L8 = c16 + d16;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Square(in SM2Field29x8Avx512 value, out SM2Field29x8Avx512 result)
	{
		Square<TwoStepCarry>(in value, out result);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void SquareRipple(in SM2Field29x8Avx512 value, out SM2Field29x8Avx512 result)
	{
		Square<RippleCarry>(in value, out result);
	}

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void Square<TCarry>(in SM2Field29x8Avx512 value, out SM2Field29x8Avx512 result) where TCarry : struct, ISM2Carry
	{
		Vector512<ulong> mask = Vector512.Create(SM2Field29.Mask);

		Vector512<ulong> y = value.L0;
		Vector512<ulong> z0 = M(y, y);
		Vector512<ulong> q = z0 & mask;
		Vector512<ulong> z1 = z0 >> SM2Field29.Bits;
		Vector512<ulong> z2 = q << 6;
		Vector512<ulong> z3 = Vector512.Create(SM2Field29.Bias3) - (q << 9);
		Vector512<ulong> z7 = Vector512.Create(SM2Field29.Bias7) - (q << 21);
		Vector512<ulong> z8 = (q << 24) + Vector512.Create(SM2Field29.BiasMiddle);

		y = value.L1;
		Vector512<ulong> twice = y + y;
		z1 += M(value.L0, twice);
		z2 += M(y, y);
		q = z1 & mask;
		z2 += z1 >> SM2Field29.Bits;
		z3 += q << 6;
		Vector512<ulong> z4 = Vector512.Create(SM2Field29.BiasMiddle) - (q << 9);
		z8 -= q << 21;
		Vector512<ulong> z9 = (q << 24) + Vector512.Create(SM2Field29.BiasMiddle);

		y = value.L2;
		twice = y + y;
		z2 += M(value.L0, twice);
		z3 += M(value.L1, twice);
		z4 += M(y, y);
		q = z2 & mask;
		z3 += z2 >> SM2Field29.Bits;
		z4 += q << 6;
		Vector512<ulong> z5 = Vector512.Create(SM2Field29.BiasMiddle) - (q << 9);
		z9 -= q << 21;
		Vector512<ulong> z10 = (q << 24) + Vector512.Create(SM2Field29.Bias10);

		y = value.L3;
		twice = y + y;
		z3 += M(value.L0, twice);
		z4 += M(value.L1, twice);
		z5 += M(value.L2, twice);
		Vector512<ulong> z6 = M(y, y) + Vector512.Create(SM2Field29.BiasMiddle);
		q = z3 & mask;
		z4 += z3 >> SM2Field29.Bits;
		z5 += q << 6;
		z6 -= q << 9;
		z10 -= q << 21;
		Vector512<ulong> z11 = (q << 24) + Vector512.Create(SM2Field29.Bias11);

		y = value.L4;
		twice = y + y;
		z4 += M(value.L0, twice);
		z5 += M(value.L1, twice);
		z6 += M(value.L2, twice);
		z7 += M(value.L3, twice);
		z8 += M(y, y);
		q = z4 & mask;
		z5 += z4 >> SM2Field29.Bits;
		z6 += q << 6;
		z7 -= q << 9;
		z11 -= q << 21;
		Vector512<ulong> z12 = (q << 24) + Vector512.Create(SM2Field29.BiasMiddle);

		y = value.L5;
		twice = y + y;
		z5 += M(value.L0, twice);
		z6 += M(value.L1, twice);
		z7 += M(value.L2, twice);
		z8 += M(value.L3, twice);
		z9 += M(value.L4, twice);
		z10 += M(y, y);
		q = z5 & mask;
		z6 += z5 >> SM2Field29.Bits;
		z7 += q << 6;
		z8 -= q << 9;
		z12 -= q << 21;
		Vector512<ulong> z13 = (q << 24) + Vector512.Create(SM2Field29.BiasMiddle);

		y = value.L6;
		twice = y + y;
		z6 += M(value.L0, twice);
		z7 += M(value.L1, twice);
		z8 += M(value.L2, twice);
		z9 += M(value.L3, twice);
		z10 += M(value.L4, twice);
		z11 += M(value.L5, twice);
		z12 += M(y, y);
		q = z6 & mask;
		z7 += z6 >> SM2Field29.Bits;
		z8 += q << 6;
		z9 -= q << 9;
		z13 -= q << 21;
		Vector512<ulong> z14 = (q << 24) + Vector512.Create(SM2Field29.BiasMiddle);

		y = value.L7;
		twice = y + y;
		z7 += M(value.L0, twice);
		z8 += M(value.L1, twice);
		z9 += M(value.L2, twice);
		z10 += M(value.L3, twice);
		z11 += M(value.L4, twice);
		z12 += M(value.L5, twice);
		z13 += M(value.L6, twice);
		z14 += M(y, y);
		q = z7 & mask;
		z8 += z7 >> SM2Field29.Bits;
		z9 += q << 6;
		z10 -= q << 9;
		z14 -= q << 21;
		Vector512<ulong> z15 = (q << 24) + Vector512.Create(SM2Field29.Bias15);

		y = value.L8;
		twice = y + y;
		z8 += M(value.L0, twice);
		z9 += M(value.L1, twice);
		z10 += M(value.L2, twice);
		z11 += M(value.L3, twice);
		z12 += M(value.L4, twice);
		z13 += M(value.L5, twice);
		z14 += M(value.L6, twice);
		z15 += M(value.L7, twice);
		Vector512<ulong> z16 = M(y, y);
		q = z8 & mask;
		z9 += z8 >> SM2Field29.Bits;
		z10 += q << 6;
		z11 -= q << 9;
		z15 -= q << 21;
		z16 += q << 24;

		if (TCarry.Ripples)
		{
			z10 += z9 >> SM2Field29.Bits;
			result.L0 = z9 & mask;
			z11 += z10 >> SM2Field29.Bits;
			result.L1 = z10 & mask;
			z12 += z11 >> SM2Field29.Bits;
			result.L2 = z11 & mask;
			z13 += z12 >> SM2Field29.Bits;
			result.L3 = z12 & mask;
			z14 += z13 >> SM2Field29.Bits;
			result.L4 = z13 & mask;
			z15 += z14 >> SM2Field29.Bits;
			result.L5 = z14 & mask;
			z16 += z15 >> SM2Field29.Bits;
			result.L6 = z15 & mask;
			result.L7 = z16 & mask;
			result.L8 = z16 >> SM2Field29.Bits;
			return;
		}

		Vector512<ulong> c9 = z9 >> SM2Field29.Bits;
		Vector512<ulong> c10 = z10 >> SM2Field29.Bits;
		Vector512<ulong> c11 = z11 >> SM2Field29.Bits;
		Vector512<ulong> c12 = z12 >> SM2Field29.Bits;
		Vector512<ulong> c13 = z13 >> SM2Field29.Bits;
		Vector512<ulong> c14 = z14 >> SM2Field29.Bits;
		Vector512<ulong> c15 = z15 >> SM2Field29.Bits;
		Vector512<ulong> c16 = z16 >> SM2Field29.Bits;
		z9 &= mask;
		z10 = (z10 & mask) + c9;
		z11 = (z11 & mask) + c10;
		z12 = (z12 & mask) + c11;
		z13 = (z13 & mask) + c12;
		z14 = (z14 & mask) + c13;
		z15 = (z15 & mask) + c14;
		z16 = (z16 & mask) + c15;
		Vector512<ulong> d10 = z10 >> SM2Field29.Bits;
		Vector512<ulong> d11 = z11 >> SM2Field29.Bits;
		Vector512<ulong> d12 = z12 >> SM2Field29.Bits;
		Vector512<ulong> d13 = z13 >> SM2Field29.Bits;
		Vector512<ulong> d14 = z14 >> SM2Field29.Bits;
		Vector512<ulong> d15 = z15 >> SM2Field29.Bits;
		Vector512<ulong> d16 = z16 >> SM2Field29.Bits;
		result.L0 = z9;
		result.L1 = z10 & mask;
		result.L2 = (z11 & mask) + d10;
		result.L3 = (z12 & mask) + d11;
		result.L4 = (z13 & mask) + d12;
		result.L5 = (z14 & mask) + d13;
		result.L6 = (z15 & mask) + d14;
		result.L7 = (z16 & mask) + d15;
		result.L8 = c16 + d16;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Add(in SM2Field29x8Avx512 left, in SM2Field29x8Avx512 right, out SM2Field29x8Avx512 result)
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

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Subtract(in SM2Field29x8Avx512 left, in SM2Field29x8Avx512 right, out SM2Field29x8Avx512 result)
	{
		Vector512<ulong> middle = Vector512.Create(SM2Field29.FourPMiddle);
		result.L0 = left.L0 + Vector512.Create(SM2Field29.FourP0) - right.L0;
		result.L1 = left.L1 + Vector512.Create(SM2Field29.FourP1) - right.L1;
		result.L2 = left.L2 + Vector512.Create(SM2Field29.FourP2) - right.L2;
		result.L3 = left.L3 + Vector512.Create(SM2Field29.FourP3) - right.L3;
		result.L4 = left.L4 + middle - right.L4;
		result.L5 = left.L5 + middle - right.L5;
		result.L6 = left.L6 + middle - right.L6;
		result.L7 = left.L7 + Vector512.Create(SM2Field29.FourP7) - right.L7;
		result.L8 = left.L8 + Vector512.Create(SM2Field29.FourP8) - right.L8;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Reduce(in SM2Field29x8Avx512 value, out SM2Field29x8Avx512 result)
	{
		Vector512<ulong> mask = Vector512.Create(SM2Field29.Mask);
		Vector512<ulong> h = value.L8 >> 24;
		Vector512<ulong> t0 = value.L0 + h;
		Vector512<ulong> t1 = value.L1 + (t0 >> SM2Field29.Bits);
		Vector512<ulong> t2 = value.L2 + (h << 38) - (h << 6) + (t1 >> SM2Field29.Bits);
		Vector512<ulong> t3 = value.L3 + (t2 >> SM2Field29.Bits);
		Vector512<ulong> t4 = value.L4 + (t3 >> SM2Field29.Bits);
		Vector512<ulong> t5 = value.L5 + (t4 >> SM2Field29.Bits);
		Vector512<ulong> t6 = value.L6 + (t5 >> SM2Field29.Bits);
		Vector512<ulong> t7 = value.L7 + (h << 21) + (t6 >> SM2Field29.Bits);
		result.L8 = (value.L8 & Vector512.Create(SM2Field29.TopMask)) + (t7 >> SM2Field29.Bits);
		result.L0 = t0 & mask;
		result.L1 = t1 & mask;
		result.L2 = t2 & mask;
		result.L3 = t3 & mask;
		result.L4 = t4 & mask;
		result.L5 = t5 & mask;
		result.L6 = t6 & mask;
		result.L7 = t7 & mask;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ConditionalSelect(ref readonly ulong mask, in SM2Field29x8Avx512 whenSet, in SM2Field29x8Avx512 whenClear, out SM2Field29x8Avx512 result)
	{
		Vector512<ulong> select = Vector512.LoadUnsafe(in mask);
		result.L0 = Vector512.ConditionalSelect(select, whenSet.L0, whenClear.L0);
		result.L1 = Vector512.ConditionalSelect(select, whenSet.L1, whenClear.L1);
		result.L2 = Vector512.ConditionalSelect(select, whenSet.L2, whenClear.L2);
		result.L3 = Vector512.ConditionalSelect(select, whenSet.L3, whenClear.L3);
		result.L4 = Vector512.ConditionalSelect(select, whenSet.L4, whenClear.L4);
		result.L5 = Vector512.ConditionalSelect(select, whenSet.L5, whenClear.L5);
		result.L6 = Vector512.ConditionalSelect(select, whenSet.L6, whenClear.L6);
		result.L7 = Vector512.ConditionalSelect(select, whenSet.L7, whenClear.L7);
		result.L8 = Vector512.ConditionalSelect(select, whenSet.L8, whenClear.L8);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ConditionalNegate(ref readonly ulong mask, ref SM2Field29x8Avx512 value)
	{
		Vector512<ulong> select = Vector512.LoadUnsafe(in mask);
		Vector512<ulong> middle = Vector512.Create(SM2Field29.FourPMiddle);
		value.L0 = Vector512.ConditionalSelect(select, Vector512.Create(SM2Field29.FourP0) - value.L0, value.L0);
		value.L1 = Vector512.ConditionalSelect(select, Vector512.Create(SM2Field29.FourP1) - value.L1, value.L1);
		value.L2 = Vector512.ConditionalSelect(select, Vector512.Create(SM2Field29.FourP2) - value.L2, value.L2);
		value.L3 = Vector512.ConditionalSelect(select, Vector512.Create(SM2Field29.FourP3) - value.L3, value.L3);
		value.L4 = Vector512.ConditionalSelect(select, middle - value.L4, value.L4);
		value.L5 = Vector512.ConditionalSelect(select, middle - value.L5, value.L5);
		value.L6 = Vector512.ConditionalSelect(select, middle - value.L6, value.L6);
		value.L7 = Vector512.ConditionalSelect(select, Vector512.Create(SM2Field29.FourP7) - value.L7, value.L7);
		value.L8 = Vector512.ConditionalSelect(select, Vector512.Create(SM2Field29.FourP8) - value.L8, value.L8);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Halve(in SM2Field29x8Avx512 value, out SM2Field29x8Avx512 result)
	{
		Vector512<ulong> one = Vector512<ulong>.One;
		Vector512<ulong> odd = Vector512<ulong>.Zero - (value.L0 & one);
		Vector512<ulong> low = Vector512.Create(SM2Field29.PLow);
		Vector512<ulong> t0 = value.L0 + (odd & low);
		Vector512<ulong> t1 = value.L1 + (odd & low);
		Vector512<ulong> t2 = value.L2 + (odd & Vector512.Create(SM2Field29.P2));
		Vector512<ulong> t3 = value.L3 + (odd & Vector512.Create(SM2Field29.P3));
		Vector512<ulong> t4 = value.L4 + (odd & low);
		Vector512<ulong> t5 = value.L5 + (odd & low);
		Vector512<ulong> t6 = value.L6 + (odd & low);
		Vector512<ulong> t7 = value.L7 + (odd & Vector512.Create(SM2Field29.P7));
		Vector512<ulong> t8 = value.L8 + (odd & Vector512.Create(SM2Field29.P8));
		result.L0 = (t0 >> 1) + ((t1 & one) << 28);
		result.L1 = (t1 >> 1) + ((t2 & one) << 28);
		result.L2 = (t2 >> 1) + ((t3 & one) << 28);
		result.L3 = (t3 >> 1) + ((t4 & one) << 28);
		result.L4 = (t4 >> 1) + ((t5 & one) << 28);
		result.L5 = (t5 >> 1) + ((t6 & one) << 28);
		result.L6 = (t6 >> 1) + ((t7 & one) << 28);
		result.L7 = (t7 >> 1) + ((t8 & one) << 28);
		result.L8 = t8 >> 1;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void MoveDown(in SM2Field29x8Avx512 value, int distance, out SM2Field29x8Avx512 result)
	{
		Debug.Assert(distance is 1 or 2 or 4);

		Vector512<ulong> indices = distance switch
		{
			4 => Vector512.Create(4UL, 5, 6, 7, 4, 5, 6, 7),
			2 => Vector512.Create(2UL, 3, 2, 3, 6, 7, 6, 7),
			_ => Vector512.Create(1UL, 0, 3, 2, 5, 4, 7, 6)
		};
		result.L0 = Vector512.Shuffle(value.L0, indices);
		result.L1 = Vector512.Shuffle(value.L1, indices);
		result.L2 = Vector512.Shuffle(value.L2, indices);
		result.L3 = Vector512.Shuffle(value.L3, indices);
		result.L4 = Vector512.Shuffle(value.L4, indices);
		result.L5 = Vector512.Shuffle(value.L5, indices);
		result.L6 = Vector512.Shuffle(value.L6, indices);
		result.L7 = Vector512.Shuffle(value.L7, indices);
		result.L8 = Vector512.Shuffle(value.L8, indices);
	}

	// An 8 × 8 transpose of the limbs: the unpacks pair the limbs of two entries, and two rounds of 128-bit block shuffles gather each limb of all eight.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void LoadEntries(ref readonly ulong entries, out SM2Field29x8Avx512 x, out SM2Field29x8Avx512 y)
	{
		ref ulong source = ref Unsafe.AsRef(in entries);
		Vector512<ulong> r0 = Vector512.LoadUnsafe(ref source);
		Vector512<ulong> r1 = Vector512.LoadUnsafe(ref source, 8);
		Vector512<ulong> r2 = Vector512.LoadUnsafe(ref source, 16);
		Vector512<ulong> r3 = Vector512.LoadUnsafe(ref source, 24);
		Vector512<ulong> r4 = Vector512.LoadUnsafe(ref source, 32);
		Vector512<ulong> r5 = Vector512.LoadUnsafe(ref source, 40);
		Vector512<ulong> r6 = Vector512.LoadUnsafe(ref source, 48);
		Vector512<ulong> r7 = Vector512.LoadUnsafe(ref source, 56);
		Vector512<ulong> even01 = Avx512F.UnpackLow(r0, r1);
		Vector512<ulong> odd01 = Avx512F.UnpackHigh(r0, r1);
		Vector512<ulong> even23 = Avx512F.UnpackLow(r2, r3);
		Vector512<ulong> odd23 = Avx512F.UnpackHigh(r2, r3);
		Vector512<ulong> even45 = Avx512F.UnpackLow(r4, r5);
		Vector512<ulong> odd45 = Avx512F.UnpackHigh(r4, r5);
		Vector512<ulong> even67 = Avx512F.UnpackLow(r6, r7);
		Vector512<ulong> odd67 = Avx512F.UnpackHigh(r6, r7);
		Vector512<ulong> even03Low = Avx512F.Shuffle4x128(even01, even23, EvenBlocks);
		Vector512<ulong> even03High = Avx512F.Shuffle4x128(even01, even23, OddBlocks);
		Vector512<ulong> even47Low = Avx512F.Shuffle4x128(even45, even67, EvenBlocks);
		Vector512<ulong> even47High = Avx512F.Shuffle4x128(even45, even67, OddBlocks);
		Vector512<ulong> odd03Low = Avx512F.Shuffle4x128(odd01, odd23, EvenBlocks);
		Vector512<ulong> odd03High = Avx512F.Shuffle4x128(odd01, odd23, OddBlocks);
		Vector512<ulong> odd47Low = Avx512F.Shuffle4x128(odd45, odd67, EvenBlocks);
		Vector512<ulong> odd47High = Avx512F.Shuffle4x128(odd45, odd67, OddBlocks);
		FromSaturated(Avx512F.Shuffle4x128(even03Low, even47Low, EvenBlocks), Avx512F.Shuffle4x128(odd03Low, odd47Low, EvenBlocks), Avx512F.Shuffle4x128(even03High, even47High, EvenBlocks), Avx512F.Shuffle4x128(odd03High, odd47High, EvenBlocks), out x);
		FromSaturated(Avx512F.Shuffle4x128(even03Low, even47Low, OddBlocks), Avx512F.Shuffle4x128(odd03Low, odd47Low, OddBlocks), Avx512F.Shuffle4x128(even03High, even47High, OddBlocks), Avx512F.Shuffle4x128(odd03High, odd47High, OddBlocks), out y);
	}

	// 2v for the value v below 2^256 of four 64-bit limbs w0 to w3, lane by lane, in limbs below 2^29, limb 8 below 2^25: limb i takes bits 29i − 1 to 29i + 27 of v.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FromSaturated(Vector512<ulong> w0, Vector512<ulong> w1, Vector512<ulong> w2, Vector512<ulong> w3, out SM2Field29x8Avx512 result)
	{
		Vector512<ulong> mask = Vector512.Create(SM2Field29.Mask);
		result.L0 = w0 << 1 & mask;
		result.L1 = w0 >> 28 & mask;
		result.L2 = (w0 >> 57 | w1 << 7) & mask;
		result.L3 = w1 >> 22 & mask;
		result.L4 = (w1 >> 51 | w2 << 13) & mask;
		result.L5 = w2 >> 16 & mask;
		result.L6 = (w2 >> 45 | w3 << 19) & mask;
		result.L7 = w3 >> 10 & mask;
		result.L8 = w3 >> 39;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> M(Vector512<ulong> x, Vector512<ulong> y)
	{
		return Avx512F.Multiply(x.AsUInt32(), y.AsUInt32());
	}
}
