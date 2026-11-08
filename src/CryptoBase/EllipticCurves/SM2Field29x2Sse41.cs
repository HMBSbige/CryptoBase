namespace CryptoBase.EllipticCurves;

// The lanes of SM2Field29 in the two lanes of Vector128 on x64.
internal struct SM2Field29x2Sse41 : ISM2Field29Lanes<SM2Field29x2Sse41>
{
	internal Vector128<ulong> L0;
	internal Vector128<ulong> L1;
	internal Vector128<ulong> L2;
	internal Vector128<ulong> L3;
	internal Vector128<ulong> L4;
	internal Vector128<ulong> L5;
	internal Vector128<ulong> L6;
	internal Vector128<ulong> L7;
	internal Vector128<ulong> L8;

	public static bool IsSupported => Sse41.IsSupported && Vector128.IsHardwareAccelerated;

	public static int LaneCount => Vector128<ulong>.Count;

	public static void One(out SM2Field29x2Sse41 result)
	{
		Vector128<ulong> zero = Vector128<ulong>.Zero;
		result.L0 = Vector128.Create(SM2Field29.One0);
		result.L1 = zero;
		result.L2 = Vector128.Create(SM2Field29.One2);
		result.L3 = Vector128.Create(SM2Field29.One3);
		result.L4 = zero;
		result.L5 = zero;
		result.L6 = zero;
		result.L7 = Vector128.Create(SM2Field29.One7);
		result.L8 = zero;
	}

	// The rows and rounds of SM2Field29.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Multiply(in SM2Field29x2Sse41 left, in SM2Field29x2Sse41 right, out SM2Field29x2Sse41 result)
	{
		Multiply<TwoStepCarry>(in left, in right, out result);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void MultiplyRipple(in SM2Field29x2Sse41 left, in SM2Field29x2Sse41 right, out SM2Field29x2Sse41 result)
	{
		Multiply<RippleCarry>(in left, in right, out result);
	}

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void Multiply<TCarry>(in SM2Field29x2Sse41 left, in SM2Field29x2Sse41 right, out SM2Field29x2Sse41 result) where TCarry : struct, ISM2Carry
	{
		Vector128<ulong> mask = Vector128.Create(SM2Field29.Mask);

		Vector128<ulong> y = right.L0;
		Vector128<ulong> z0 = M(left.L0, y);
		Vector128<ulong> z1 = M(left.L1, y);
		Vector128<ulong> z2 = M(left.L2, y);
		Vector128<ulong> z3 = M(left.L3, y) + Vector128.Create(SM2Field29.Bias3);
		Vector128<ulong> z4 = M(left.L4, y) + Vector128.Create(SM2Field29.BiasMiddle);
		Vector128<ulong> z5 = M(left.L5, y) + Vector128.Create(SM2Field29.BiasMiddle);
		Vector128<ulong> z6 = M(left.L6, y) + Vector128.Create(SM2Field29.BiasMiddle);
		Vector128<ulong> z7 = M(left.L7, y) + Vector128.Create(SM2Field29.Bias7);
		Vector128<ulong> z8 = M(left.L8, y) + Vector128.Create(SM2Field29.BiasMiddle);
		Vector128<ulong> q = z0 & mask;
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
		Vector128<ulong> z9 = M(left.L8, y) + Vector128.Create(SM2Field29.BiasMiddle);
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
		Vector128<ulong> z10 = M(left.L8, y) + Vector128.Create(SM2Field29.Bias10);
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
		Vector128<ulong> z11 = M(left.L8, y) + Vector128.Create(SM2Field29.Bias11);
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
		Vector128<ulong> z12 = M(left.L8, y) + Vector128.Create(SM2Field29.BiasMiddle);
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
		Vector128<ulong> z13 = M(left.L8, y) + Vector128.Create(SM2Field29.BiasMiddle);
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
		Vector128<ulong> z14 = M(left.L8, y) + Vector128.Create(SM2Field29.BiasMiddle);
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
		Vector128<ulong> z15 = M(left.L8, y) + Vector128.Create(SM2Field29.Bias15);
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
		Vector128<ulong> z16 = M(left.L8, y);
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

		Vector128<ulong> c9 = z9 >> SM2Field29.Bits;
		Vector128<ulong> c10 = z10 >> SM2Field29.Bits;
		Vector128<ulong> c11 = z11 >> SM2Field29.Bits;
		Vector128<ulong> c12 = z12 >> SM2Field29.Bits;
		Vector128<ulong> c13 = z13 >> SM2Field29.Bits;
		Vector128<ulong> c14 = z14 >> SM2Field29.Bits;
		Vector128<ulong> c15 = z15 >> SM2Field29.Bits;
		Vector128<ulong> c16 = z16 >> SM2Field29.Bits;
		z9 &= mask;
		z10 = (z10 & mask) + c9;
		z11 = (z11 & mask) + c10;
		z12 = (z12 & mask) + c11;
		z13 = (z13 & mask) + c12;
		z14 = (z14 & mask) + c13;
		z15 = (z15 & mask) + c14;
		z16 = (z16 & mask) + c15;
		Vector128<ulong> d10 = z10 >> SM2Field29.Bits;
		Vector128<ulong> d11 = z11 >> SM2Field29.Bits;
		Vector128<ulong> d12 = z12 >> SM2Field29.Bits;
		Vector128<ulong> d13 = z13 >> SM2Field29.Bits;
		Vector128<ulong> d14 = z14 >> SM2Field29.Bits;
		Vector128<ulong> d15 = z15 >> SM2Field29.Bits;
		Vector128<ulong> d16 = z16 >> SM2Field29.Bits;
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
	public static void Square(in SM2Field29x2Sse41 value, out SM2Field29x2Sse41 result)
	{
		Square<TwoStepCarry>(in value, out result);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void SquareRipple(in SM2Field29x2Sse41 value, out SM2Field29x2Sse41 result)
	{
		Square<RippleCarry>(in value, out result);
	}

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void Square<TCarry>(in SM2Field29x2Sse41 value, out SM2Field29x2Sse41 result) where TCarry : struct, ISM2Carry
	{
		Vector128<ulong> mask = Vector128.Create(SM2Field29.Mask);

		Vector128<ulong> y = value.L0;
		Vector128<ulong> z0 = M(y, y);
		Vector128<ulong> q = z0 & mask;
		Vector128<ulong> z1 = z0 >> SM2Field29.Bits;
		Vector128<ulong> z2 = q << 6;
		Vector128<ulong> z3 = Vector128.Create(SM2Field29.Bias3) - (q << 9);
		Vector128<ulong> z7 = Vector128.Create(SM2Field29.Bias7) - (q << 21);
		Vector128<ulong> z8 = (q << 24) + Vector128.Create(SM2Field29.BiasMiddle);

		y = value.L1;
		Vector128<ulong> twice = y + y;
		z1 += M(value.L0, twice);
		z2 += M(y, y);
		q = z1 & mask;
		z2 += z1 >> SM2Field29.Bits;
		z3 += q << 6;
		Vector128<ulong> z4 = Vector128.Create(SM2Field29.BiasMiddle) - (q << 9);
		z8 -= q << 21;
		Vector128<ulong> z9 = (q << 24) + Vector128.Create(SM2Field29.BiasMiddle);

		y = value.L2;
		twice = y + y;
		z2 += M(value.L0, twice);
		z3 += M(value.L1, twice);
		z4 += M(y, y);
		q = z2 & mask;
		z3 += z2 >> SM2Field29.Bits;
		z4 += q << 6;
		Vector128<ulong> z5 = Vector128.Create(SM2Field29.BiasMiddle) - (q << 9);
		z9 -= q << 21;
		Vector128<ulong> z10 = (q << 24) + Vector128.Create(SM2Field29.Bias10);

		y = value.L3;
		twice = y + y;
		z3 += M(value.L0, twice);
		z4 += M(value.L1, twice);
		z5 += M(value.L2, twice);
		Vector128<ulong> z6 = M(y, y) + Vector128.Create(SM2Field29.BiasMiddle);
		q = z3 & mask;
		z4 += z3 >> SM2Field29.Bits;
		z5 += q << 6;
		z6 -= q << 9;
		z10 -= q << 21;
		Vector128<ulong> z11 = (q << 24) + Vector128.Create(SM2Field29.Bias11);

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
		Vector128<ulong> z12 = (q << 24) + Vector128.Create(SM2Field29.BiasMiddle);

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
		Vector128<ulong> z13 = (q << 24) + Vector128.Create(SM2Field29.BiasMiddle);

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
		Vector128<ulong> z14 = (q << 24) + Vector128.Create(SM2Field29.BiasMiddle);

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
		Vector128<ulong> z15 = (q << 24) + Vector128.Create(SM2Field29.Bias15);

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
		Vector128<ulong> z16 = M(y, y);
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

		Vector128<ulong> c9 = z9 >> SM2Field29.Bits;
		Vector128<ulong> c10 = z10 >> SM2Field29.Bits;
		Vector128<ulong> c11 = z11 >> SM2Field29.Bits;
		Vector128<ulong> c12 = z12 >> SM2Field29.Bits;
		Vector128<ulong> c13 = z13 >> SM2Field29.Bits;
		Vector128<ulong> c14 = z14 >> SM2Field29.Bits;
		Vector128<ulong> c15 = z15 >> SM2Field29.Bits;
		Vector128<ulong> c16 = z16 >> SM2Field29.Bits;
		z9 &= mask;
		z10 = (z10 & mask) + c9;
		z11 = (z11 & mask) + c10;
		z12 = (z12 & mask) + c11;
		z13 = (z13 & mask) + c12;
		z14 = (z14 & mask) + c13;
		z15 = (z15 & mask) + c14;
		z16 = (z16 & mask) + c15;
		Vector128<ulong> d10 = z10 >> SM2Field29.Bits;
		Vector128<ulong> d11 = z11 >> SM2Field29.Bits;
		Vector128<ulong> d12 = z12 >> SM2Field29.Bits;
		Vector128<ulong> d13 = z13 >> SM2Field29.Bits;
		Vector128<ulong> d14 = z14 >> SM2Field29.Bits;
		Vector128<ulong> d15 = z15 >> SM2Field29.Bits;
		Vector128<ulong> d16 = z16 >> SM2Field29.Bits;
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
	public static void Add(in SM2Field29x2Sse41 left, in SM2Field29x2Sse41 right, out SM2Field29x2Sse41 result)
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
	public static void Subtract(in SM2Field29x2Sse41 left, in SM2Field29x2Sse41 right, out SM2Field29x2Sse41 result)
	{
		Vector128<ulong> middle = Vector128.Create(SM2Field29.FourPMiddle);
		result.L0 = left.L0 + Vector128.Create(SM2Field29.FourP0) - right.L0;
		result.L1 = left.L1 + Vector128.Create(SM2Field29.FourP1) - right.L1;
		result.L2 = left.L2 + Vector128.Create(SM2Field29.FourP2) - right.L2;
		result.L3 = left.L3 + Vector128.Create(SM2Field29.FourP3) - right.L3;
		result.L4 = left.L4 + middle - right.L4;
		result.L5 = left.L5 + middle - right.L5;
		result.L6 = left.L6 + middle - right.L6;
		result.L7 = left.L7 + Vector128.Create(SM2Field29.FourP7) - right.L7;
		result.L8 = left.L8 + Vector128.Create(SM2Field29.FourP8) - right.L8;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Reduce(in SM2Field29x2Sse41 value, out SM2Field29x2Sse41 result)
	{
		Vector128<ulong> mask = Vector128.Create(SM2Field29.Mask);
		Vector128<ulong> h = value.L8 >> 24;
		Vector128<ulong> t0 = value.L0 + h;
		Vector128<ulong> t1 = value.L1 + (t0 >> SM2Field29.Bits);
		Vector128<ulong> t2 = value.L2 + (h << 38) - (h << 6) + (t1 >> SM2Field29.Bits);
		Vector128<ulong> t3 = value.L3 + (t2 >> SM2Field29.Bits);
		Vector128<ulong> t4 = value.L4 + (t3 >> SM2Field29.Bits);
		Vector128<ulong> t5 = value.L5 + (t4 >> SM2Field29.Bits);
		Vector128<ulong> t6 = value.L6 + (t5 >> SM2Field29.Bits);
		Vector128<ulong> t7 = value.L7 + (h << 21) + (t6 >> SM2Field29.Bits);
		result.L8 = (value.L8 & Vector128.Create(SM2Field29.TopMask)) + (t7 >> SM2Field29.Bits);
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
	public static void ConditionalSelect(ref readonly ulong mask, in SM2Field29x2Sse41 whenSet, in SM2Field29x2Sse41 whenClear, out SM2Field29x2Sse41 result)
	{
		Vector128<ulong> select = Vector128.LoadUnsafe(in mask);
		result.L0 = Vector128.ConditionalSelect(select, whenSet.L0, whenClear.L0);
		result.L1 = Vector128.ConditionalSelect(select, whenSet.L1, whenClear.L1);
		result.L2 = Vector128.ConditionalSelect(select, whenSet.L2, whenClear.L2);
		result.L3 = Vector128.ConditionalSelect(select, whenSet.L3, whenClear.L3);
		result.L4 = Vector128.ConditionalSelect(select, whenSet.L4, whenClear.L4);
		result.L5 = Vector128.ConditionalSelect(select, whenSet.L5, whenClear.L5);
		result.L6 = Vector128.ConditionalSelect(select, whenSet.L6, whenClear.L6);
		result.L7 = Vector128.ConditionalSelect(select, whenSet.L7, whenClear.L7);
		result.L8 = Vector128.ConditionalSelect(select, whenSet.L8, whenClear.L8);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ConditionalNegate(ref readonly ulong mask, ref SM2Field29x2Sse41 value)
	{
		Vector128<ulong> select = Vector128.LoadUnsafe(in mask);
		Vector128<ulong> middle = Vector128.Create(SM2Field29.FourPMiddle);
		value.L0 = Vector128.ConditionalSelect(select, Vector128.Create(SM2Field29.FourP0) - value.L0, value.L0);
		value.L1 = Vector128.ConditionalSelect(select, Vector128.Create(SM2Field29.FourP1) - value.L1, value.L1);
		value.L2 = Vector128.ConditionalSelect(select, Vector128.Create(SM2Field29.FourP2) - value.L2, value.L2);
		value.L3 = Vector128.ConditionalSelect(select, Vector128.Create(SM2Field29.FourP3) - value.L3, value.L3);
		value.L4 = Vector128.ConditionalSelect(select, middle - value.L4, value.L4);
		value.L5 = Vector128.ConditionalSelect(select, middle - value.L5, value.L5);
		value.L6 = Vector128.ConditionalSelect(select, middle - value.L6, value.L6);
		value.L7 = Vector128.ConditionalSelect(select, Vector128.Create(SM2Field29.FourP7) - value.L7, value.L7);
		value.L8 = Vector128.ConditionalSelect(select, Vector128.Create(SM2Field29.FourP8) - value.L8, value.L8);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Halve(in SM2Field29x2Sse41 value, out SM2Field29x2Sse41 result)
	{
		Vector128<ulong> one = Vector128<ulong>.One;
		Vector128<ulong> odd = Vector128<ulong>.Zero - (value.L0 & one);
		Vector128<ulong> low = Vector128.Create(SM2Field29.PLow);
		Vector128<ulong> t0 = value.L0 + (odd & low);
		Vector128<ulong> t1 = value.L1 + (odd & low);
		Vector128<ulong> t2 = value.L2 + (odd & Vector128.Create(SM2Field29.P2));
		Vector128<ulong> t3 = value.L3 + (odd & Vector128.Create(SM2Field29.P3));
		Vector128<ulong> t4 = value.L4 + (odd & low);
		Vector128<ulong> t5 = value.L5 + (odd & low);
		Vector128<ulong> t6 = value.L6 + (odd & low);
		Vector128<ulong> t7 = value.L7 + (odd & Vector128.Create(SM2Field29.P7));
		Vector128<ulong> t8 = value.L8 + (odd & Vector128.Create(SM2Field29.P8));
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
	public static void MoveDown(in SM2Field29x2Sse41 value, int distance, out SM2Field29x2Sse41 result)
	{
		Debug.Assert(distance is 1);

		Vector128<ulong> indices = Vector128.Create(1UL, 0);
		result.L0 = Vector128.Shuffle(value.L0, indices);
		result.L1 = Vector128.Shuffle(value.L1, indices);
		result.L2 = Vector128.Shuffle(value.L2, indices);
		result.L3 = Vector128.Shuffle(value.L3, indices);
		result.L4 = Vector128.Shuffle(value.L4, indices);
		result.L5 = Vector128.Shuffle(value.L5, indices);
		result.L6 = Vector128.Shuffle(value.L6, indices);
		result.L7 = Vector128.Shuffle(value.L7, indices);
		result.L8 = Vector128.Shuffle(value.L8, indices);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void LoadEntries(ref readonly ulong entries, out SM2Field29x2Sse41 x, out SM2Field29x2Sse41 y)
	{
		ref ulong source = ref Unsafe.AsRef(in entries);
		Vector128<ulong> first0 = Vector128.LoadUnsafe(ref source, 0);
		Vector128<ulong> second0 = Vector128.LoadUnsafe(ref source, 8);
		Vector128<ulong> first2 = Vector128.LoadUnsafe(ref source, 2);
		Vector128<ulong> second2 = Vector128.LoadUnsafe(ref source, 10);
		Vector128<ulong> first4 = Vector128.LoadUnsafe(ref source, 4);
		Vector128<ulong> second4 = Vector128.LoadUnsafe(ref source, 12);
		Vector128<ulong> first6 = Vector128.LoadUnsafe(ref source, 6);
		Vector128<ulong> second6 = Vector128.LoadUnsafe(ref source, 14);
		FromSaturated(Sse2.UnpackLow(first0, second0), Sse2.UnpackHigh(first0, second0), Sse2.UnpackLow(first2, second2), Sse2.UnpackHigh(first2, second2), out x);
		FromSaturated(Sse2.UnpackLow(first4, second4), Sse2.UnpackHigh(first4, second4), Sse2.UnpackLow(first6, second6), Sse2.UnpackHigh(first6, second6), out y);
	}

	// 2v for the value v below 2^256 of four 64-bit limbs w0 to w3, lane by lane, in limbs below 2^29, limb 8 below 2^25: limb i takes bits 29i − 1 to 29i + 27 of v.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FromSaturated(Vector128<ulong> w0, Vector128<ulong> w1, Vector128<ulong> w2, Vector128<ulong> w3, out SM2Field29x2Sse41 result)
	{
		Vector128<ulong> mask = Vector128.Create(SM2Field29.Mask);
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
	private static Vector128<ulong> M(Vector128<ulong> x, Vector128<ulong> y)
	{
		return Sse2.Multiply(x.AsUInt32(), y.AsUInt32());
	}
}
