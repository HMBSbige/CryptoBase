namespace CryptoBase.EllipticCurves;

// The lanes of SM2Field29 in the two lanes of Vector128 on ARM64. The multiplier reads 32-bit lanes packed in 64 bits, so the products take the limbs narrowed, and each product accumulates in the same instruction.
internal struct SM2Field29x2AdvSimd : ISM2Field29Lanes<SM2Field29x2AdvSimd>
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

	public static bool IsSupported => AdvSimd.Arm64.IsSupported && Vector128.IsHardwareAccelerated;

	public static int LaneCount => Vector128<ulong>.Count;

	public static void One(out SM2Field29x2AdvSimd result)
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

	// The rows and rounds of SM2Field29, on the limbs narrowed once each; a column takes the terms of the rounds before just ahead of its own round, the carry last, so that its products do not wait on them.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Multiply(in SM2Field29x2AdvSimd left, in SM2Field29x2AdvSimd right, out SM2Field29x2AdvSimd result)
	{
		Multiply<TwoStepCarry>(in left, in right, out result);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void MultiplyRipple(in SM2Field29x2AdvSimd left, in SM2Field29x2AdvSimd right, out SM2Field29x2AdvSimd result)
	{
		Multiply<RippleCarry>(in left, in right, out result);
	}

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void Multiply<TCarry>(in SM2Field29x2AdvSimd left, in SM2Field29x2AdvSimd right, out SM2Field29x2AdvSimd result) where TCarry : struct, ISM2Carry
	{
		Vector128<ulong> mask = Vector128.Create(SM2Field29.Mask);
		Vector64<uint> a0 = AdvSimd.ExtractNarrowingLower(left.L0);
		Vector64<uint> a1 = AdvSimd.ExtractNarrowingLower(left.L1);
		Vector64<uint> a2 = AdvSimd.ExtractNarrowingLower(left.L2);
		Vector64<uint> a3 = AdvSimd.ExtractNarrowingLower(left.L3);
		Vector64<uint> a4 = AdvSimd.ExtractNarrowingLower(left.L4);
		Vector64<uint> a5 = AdvSimd.ExtractNarrowingLower(left.L5);
		Vector64<uint> a6 = AdvSimd.ExtractNarrowingLower(left.L6);
		Vector64<uint> a7 = AdvSimd.ExtractNarrowingLower(left.L7);
		Vector64<uint> a8 = AdvSimd.ExtractNarrowingLower(left.L8);

		Vector64<uint> y = AdvSimd.ExtractNarrowingLower(right.L0);
		Vector128<ulong> z0 = AdvSimd.MultiplyWideningLower(a0, y);
		Vector128<ulong> z1 = AdvSimd.MultiplyWideningLower(a1, y);
		Vector128<ulong> z2 = AdvSimd.MultiplyWideningLower(a2, y);
		Vector128<ulong> z3 = AdvSimd.MultiplyWideningLowerAndAdd(Vector128.Create(SM2Field29.Bias3), a3, y);
		Vector128<ulong> z4 = AdvSimd.MultiplyWideningLowerAndAdd(Vector128.Create(SM2Field29.BiasMiddle), a4, y);
		Vector128<ulong> z5 = AdvSimd.MultiplyWideningLowerAndAdd(Vector128.Create(SM2Field29.BiasMiddle), a5, y);
		Vector128<ulong> z6 = AdvSimd.MultiplyWideningLowerAndAdd(Vector128.Create(SM2Field29.BiasMiddle), a6, y);
		Vector128<ulong> z7 = AdvSimd.MultiplyWideningLowerAndAdd(Vector128.Create(SM2Field29.Bias7), a7, y);
		Vector128<ulong> z8 = AdvSimd.MultiplyWideningLowerAndAdd(Vector128.Create(SM2Field29.BiasMiddle), a8, y);
		Vector128<ulong> q0 = z0 & mask;

		y = AdvSimd.ExtractNarrowingLower(right.L1);
		z1 = AdvSimd.MultiplyWideningLowerAndAdd(z1, a0, y);
		z2 = AdvSimd.MultiplyWideningLowerAndAdd(z2, a1, y);
		z3 = AdvSimd.MultiplyWideningLowerAndAdd(z3, a2, y);
		z4 = AdvSimd.MultiplyWideningLowerAndAdd(z4, a3, y);
		z5 = AdvSimd.MultiplyWideningLowerAndAdd(z5, a4, y);
		z6 = AdvSimd.MultiplyWideningLowerAndAdd(z6, a5, y);
		z7 = AdvSimd.MultiplyWideningLowerAndAdd(z7, a6, y);
		z8 = AdvSimd.MultiplyWideningLowerAndAdd(z8, a7, y);
		Vector128<ulong> z9 = AdvSimd.MultiplyWideningLowerAndAdd(Vector128.Create(SM2Field29.BiasMiddle), a8, y);
		z1 = CarryInto<TCarry>(z1, z0);
		Vector128<ulong> q1 = z1 & mask;

		y = AdvSimd.ExtractNarrowingLower(right.L2);
		z2 = AdvSimd.MultiplyWideningLowerAndAdd(z2, a0, y);
		z3 = AdvSimd.MultiplyWideningLowerAndAdd(z3, a1, y);
		z4 = AdvSimd.MultiplyWideningLowerAndAdd(z4, a2, y);
		z5 = AdvSimd.MultiplyWideningLowerAndAdd(z5, a3, y);
		z6 = AdvSimd.MultiplyWideningLowerAndAdd(z6, a4, y);
		z7 = AdvSimd.MultiplyWideningLowerAndAdd(z7, a5, y);
		z8 = AdvSimd.MultiplyWideningLowerAndAdd(z8, a6, y);
		z9 = AdvSimd.MultiplyWideningLowerAndAdd(z9, a7, y);
		Vector128<ulong> z10 = AdvSimd.MultiplyWideningLowerAndAdd(Vector128.Create(SM2Field29.Bias10), a8, y);
		z2 += q0 << 6;
		z2 = CarryInto<TCarry>(z2, z1);
		Vector128<ulong> q2 = z2 & mask;

		y = AdvSimd.ExtractNarrowingLower(right.L3);
		z3 = AdvSimd.MultiplyWideningLowerAndAdd(z3, a0, y);
		z4 = AdvSimd.MultiplyWideningLowerAndAdd(z4, a1, y);
		z5 = AdvSimd.MultiplyWideningLowerAndAdd(z5, a2, y);
		z6 = AdvSimd.MultiplyWideningLowerAndAdd(z6, a3, y);
		z7 = AdvSimd.MultiplyWideningLowerAndAdd(z7, a4, y);
		z8 = AdvSimd.MultiplyWideningLowerAndAdd(z8, a5, y);
		z9 = AdvSimd.MultiplyWideningLowerAndAdd(z9, a6, y);
		z10 = AdvSimd.MultiplyWideningLowerAndAdd(z10, a7, y);
		Vector128<ulong> z11 = AdvSimd.MultiplyWideningLowerAndAdd(Vector128.Create(SM2Field29.Bias11), a8, y);
		z3 += q1 << 6;
		z3 -= q0 << 9;
		z3 = CarryInto<TCarry>(z3, z2);
		Vector128<ulong> q3 = z3 & mask;

		y = AdvSimd.ExtractNarrowingLower(right.L4);
		z4 = AdvSimd.MultiplyWideningLowerAndAdd(z4, a0, y);
		z5 = AdvSimd.MultiplyWideningLowerAndAdd(z5, a1, y);
		z6 = AdvSimd.MultiplyWideningLowerAndAdd(z6, a2, y);
		z7 = AdvSimd.MultiplyWideningLowerAndAdd(z7, a3, y);
		z8 = AdvSimd.MultiplyWideningLowerAndAdd(z8, a4, y);
		z9 = AdvSimd.MultiplyWideningLowerAndAdd(z9, a5, y);
		z10 = AdvSimd.MultiplyWideningLowerAndAdd(z10, a6, y);
		z11 = AdvSimd.MultiplyWideningLowerAndAdd(z11, a7, y);
		Vector128<ulong> z12 = AdvSimd.MultiplyWideningLowerAndAdd(Vector128.Create(SM2Field29.BiasMiddle), a8, y);
		z4 += q2 << 6;
		z4 -= q1 << 9;
		z4 = CarryInto<TCarry>(z4, z3);
		Vector128<ulong> q4 = z4 & mask;

		y = AdvSimd.ExtractNarrowingLower(right.L5);
		z5 = AdvSimd.MultiplyWideningLowerAndAdd(z5, a0, y);
		z6 = AdvSimd.MultiplyWideningLowerAndAdd(z6, a1, y);
		z7 = AdvSimd.MultiplyWideningLowerAndAdd(z7, a2, y);
		z8 = AdvSimd.MultiplyWideningLowerAndAdd(z8, a3, y);
		z9 = AdvSimd.MultiplyWideningLowerAndAdd(z9, a4, y);
		z10 = AdvSimd.MultiplyWideningLowerAndAdd(z10, a5, y);
		z11 = AdvSimd.MultiplyWideningLowerAndAdd(z11, a6, y);
		z12 = AdvSimd.MultiplyWideningLowerAndAdd(z12, a7, y);
		Vector128<ulong> z13 = AdvSimd.MultiplyWideningLowerAndAdd(Vector128.Create(SM2Field29.BiasMiddle), a8, y);
		z5 += q3 << 6;
		z5 -= q2 << 9;
		z5 = CarryInto<TCarry>(z5, z4);
		Vector128<ulong> q5 = z5 & mask;

		y = AdvSimd.ExtractNarrowingLower(right.L6);
		z6 = AdvSimd.MultiplyWideningLowerAndAdd(z6, a0, y);
		z7 = AdvSimd.MultiplyWideningLowerAndAdd(z7, a1, y);
		z8 = AdvSimd.MultiplyWideningLowerAndAdd(z8, a2, y);
		z9 = AdvSimd.MultiplyWideningLowerAndAdd(z9, a3, y);
		z10 = AdvSimd.MultiplyWideningLowerAndAdd(z10, a4, y);
		z11 = AdvSimd.MultiplyWideningLowerAndAdd(z11, a5, y);
		z12 = AdvSimd.MultiplyWideningLowerAndAdd(z12, a6, y);
		z13 = AdvSimd.MultiplyWideningLowerAndAdd(z13, a7, y);
		Vector128<ulong> z14 = AdvSimd.MultiplyWideningLowerAndAdd(Vector128.Create(SM2Field29.BiasMiddle), a8, y);
		z6 += q4 << 6;
		z6 -= q3 << 9;
		z6 = CarryInto<TCarry>(z6, z5);
		Vector128<ulong> q6 = z6 & mask;

		y = AdvSimd.ExtractNarrowingLower(right.L7);
		z7 = AdvSimd.MultiplyWideningLowerAndAdd(z7, a0, y);
		z8 = AdvSimd.MultiplyWideningLowerAndAdd(z8, a1, y);
		z9 = AdvSimd.MultiplyWideningLowerAndAdd(z9, a2, y);
		z10 = AdvSimd.MultiplyWideningLowerAndAdd(z10, a3, y);
		z11 = AdvSimd.MultiplyWideningLowerAndAdd(z11, a4, y);
		z12 = AdvSimd.MultiplyWideningLowerAndAdd(z12, a5, y);
		z13 = AdvSimd.MultiplyWideningLowerAndAdd(z13, a6, y);
		z14 = AdvSimd.MultiplyWideningLowerAndAdd(z14, a7, y);
		Vector128<ulong> z15 = AdvSimd.MultiplyWideningLowerAndAdd(Vector128.Create(SM2Field29.Bias15), a8, y);
		z7 += q5 << 6;
		z7 -= q4 << 9;
		z7 -= q0 << 21;
		z7 = CarryInto<TCarry>(z7, z6);
		Vector128<ulong> q7 = z7 & mask;

		y = AdvSimd.ExtractNarrowingLower(right.L8);
		z8 = AdvSimd.MultiplyWideningLowerAndAdd(z8, a0, y);
		z9 = AdvSimd.MultiplyWideningLowerAndAdd(z9, a1, y);
		z10 = AdvSimd.MultiplyWideningLowerAndAdd(z10, a2, y);
		z11 = AdvSimd.MultiplyWideningLowerAndAdd(z11, a3, y);
		z12 = AdvSimd.MultiplyWideningLowerAndAdd(z12, a4, y);
		z13 = AdvSimd.MultiplyWideningLowerAndAdd(z13, a5, y);
		z14 = AdvSimd.MultiplyWideningLowerAndAdd(z14, a6, y);
		z15 = AdvSimd.MultiplyWideningLowerAndAdd(z15, a7, y);
		Vector128<ulong> z16 = AdvSimd.MultiplyWideningLower(a8, y);
		z8 += q6 << 6;
		z8 -= q5 << 9;
		z8 -= q1 << 21;
		z8 += q0 << 24;
		z8 = CarryInto<TCarry>(z8, z7);
		Vector128<ulong> q8 = z8 & mask;

		z9 += q7 << 6;
		z9 -= q6 << 9;
		z9 -= q2 << 21;
		z9 += q1 << 24;
		z9 = CarryInto<TCarry>(z9, z8);
		z10 += q8 << 6;
		z10 -= q7 << 9;
		z10 -= q3 << 21;
		z10 += q2 << 24;
		z11 -= q8 << 9;
		z11 -= q4 << 21;
		z11 += q3 << 24;
		z12 -= q5 << 21;
		z12 += q4 << 24;
		z13 -= q6 << 21;
		z13 += q5 << 24;
		z14 -= q7 << 21;
		z14 += q6 << 24;
		z15 -= q8 << 21;
		z15 += q7 << 24;
		z16 += q8 << 24;

		if (TCarry.Ripples)
		{
			z10 = CarryInto<TCarry>(z10, z9);
			result.L0 = z9 & mask;
			z11 = CarryInto<TCarry>(z11, z10);
			result.L1 = z10 & mask;
			z12 = CarryInto<TCarry>(z12, z11);
			result.L2 = z11 & mask;
			z13 = CarryInto<TCarry>(z13, z12);
			result.L3 = z12 & mask;
			z14 = CarryInto<TCarry>(z14, z13);
			result.L4 = z13 & mask;
			z15 = CarryInto<TCarry>(z15, z14);
			result.L5 = z14 & mask;
			z16 = CarryInto<TCarry>(z16, z15);
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
	public static void Square(in SM2Field29x2AdvSimd value, out SM2Field29x2AdvSimd result)
	{
		Square<TwoStepCarry>(in value, out result);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void SquareRipple(in SM2Field29x2AdvSimd value, out SM2Field29x2AdvSimd result)
	{
		Square<RippleCarry>(in value, out result);
	}

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void Square<TCarry>(in SM2Field29x2AdvSimd value, out SM2Field29x2AdvSimd result) where TCarry : struct, ISM2Carry
	{
		Vector128<ulong> mask = Vector128.Create(SM2Field29.Mask);
		Vector64<uint> a0 = AdvSimd.ExtractNarrowingLower(value.L0);
		Vector64<uint> a1 = AdvSimd.ExtractNarrowingLower(value.L1);
		Vector64<uint> a2 = AdvSimd.ExtractNarrowingLower(value.L2);
		Vector64<uint> a3 = AdvSimd.ExtractNarrowingLower(value.L3);
		Vector64<uint> a4 = AdvSimd.ExtractNarrowingLower(value.L4);
		Vector64<uint> a5 = AdvSimd.ExtractNarrowingLower(value.L5);
		Vector64<uint> a6 = AdvSimd.ExtractNarrowingLower(value.L6);
		Vector64<uint> a7 = AdvSimd.ExtractNarrowingLower(value.L7);
		Vector64<uint> a8 = AdvSimd.ExtractNarrowingLower(value.L8);

		Vector128<ulong> z0 = AdvSimd.MultiplyWideningLower(a0, a0);
		Vector128<ulong> q0 = z0 & mask;

		Vector64<uint> twice = AdvSimd.Add(a1, a1);
		Vector128<ulong> z1 = AdvSimd.MultiplyWideningLower(a0, twice);
		Vector128<ulong> z2 = AdvSimd.MultiplyWideningLower(a1, a1);
		z1 = CarryInto<TCarry>(z1, z0);
		Vector128<ulong> q1 = z1 & mask;

		twice = AdvSimd.Add(a2, a2);
		z2 = AdvSimd.MultiplyWideningLowerAndAdd(z2, a0, twice);
		Vector128<ulong> z3 = AdvSimd.MultiplyWideningLowerAndAdd(Vector128.Create(SM2Field29.Bias3), a1, twice);
		Vector128<ulong> z4 = AdvSimd.MultiplyWideningLowerAndAdd(Vector128.Create(SM2Field29.BiasMiddle), a2, a2);
		z2 += q0 << 6;
		z2 = CarryInto<TCarry>(z2, z1);
		Vector128<ulong> q2 = z2 & mask;

		twice = AdvSimd.Add(a3, a3);
		z3 = AdvSimd.MultiplyWideningLowerAndAdd(z3, a0, twice);
		z4 = AdvSimd.MultiplyWideningLowerAndAdd(z4, a1, twice);
		Vector128<ulong> z5 = AdvSimd.MultiplyWideningLowerAndAdd(Vector128.Create(SM2Field29.BiasMiddle), a2, twice);
		Vector128<ulong> z6 = AdvSimd.MultiplyWideningLowerAndAdd(Vector128.Create(SM2Field29.BiasMiddle), a3, a3);
		z3 += q1 << 6;
		z3 -= q0 << 9;
		z3 = CarryInto<TCarry>(z3, z2);
		Vector128<ulong> q3 = z3 & mask;

		twice = AdvSimd.Add(a4, a4);
		z4 = AdvSimd.MultiplyWideningLowerAndAdd(z4, a0, twice);
		z5 = AdvSimd.MultiplyWideningLowerAndAdd(z5, a1, twice);
		z6 = AdvSimd.MultiplyWideningLowerAndAdd(z6, a2, twice);
		Vector128<ulong> z7 = AdvSimd.MultiplyWideningLowerAndAdd(Vector128.Create(SM2Field29.Bias7), a3, twice);
		Vector128<ulong> z8 = AdvSimd.MultiplyWideningLowerAndAdd(Vector128.Create(SM2Field29.BiasMiddle), a4, a4);
		z4 += q2 << 6;
		z4 -= q1 << 9;
		z4 = CarryInto<TCarry>(z4, z3);
		Vector128<ulong> q4 = z4 & mask;

		twice = AdvSimd.Add(a5, a5);
		z5 = AdvSimd.MultiplyWideningLowerAndAdd(z5, a0, twice);
		z6 = AdvSimd.MultiplyWideningLowerAndAdd(z6, a1, twice);
		z7 = AdvSimd.MultiplyWideningLowerAndAdd(z7, a2, twice);
		z8 = AdvSimd.MultiplyWideningLowerAndAdd(z8, a3, twice);
		Vector128<ulong> z9 = AdvSimd.MultiplyWideningLowerAndAdd(Vector128.Create(SM2Field29.BiasMiddle), a4, twice);
		Vector128<ulong> z10 = AdvSimd.MultiplyWideningLowerAndAdd(Vector128.Create(SM2Field29.Bias10), a5, a5);
		z5 += q3 << 6;
		z5 -= q2 << 9;
		z5 = CarryInto<TCarry>(z5, z4);
		Vector128<ulong> q5 = z5 & mask;

		twice = AdvSimd.Add(a6, a6);
		z6 = AdvSimd.MultiplyWideningLowerAndAdd(z6, a0, twice);
		z7 = AdvSimd.MultiplyWideningLowerAndAdd(z7, a1, twice);
		z8 = AdvSimd.MultiplyWideningLowerAndAdd(z8, a2, twice);
		z9 = AdvSimd.MultiplyWideningLowerAndAdd(z9, a3, twice);
		z10 = AdvSimd.MultiplyWideningLowerAndAdd(z10, a4, twice);
		Vector128<ulong> z11 = AdvSimd.MultiplyWideningLowerAndAdd(Vector128.Create(SM2Field29.Bias11), a5, twice);
		Vector128<ulong> z12 = AdvSimd.MultiplyWideningLowerAndAdd(Vector128.Create(SM2Field29.BiasMiddle), a6, a6);
		z6 += q4 << 6;
		z6 -= q3 << 9;
		z6 = CarryInto<TCarry>(z6, z5);
		Vector128<ulong> q6 = z6 & mask;

		twice = AdvSimd.Add(a7, a7);
		z7 = AdvSimd.MultiplyWideningLowerAndAdd(z7, a0, twice);
		z8 = AdvSimd.MultiplyWideningLowerAndAdd(z8, a1, twice);
		z9 = AdvSimd.MultiplyWideningLowerAndAdd(z9, a2, twice);
		z10 = AdvSimd.MultiplyWideningLowerAndAdd(z10, a3, twice);
		z11 = AdvSimd.MultiplyWideningLowerAndAdd(z11, a4, twice);
		z12 = AdvSimd.MultiplyWideningLowerAndAdd(z12, a5, twice);
		Vector128<ulong> z13 = AdvSimd.MultiplyWideningLowerAndAdd(Vector128.Create(SM2Field29.BiasMiddle), a6, twice);
		Vector128<ulong> z14 = AdvSimd.MultiplyWideningLowerAndAdd(Vector128.Create(SM2Field29.BiasMiddle), a7, a7);
		z7 += q5 << 6;
		z7 -= q4 << 9;
		z7 -= q0 << 21;
		z7 = CarryInto<TCarry>(z7, z6);
		Vector128<ulong> q7 = z7 & mask;

		twice = AdvSimd.Add(a8, a8);
		z8 = AdvSimd.MultiplyWideningLowerAndAdd(z8, a0, twice);
		z9 = AdvSimd.MultiplyWideningLowerAndAdd(z9, a1, twice);
		z10 = AdvSimd.MultiplyWideningLowerAndAdd(z10, a2, twice);
		z11 = AdvSimd.MultiplyWideningLowerAndAdd(z11, a3, twice);
		z12 = AdvSimd.MultiplyWideningLowerAndAdd(z12, a4, twice);
		z13 = AdvSimd.MultiplyWideningLowerAndAdd(z13, a5, twice);
		z14 = AdvSimd.MultiplyWideningLowerAndAdd(z14, a6, twice);
		Vector128<ulong> z15 = AdvSimd.MultiplyWideningLowerAndAdd(Vector128.Create(SM2Field29.Bias15), a7, twice);
		Vector128<ulong> z16 = AdvSimd.MultiplyWideningLower(a8, a8);
		z8 += q6 << 6;
		z8 -= q5 << 9;
		z8 -= q1 << 21;
		z8 += q0 << 24;
		z8 = CarryInto<TCarry>(z8, z7);
		Vector128<ulong> q8 = z8 & mask;

		z9 += q7 << 6;
		z9 -= q6 << 9;
		z9 -= q2 << 21;
		z9 += q1 << 24;
		z9 = CarryInto<TCarry>(z9, z8);
		z10 += q8 << 6;
		z10 -= q7 << 9;
		z10 -= q3 << 21;
		z10 += q2 << 24;
		z11 -= q8 << 9;
		z11 -= q4 << 21;
		z11 += q3 << 24;
		z12 -= q5 << 21;
		z12 += q4 << 24;
		z13 -= q6 << 21;
		z13 += q5 << 24;
		z14 -= q7 << 21;
		z14 += q6 << 24;
		z15 -= q8 << 21;
		z15 += q7 << 24;
		z16 += q8 << 24;

		if (TCarry.Ripples)
		{
			z10 = CarryInto<TCarry>(z10, z9);
			result.L0 = z9 & mask;
			z11 = CarryInto<TCarry>(z11, z10);
			result.L1 = z10 & mask;
			z12 = CarryInto<TCarry>(z12, z11);
			result.L2 = z11 & mask;
			z13 = CarryInto<TCarry>(z13, z12);
			result.L3 = z12 & mask;
			z14 = CarryInto<TCarry>(z14, z13);
			result.L4 = z13 & mask;
			z15 = CarryInto<TCarry>(z15, z14);
			result.L5 = z14 & mask;
			z16 = CarryInto<TCarry>(z16, z15);
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
	public static void Add(in SM2Field29x2AdvSimd left, in SM2Field29x2AdvSimd right, out SM2Field29x2AdvSimd result)
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
	public static void Subtract(in SM2Field29x2AdvSimd left, in SM2Field29x2AdvSimd right, out SM2Field29x2AdvSimd result)
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

	// The carries ripple from limb 0 up, the order in which a product reads the limbs it takes, so they take the USRA.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Reduce(in SM2Field29x2AdvSimd value, out SM2Field29x2AdvSimd result)
	{
		Vector128<ulong> mask = Vector128.Create(SM2Field29.Mask);
		Vector128<ulong> h = value.L8 >> 24;
		Vector128<ulong> t0 = value.L0 + h;
		Vector128<ulong> t1 = CarryInto(value.L1, t0);
		Vector128<ulong> t2 = CarryInto(value.L2 + (h << 38) - (h << 6), t1);
		Vector128<ulong> t3 = CarryInto(value.L3, t2);
		Vector128<ulong> t4 = CarryInto(value.L4, t3);
		Vector128<ulong> t5 = CarryInto(value.L5, t4);
		Vector128<ulong> t6 = CarryInto(value.L6, t5);
		Vector128<ulong> t7 = CarryInto(value.L7 + (h << 21), t6);
		result.L8 = CarryInto(value.L8 & Vector128.Create(SM2Field29.TopMask), t7);
		result.L0 = t0 & mask;
		result.L1 = t1 & mask;
		result.L2 = t2 & mask;
		result.L3 = t3 & mask;
		result.L4 = t4 & mask;
		result.L5 = t5 & mask;
		result.L6 = t6 & mask;
		result.L7 = t7 & mask;
	}

	// limb + (from >> Bits) in one USRA, which saves an instruction over a shift and an add but takes longer through its shifted operand.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ulong> CarryInto(Vector128<ulong> limb, Vector128<ulong> from)
	{
		return AdvSimd.ShiftRightLogicalAdd(limb, from, SM2Field29.Bits);
	}

	// As CarryInto in a product that ripples, among products that need not wait for each other; a product that carries in two steps, which the next step waits for, keeps the shift and the add.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ulong> CarryInto<TCarry>(Vector128<ulong> limb, Vector128<ulong> from) where TCarry : struct, ISM2Carry
	{
		return TCarry.Ripples ? AdvSimd.ShiftRightLogicalAdd(limb, from, SM2Field29.Bits) : limb + (from >> SM2Field29.Bits);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ConditionalSelect(ref readonly ulong mask, in SM2Field29x2AdvSimd whenSet, in SM2Field29x2AdvSimd whenClear, out SM2Field29x2AdvSimd result)
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
	public static void ConditionalNegate(ref readonly ulong mask, ref SM2Field29x2AdvSimd value)
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
	public static void Halve(in SM2Field29x2AdvSimd value, out SM2Field29x2AdvSimd result)
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
	public static void MoveDown(in SM2Field29x2AdvSimd value, int distance, out SM2Field29x2AdvSimd result)
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
	public static void LoadEntries(ref readonly ulong entries, out SM2Field29x2AdvSimd x, out SM2Field29x2AdvSimd y)
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
		FromSaturated(AdvSimd.Arm64.ZipLow(first0, second0), AdvSimd.Arm64.ZipHigh(first0, second0), AdvSimd.Arm64.ZipLow(first2, second2), AdvSimd.Arm64.ZipHigh(first2, second2), out x);
		FromSaturated(AdvSimd.Arm64.ZipLow(first4, second4), AdvSimd.Arm64.ZipHigh(first4, second4), AdvSimd.Arm64.ZipLow(first6, second6), AdvSimd.Arm64.ZipHigh(first6, second6), out y);
	}

	// 2v for the value v below 2^256 of four 64-bit limbs w0 to w3, lane by lane, in limbs below 2^29, limb 8 below 2^25: limb i takes bits 29i − 1 to 29i + 27 of v.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FromSaturated(Vector128<ulong> w0, Vector128<ulong> w1, Vector128<ulong> w2, Vector128<ulong> w3, out SM2Field29x2AdvSimd result)
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
}
