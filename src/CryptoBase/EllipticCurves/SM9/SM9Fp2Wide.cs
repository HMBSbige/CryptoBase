namespace CryptoBase.EllipticCurves.SM9;

// An element W0 + W1·u of Fp2 as two sums of products before reduction, for the lazy reductions of the tower: the coefficients are signed integers, SM9Fp2.MultiplyWide and SquareWide give the products of their inputs as integer polynomials, a0b0 − 2a1b1 and a0b1 + a1b0, and the sums, differences and multiples by u combine them exactly, so that a combination is reduced once per coefficient by SM9Fp.ReduceWide. The callers state the bounds of the values against the (−128p², 342p²) that it takes, in multiples of B = (2.25p)², the largest product of two reduced elements: a product of elements below x and y has a0b0 − 2a1b1 in (−2xy, xy) and a0b1 + a1b0 in [0, 2xy). They also keep the columns below 2^61.9 in magnitude.
internal struct SM9Fp2Wide
{
	internal SM9FpWide W0;
	internal SM9FpWide W1;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Add(in SM9Fp2Wide left, in SM9Fp2Wide right, out SM9Fp2Wide result)
	{
		SM9FpWide.Add(in left.W0, in right.W0, out result.W0);
		SM9FpWide.Add(in left.W1, in right.W1, out result.W1);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Subtract(in SM9Fp2Wide left, in SM9Fp2Wide right, out SM9Fp2Wide result)
	{
		SM9FpWide.Subtract(in left.W0, in right.W0, out result.W0);
		SM9FpWide.Subtract(in left.W1, in right.W1, out result.W1);
	}

	// left + u·right = (left0 − 2·right1) + (left1 + right0)·u.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void AddTimesU(in SM9Fp2Wide left, in SM9Fp2Wide right, out SM9Fp2Wide result)
	{
		SM9FpWide w1 = right.W1;
		SM9FpWide.Add(in left.W1, in right.W0, out result.W1);
		SM9FpWide.SubtractTwiceUnbalanced(in left.W0, in w1, out result.W0);
	}

	// value + x·R for a reduced x, which the reduction adds to the result as it is: each coefficient below 2.25p adds below 50.6p².
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void AddShifted(ref SM9Fp2Wide value, in SM9Fp2 x)
	{
		SM9FpWide.AddShifted(ref value.W0, in x.A0);
		SM9FpWide.AddShifted(ref value.W1, in x.A1);
	}

	// value + u·x·R for a reduced x, with u·x = −2x1 + x0·u as 2(3p − x1) + x0·u: the first coefficient adds below 134.8p² and the second below 50.6p², in limbs below 2^54.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void AddShiftedTimesU(ref SM9Fp2Wide value, in SM9Fp2 x)
	{
		SM9Fp zero = default;
		SM9Fp.SubtractUnreduced(in zero, in x.A1, out SM9Fp negated);
		SM9Fp.AddUnreduced(in negated, in negated, out negated);
		SM9FpWide.AddShifted(ref value.W0, in negated);
		SM9FpWide.AddShifted(ref value.W1, in x.A0);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void MultiplySmall(in SM9Fp2Wide value, ulong k, out SM9Fp2Wide result)
	{
		SM9FpWide.MultiplySmall(in value.W0, k, out result.W0);
		SM9FpWide.MultiplySmall(in value.W1, k, out result.W1);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void SubtractMultiple(in SM9Fp2Wide left, in SM9Fp2Wide right, ulong k, out SM9Fp2Wide result)
	{
		SM9FpWide.SubtractMultiple(in left.W0, in right.W0, k, out result.W0);
		SM9FpWide.SubtractMultiple(in left.W1, in right.W1, k, out result.W1);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Normalize(ref SM9Fp2Wide value)
	{
		SM9FpWide.Normalize(ref value.W0);
		SM9FpWide.Normalize(ref value.W1);
	}

	// Reduces both coefficients, each in (−128p², 342p²).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Reduce(in SM9Fp2Wide value, out SM9Fp2 result)
	{
		Unsafe.SkipInit(out result);
		SM9Fp.ReduceWide(in value.W0, out result.A0);
		SM9Fp.ReduceWide(in value.W1, out result.A1);
	}
}
