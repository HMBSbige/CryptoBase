namespace CryptoBase.EllipticCurves.SM9;

// The Miller loop on two points, the powers of GT with a fixed table and the builds of those tables on SM9Lanes over SM9VectorAdvSimd and the products of G1 from fixed-base tables on SM9PointLanes; the rest, which SM9KernelDispatch does not take here, forwards to SM9Scalar.
internal readonly struct SM9AdvSimd : ISM9Kernel
{
	public static bool IsSupported => SM9VectorAdvSimd.IsSupported;

	public static void MillerLoop(in SM9AffinePoint<SM9Fp> p, in SM9AffinePoint<SM9Fp2> q, out SM9Fp12 result)
	{
		SM9LaneKernel<SM9VectorAdvSimd>.MillerLoop(in p, in q, out result);
	}

	public static void MillerLoop(in SM9Fp alpha, in SM9Fp beta, ReadOnlySpan<SM9PrecomputedLine> lines, out SM9Fp12 result)
	{
		SM9Scalar.MillerLoop(in alpha, in beta, lines, out result);
	}

	public static void MillerLoop(in SM9Fp alpha, in SM9Fp beta, ReadOnlySpan<SM9PrecomputedLine> lines, in SM9Fp otherAlpha, in SM9Fp otherBeta, ReadOnlySpan<SM9PrecomputedLine> otherLines, out SM9Fp12 result)
	{
		SM9Scalar.MillerLoop(in alpha, in beta, lines, in otherAlpha, in otherBeta, otherLines, out result);
	}

	public static void FinalExponentiation(in SM9Fp12 value, out SM9Fp12 result)
	{
		SM9Scalar.FinalExponentiation(in value, out result);
	}

	public static void Power(in SM9Fp12 value, in FieldElement<SM9Order> exponent, out SM9Fp12 result)
	{
		SM9Scalar.Power(in value, in exponent, out result);
	}

	public static void BuildPowerTable(in SM9Fp12 value, Span<SM9Fp12> table, out SM9Fp12 inverse)
	{
		SM9LaneKernel<SM9VectorAdvSimd>.BuildFixedTable(in value, table, out inverse);
	}

	public static void Power(ReadOnlySpan<SM9Fp12> table, in SM9Fp12 inverse, in FieldElement<SM9Order> exponent, out SM9Fp12 result)
	{
		SM9LaneKernel<SM9VectorAdvSimd>.Power(table, in inverse, in exponent, out result);
	}

	public static void BuildBaseTable(in SM9AffinePoint<SM9Fp> generator, int width, bool secret, Span<SM9AffinePoint<SM9Fp>> entries)
	{
		SM9Scalar.BuildBaseTable(in generator, width, secret, entries);
	}

	public static void BuildBaseTable(in SM9AffinePoint<SM9Fp2> generator, int width, bool secret, Span<SM9AffinePoint<SM9Fp2>> entries)
	{
		SM9Scalar.BuildBaseTable(in generator, width, secret, entries);
	}

	public static void ToAffine(ReadOnlySpan<SM9Point<SM9Fp2>> points, Span<SM9AffinePoint<SM9Fp2>> result, bool variableTime)
	{
		SM9Scalar.ToAffine(points, result, variableTime);
	}

	public static void MultiplyBaseG1(SM9BaseTable<SM9Fp> table, in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp> result)
	{
		SM9PointLanes<SM9VectorAdvSimd, SM9Lanes<SM9VectorAdvSimd>.FpLanes, SM9Fp>.MultiplyBase(table, in scalar, out result);
	}

	public static void MultiplyBaseSumG1(SM9BaseTable<SM9Fp> first, in FieldElement<SM9Order> firstScalar, SM9BaseTable<SM9Fp> second, in FieldElement<SM9Order> secondScalar, out SM9Point<SM9Fp> result)
	{
		SM9PointLanes<SM9VectorAdvSimd, SM9Lanes<SM9VectorAdvSimd>.FpLanes, SM9Fp>.MultiplyBase(first, in firstScalar, second, in secondScalar, out result);
	}

	public static void MultiplyG1(in SM9AffinePoint<SM9Fp> point, in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp> result)
	{
		SM9Scalar.MultiplyG1(in point, in scalar, out result);
	}

	public static void MultiplyVariableTimeG1(in SM9AffinePoint<SM9Fp> point, in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp> result)
	{
		SM9Scalar.MultiplyVariableTimeG1(in point, in scalar, out result);
	}

	public static void MultiplyBaseAddVariableTimeG1(in FieldElement<SM9Order> scalar, in SM9Point<SM9Fp> addend, out SM9Point<SM9Fp> result)
	{
		SM9PointLanes<SM9VectorAdvSimd, SM9Lanes<SM9VectorAdvSimd>.FpLanes, SM9Fp>.MultiplyBaseAddVariableTime(SM9G1Group.BaseTable, in scalar, in addend, out result);
	}

	public static void MultiplyBaseG2(in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp2> result)
	{
		SM9Scalar.MultiplyBaseG2(in scalar, out result);
	}

	public static void MultiplyBaseAddVariableTimeG2(in FieldElement<SM9Order> scalar, in SM9Point<SM9Fp2> addend, out SM9Point<SM9Fp2> result)
	{
		SM9Scalar.MultiplyBaseAddVariableTimeG2(in scalar, in addend, out result);
	}

	public static void MultiplyByLoopScalarG2(in SM9Point<SM9Fp2> point, out SM9Point<SM9Fp2> result)
	{
		SM9Scalar.MultiplyByLoopScalarG2(in point, out result);
	}
}
