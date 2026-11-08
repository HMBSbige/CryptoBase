namespace CryptoBase.EllipticCurves.SM9;

// The pairing and the powers of GT on SM9Lanes over SM9VectorSse41, the products of G1 and G2 from fixed-base tables on SM9PointLanes and that of G1 with a variable point on SM9PointKernel.
internal readonly struct SM9Sse41 : ISM9Kernel
{
	public static bool IsSupported => SM9VectorSse41.IsSupported;

	public static void MillerLoop(in SM9AffinePoint<SM9Fp> p, in SM9AffinePoint<SM9Fp2> q, out SM9Fp12 result)
	{
		SM9LaneKernel<SM9VectorSse41>.MillerLoop(in p, in q, out result);
	}

	public static void MillerLoop(in SM9Fp alpha, in SM9Fp beta, ReadOnlySpan<SM9PrecomputedLine> lines, out SM9Fp12 result)
	{
		SM9LaneKernel<SM9VectorSse41>.MillerLoop(in alpha, in beta, lines, out result);
	}

	public static void MillerLoop(in SM9Fp alpha, in SM9Fp beta, ReadOnlySpan<SM9PrecomputedLine> lines, in SM9Fp otherAlpha, in SM9Fp otherBeta, ReadOnlySpan<SM9PrecomputedLine> otherLines, out SM9Fp12 result)
	{
		SM9LaneKernel<SM9VectorSse41>.MillerLoop(in alpha, in beta, lines, in otherAlpha, in otherBeta, otherLines, out result);
	}

	public static void FinalExponentiation(in SM9Fp12 value, out SM9Fp12 result)
	{
		SM9LaneKernel<SM9VectorSse41>.FinalExponentiation(in value, out result);
	}

	public static void Power(in SM9Fp12 value, in FieldElement<SM9Order> exponent, out SM9Fp12 result)
	{
		SM9LaneKernel<SM9VectorSse41>.Power(in value, in exponent, out result);
	}

	public static void BuildPowerTable(in SM9Fp12 value, Span<SM9Fp12> table, out SM9Fp12 inverse)
	{
		SM9LaneKernel<SM9VectorSse41>.BuildFixedTable(in value, table, out inverse);
	}

	public static void Power(ReadOnlySpan<SM9Fp12> table, in SM9Fp12 inverse, in FieldElement<SM9Order> exponent, out SM9Fp12 result)
	{
		SM9LaneKernel<SM9VectorSse41>.Power(table, in inverse, in exponent, out result);
	}

	public static void BuildBaseTable(in SM9AffinePoint<SM9Fp> generator, int width, bool secret, Span<SM9AffinePoint<SM9Fp>> entries)
	{
		SM9PointLanes<SM9VectorSse41, SM9Lanes<SM9VectorSse41>.FpLanes, SM9Fp>.BuildTable(in generator, width, secret, entries);
	}

	public static void BuildBaseTable(in SM9AffinePoint<SM9Fp2> generator, int width, bool secret, Span<SM9AffinePoint<SM9Fp2>> entries)
	{
		SM9PointLanes<SM9VectorSse41, SM9Lanes<SM9VectorSse41>.Fp2Lanes, SM9Fp2>.BuildTable(in generator, width, secret, entries);
	}

	public static void ToAffine(ReadOnlySpan<SM9Point<SM9Fp2>> points, Span<SM9AffinePoint<SM9Fp2>> result, bool variableTime)
	{
		SM9PointLanes<SM9VectorSse41, SM9Lanes<SM9VectorSse41>.Fp2Lanes, SM9Fp2>.ToAffine(points, result, variableTime);
	}

	public static void MultiplyBaseG1(SM9BaseTable<SM9Fp> table, in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp> result)
	{
		SM9PointLanes<SM9VectorSse41, SM9Lanes<SM9VectorSse41>.FpLanes, SM9Fp>.MultiplyBase(table, in scalar, out result);
	}

	public static void MultiplyBaseSumG1(SM9BaseTable<SM9Fp> first, in FieldElement<SM9Order> firstScalar, SM9BaseTable<SM9Fp> second, in FieldElement<SM9Order> secondScalar, out SM9Point<SM9Fp> result)
	{
		SM9PointLanes<SM9VectorSse41, SM9Lanes<SM9VectorSse41>.FpLanes, SM9Fp>.MultiplyBase(first, in firstScalar, second, in secondScalar, out result);
	}

	public static void MultiplyG1(in SM9AffinePoint<SM9Fp> point, in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp> result)
	{
		SM9PointKernel<SM9VectorSse41>.MultiplyG1(in point, in scalar, out result);
	}

	public static void MultiplyVariableTimeG1(in SM9AffinePoint<SM9Fp> point, in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp> result)
	{
		SM9PointKernel<SM9VectorSse41>.MultiplyG1VariableTime(in point, in scalar, out result);
	}

	public static void MultiplyBaseAddVariableTimeG1(in FieldElement<SM9Order> scalar, in SM9Point<SM9Fp> addend, out SM9Point<SM9Fp> result)
	{
		SM9PointLanes<SM9VectorSse41, SM9Lanes<SM9VectorSse41>.FpLanes, SM9Fp>.MultiplyBaseAddVariableTime(SM9G1Group.BaseTable, in scalar, in addend, out result);
	}

	public static void MultiplyBaseG2(in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp2> result)
	{
		SM9PointLanes<SM9VectorSse41, SM9Lanes<SM9VectorSse41>.Fp2Lanes, SM9Fp2>.MultiplyBase(SM9G2Group.BaseTable, in scalar, out result);
	}

	public static void MultiplyBaseAddVariableTimeG2(in FieldElement<SM9Order> scalar, in SM9Point<SM9Fp2> addend, out SM9Point<SM9Fp2> result)
	{
		SM9PointLanes<SM9VectorSse41, SM9Lanes<SM9VectorSse41>.Fp2Lanes, SM9Fp2>.MultiplyBaseAddVariableTime(SM9G2Group.BaseTable, in scalar, in addend, out result);
	}

	public static void MultiplyByLoopScalarG2(in SM9Point<SM9Fp2> point, out SM9Point<SM9Fp2> result)
	{
		SM9PointKernel<SM9VectorSse41>.MultiplyByLoopScalarG2(in point, out result);
	}
}
