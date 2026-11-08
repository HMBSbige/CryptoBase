namespace CryptoBase.EllipticCurves.SM9;

// The kernel of SM9Fp alone, for every platform.
internal readonly struct SM9Scalar : ISM9Kernel
{
	public static bool IsSupported => true;

	public static void MillerLoop(in SM9AffinePoint<SM9Fp> p, in SM9AffinePoint<SM9Fp2> q, out SM9Fp12 result)
	{
		SM9MillerLoop.Run(in p, in q, out result);
	}

	public static void MillerLoop(in SM9Fp alpha, in SM9Fp beta, ReadOnlySpan<SM9PrecomputedLine> lines, out SM9Fp12 result)
	{
		SM9MillerLoop.Run(in alpha, in beta, lines, out result);
	}

	public static void MillerLoop(in SM9Fp alpha, in SM9Fp beta, ReadOnlySpan<SM9PrecomputedLine> lines, in SM9Fp otherAlpha, in SM9Fp otherBeta, ReadOnlySpan<SM9PrecomputedLine> otherLines, out SM9Fp12 result)
	{
		SM9MillerLoop.Run(in alpha, in beta, lines, in otherAlpha, in otherBeta, otherLines, out result);
	}

	public static void FinalExponentiation(in SM9Fp12 value, out SM9Fp12 result)
	{
		SM9FinalExponentiation.Run(in value, out result);
	}

	public static void Power(in SM9Fp12 value, in FieldElement<SM9Order> exponent, out SM9Fp12 result)
	{
		SM9GTPower.Power(in value, in exponent, out result);
	}

	public static void BuildPowerTable(in SM9Fp12 value, Span<SM9Fp12> table, out SM9Fp12 inverse)
	{
		SM9GTPower.BuildFixedTable(in value, table, out inverse);
	}

	public static void Power(ReadOnlySpan<SM9Fp12> table, in SM9Fp12 inverse, in FieldElement<SM9Order> exponent, out SM9Fp12 result)
	{
		SM9GTPower.Power(table, in inverse, in exponent, out result);
	}

	public static void BuildBaseTable(in SM9AffinePoint<SM9Fp> generator, int width, bool secret, Span<SM9AffinePoint<SM9Fp>> entries)
	{
		SM9BaseTable<SM9Fp>.BuildEntries(in generator, width, secret, entries);
	}

	public static void BuildBaseTable(in SM9AffinePoint<SM9Fp2> generator, int width, bool secret, Span<SM9AffinePoint<SM9Fp2>> entries)
	{
		SM9BaseTable<SM9Fp2>.BuildEntries(in generator, width, secret, entries);
	}

	public static void ToAffine(ReadOnlySpan<SM9Point<SM9Fp2>> points, Span<SM9AffinePoint<SM9Fp2>> result, bool variableTime)
	{
		SM9Curve<SM9Fp2>.ToAffine(points, result, variableTime);
	}

	public static void MultiplyBaseG1(SM9BaseTable<SM9Fp> table, in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp> result)
	{
		table.Multiply(in scalar, out result);
	}

	[SkipLocalsInit]
	public static void MultiplyBaseSumG1(SM9BaseTable<SM9Fp> first, in FieldElement<SM9Order> firstScalar, SM9BaseTable<SM9Fp> second, in FieldElement<SM9Order> secondScalar, out SM9Point<SM9Fp> result)
	{
		first.Multiply(in firstScalar, out result);
		second.Multiply(in secondScalar, out SM9Point<SM9Fp> other);
		SM9Curve<SM9Fp>.Add(in result, in other, out result);
		other.ZeroMemory();
	}

	public static void MultiplyG1(in SM9AffinePoint<SM9Fp> point, in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp> result)
	{
		SM9G1Group.Multiply(in point, in scalar, out result);
	}

	public static void MultiplyVariableTimeG1(in SM9AffinePoint<SM9Fp> point, in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp> result)
	{
		SM9G1Group.MultiplyVariableTime(in point, in scalar, out result);
	}

	public static void MultiplyBaseAddVariableTimeG1(in FieldElement<SM9Order> scalar, in SM9Point<SM9Fp> addend, out SM9Point<SM9Fp> result)
	{
		SM9G1Group.MultiplyBaseAddVariableTime(in scalar, in addend, out result);
	}

	public static void MultiplyBaseG2(in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp2> result)
	{
		SM9G2Group.MultiplyBase(in scalar, out result);
	}

	public static void MultiplyByLoopScalarG2(in SM9Point<SM9Fp2> point, out SM9Point<SM9Fp2> result)
	{
		SM9Curve<SM9Fp2>.MultiplyVariableTime(in point, SM9G2Group.LoopScalar, out result);
	}

	public static void MultiplyBaseAddVariableTimeG2(in FieldElement<SM9Order> scalar, in SM9Point<SM9Fp2> addend, out SM9Point<SM9Fp2> result)
	{
		SM9G2Group.MultiplyBaseAddVariableTime(in scalar, in addend, out result);
	}
}
