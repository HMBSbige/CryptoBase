namespace CryptoBase.EllipticCurves;

// The products of SM2Vector on SM2Field29x4Avx2, and those of one point at a time on the four lanes of SM2QuadFormulas: u1·G + u2·Q without a table sums u1·G from the windows of G and u2·Q from the NAF of u2.
internal readonly struct SM2Avx2 : ISM2Kernel
{
	public static bool IsSupported => SM2Field29x4Avx2.IsSupported;

	public static void MultiplyBase(in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> result)
	{
		SM2Vector<SM2Field29x4Avx2>.MultiplyBase(in scalar, out result);
	}

	public static void FillBases<TCurve>(in AffinePoint<SM2Field52> point, Span<JacobianPoint<SM2Field52>> bases) where TCurve : struct, IECCurve
	{
		SM2QuadFormulas.FillBases(in point, TCurve.GeneratorWindowWidth, bases);
	}

	public static void FillWindows<TCurve>(Span<ulong> windows) where TCurve : struct, IECCurve
	{
		SM2Vector<SM2Field29x4Avx2>.FillWindows<TCurve>(windows);
	}

	public static void MultiplyFixed(ReadOnlySpan<ulong> windows, in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> result)
	{
		SM2Vector<SM2Field29x4Avx2>.MultiplyFixed(windows, in scalar, out result);
	}

	public static void MultiplyAddFixed(ReadOnlySpan<ulong> windows, in FieldElement<SM2Order> u1, in FieldElement<SM2Order> u2, out JacobianPoint<SM2Field52> result)
	{
		SM2Vector<SM2Field29x4Avx2>.MultiplyAddFixed(windows, in u1, in u2, out result);
	}

	public static void MultiplyBaseAndFixed(ReadOnlySpan<ulong> windows, in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> baseResult, out JacobianPoint<SM2Field52> result)
	{
		SM2Vector<SM2Field29x4Avx2>.MultiplyBaseAndFixed(windows, in scalar, out baseResult, out result);
	}

	public static void MultiplyAdd(in FieldElement<SM2Order> u1, ReadOnlySpan<AffinePoint<SM2Field52>> pointTable, in FieldElement<SM2Order> u2, out JacobianPoint<SM2Field52> result)
	{
		SM2Vector<SM2Field29x4Avx2>.MultiplyAdd(in u1, pointTable, in u2, out result);
	}

	public static void Multiply(in AffinePoint<SM2Field52> point, in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> result)
	{
		SM2QuadFormulas.Multiply(in point, in scalar, out result);
	}

	public static void MultiplyAdd(in FieldElement<SM2Order> u1, in AffinePoint<SM2Field52> point, in FieldElement<SM2Order> u2, out JacobianPoint<SM2Field52> result)
	{
		SM2QuadFormulas.MultiplyVariableTime(in point, in u2, out result);

		// x̄·R of the key exchange takes u1 = 0.
		if (FieldElement<SM2Order>.IsZero(in u1) is not 0)
		{
			return;
		}

		SM2Vector<SM2Field29x4Avx2>.MultiplyBaseVariableTime(in u1, out JacobianPoint<SM2Field52> product);
		ECVariableTimeGroup<SM2Curve, SM2Field52, SM2Order>.Add(ref result, in product);
	}
}
