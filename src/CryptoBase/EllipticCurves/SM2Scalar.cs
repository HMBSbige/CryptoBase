namespace CryptoBase.EllipticCurves;

// The windows of ECGroup and ECVariableTimeGroup on SM2Field52, for every platform: the reference of the other kernels.
internal readonly struct SM2Scalar : ISM2Kernel
{
	public static bool IsSupported => true;

	public static void MultiplyBase(in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> result)
	{
		ECGroup<SM2Curve, SM2Field52, SM2Order>.MultiplyBaseWindows(in scalar, out result);
	}

	public static void FillBases<TCurve>(in AffinePoint<SM2Field52> point, Span<JacobianPoint<SM2Field52>> bases) where TCurve : struct, IECCurve
	{
		ECGeneratorTable<TCurve, SM2Field52, SM2Order>.FillBases(in point, bases);
	}

	public static void FillWindows<TCurve>(Span<ulong> windows) where TCurve : struct, IECCurve
	{
		ECGeneratorTable<TCurve, SM2Field52, SM2Order>.FillWindows(windows);
	}

	public static void MultiplyFixed(ReadOnlySpan<ulong> windows, in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> result)
	{
		ECGroup<SM2Curve, SM2Field52, SM2Order>.MultiplyFixedWindows(windows, in scalar, out result);
	}

	public static void MultiplyAddFixed(ReadOnlySpan<ulong> windows, in FieldElement<SM2Order> u1, in FieldElement<SM2Order> u2, out JacobianPoint<SM2Field52> result)
	{
		ECVariableTimeGroup<SM2VerificationCurve, SM2Field52, SM2Order>.MultiplyAddFixedWindows(windows, in u1, in u2, out result);
	}

	public static void MultiplyBaseAndFixed(ReadOnlySpan<ulong> windows, in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> baseResult, out JacobianPoint<SM2Field52> result)
	{
		ECGroup<SM2Curve, SM2Field52, SM2Order>.MultiplyBaseWindows(in scalar, out baseResult);
		ECGroup<SM2Curve, SM2Field52, SM2Order>.MultiplyFixedWindows(windows, in scalar, out result);
	}

	public static void MultiplyAdd(in FieldElement<SM2Order> u1, ReadOnlySpan<AffinePoint<SM2Field52>> pointTable, in FieldElement<SM2Order> u2, out JacobianPoint<SM2Field52> result)
	{
		ECVariableTimeGroup<SM2Curve, SM2Field52, SM2Order>.MultiplyAddWindows(in u1, pointTable, in u2, out result);
	}

	public static void Multiply(in AffinePoint<SM2Field52> point, in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> result)
	{
		ECGroup<SM2Curve, SM2Field52, SM2Order>.MultiplyWindows(in point, in scalar, out result);
	}

	public static void MultiplyAdd(in FieldElement<SM2Order> u1, in AffinePoint<SM2Field52> point, in FieldElement<SM2Order> u2, out JacobianPoint<SM2Field52> result)
	{
		ECVariableTimeGroup<SM2Curve, SM2Field52, SM2Order>.MultiplyAddWindows(in u1, in point, in u2, out result);
	}
}
