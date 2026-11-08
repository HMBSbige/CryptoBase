namespace CryptoBase.EllipticCurves;

// The products of SM2Vector and SM2PairFormulas on SM2Field29x2AdvSimd.
internal readonly struct SM2AdvSimd : ISM2Kernel
{
	public static bool IsSupported => SM2Field29x2AdvSimd.IsSupported;

	public static void MultiplyBase(in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> result)
	{
		SM2Vector<SM2Field29x2AdvSimd>.MultiplyBase(in scalar, out result);
	}

	public static void FillBases<TCurve>(in AffinePoint<SM2Field52> point, Span<JacobianPoint<SM2Field52>> bases) where TCurve : struct, IECCurve
	{
		SM2PairFormulas<SM2Field29x2AdvSimd>.FillBases(in point, TCurve.GeneratorWindowWidth, bases);
	}

	public static void FillWindows<TCurve>(Span<ulong> windows) where TCurve : struct, IECCurve
	{
		SM2Vector<SM2Field29x2AdvSimd>.FillWindows<TCurve>(windows);
	}

	public static void MultiplyFixed(ReadOnlySpan<ulong> windows, in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> result)
	{
		SM2Vector<SM2Field29x2AdvSimd>.MultiplyFixed(windows, in scalar, out result);
	}

	public static void MultiplyAddFixed(ReadOnlySpan<ulong> windows, in FieldElement<SM2Order> u1, in FieldElement<SM2Order> u2, out JacobianPoint<SM2Field52> result)
	{
		SM2Vector<SM2Field29x2AdvSimd>.MultiplyAddFixed(windows, in u1, in u2, out result);
	}

	public static void MultiplyBaseAndFixed(ReadOnlySpan<ulong> windows, in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> baseResult, out JacobianPoint<SM2Field52> result)
	{
		SM2Vector<SM2Field29x2AdvSimd>.MultiplyBaseAndFixed(windows, in scalar, out baseResult, out result);
	}

	public static void MultiplyAdd(in FieldElement<SM2Order> u1, ReadOnlySpan<AffinePoint<SM2Field52>> pointTable, in FieldElement<SM2Order> u2, out JacobianPoint<SM2Field52> result)
	{
		SM2Vector<SM2Field29x2AdvSimd>.MultiplyAdd(in u1, pointTable, in u2, out result);
	}

	public static void Multiply(in AffinePoint<SM2Field52> point, in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> result)
	{
		SM2PairFormulas<SM2Field29x2AdvSimd>.Multiply(in point, in scalar, out result);
	}

	public static void MultiplyAdd(in FieldElement<SM2Order> u1, in AffinePoint<SM2Field52> point, in FieldElement<SM2Order> u2, out JacobianPoint<SM2Field52> result)
	{
		SM2PairFormulas<SM2Field29x2AdvSimd>.MultiplyAdd(in u1, in point, in u2, out result);
	}
}
