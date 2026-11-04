namespace CryptoBase.EllipticCurves.Curve448;

// The multiplications of Curve448Vector and Edwards448Vector on Field448x4Avx512.
internal readonly struct Curve448Avx512 : ICurve448Kernel
{
	public static bool IsSupported => Field448x4Avx512.IsSupported;

	// As Curve448Avx2.Ladder.
	public static void Ladder(ReadOnlySpan<byte> scalar, in Field448 u, out Field448 x, out Field448 z)
	{
		Curve448Vector<Field448x4Avx512>.Ladder(scalar, in u, out x, out z);
	}

	public static void MultiplyBase(ReadOnlySpan<byte> scalar, out EdwardsPoint result)
	{
		Edwards448Vector<Field448x4Avx512>.MultiplyBase(scalar, out result);
	}

	public static void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, in EdwardsPoint point, ReadOnlySpan<byte> b, out EdwardsPoint result)
	{
		Edwards448Vector<Field448x4Avx512>.DoubleScalarMultiplyVariableTime(a, in point, b, out result);
	}

	public static void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, ReadOnlySpan<EdwardsAffinePoint> pointTable, ReadOnlySpan<byte> b, out EdwardsPoint result)
	{
		Edwards448Vector<Field448x4Avx512>.DoubleScalarMultiplyVariableTime(a, pointTable, b, out result);
	}
}
