namespace CryptoBase.EllipticCurves.Curve25519;

// The multiplications of Curve25519Vector on Field25519x4Avx2.
internal readonly struct Curve25519Avx2 : ICurve25519Kernel
{
	public static bool IsSupported => Field25519x4Avx2.IsSupported;

	public static void Ladder(ReadOnlySpan<byte> scalar, in Field25519 u, out Field25519 x, out Field25519 z)
	{
		Curve25519Vector<Field25519x4Avx2>.Ladder(scalar, in u, out x, out z);
	}

	public static void MultiplyBase(ReadOnlySpan<byte> scalar, out EdwardsPoint result)
	{
		Curve25519Vector<Field25519x4Avx2>.MultiplyBase(scalar, out result);
	}

	public static void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, in EdwardsPoint point, ReadOnlySpan<byte> b, out EdwardsPoint result)
	{
		Curve25519Vector<Field25519x4Avx2>.DoubleScalarMultiplyVariableTime(a, in point, b, out result);
	}

	public static void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, ReadOnlySpan<EdwardsNielsPoint> pointTable, ReadOnlySpan<byte> b, out EdwardsPoint result)
	{
		Curve25519Vector<Field25519x4Avx2>.DoubleScalarMultiplyVariableTime(a, pointTable, b, out result);
	}
}
