namespace CryptoBase.EllipticCurves.Curve448;

// The scalar multiplications of X448 and edwards448, which take and give Field448 and EdwardsPoint values whatever a kernel uses inside. Scalars are 56 little-endian bytes. Ladder and MultiplyBase take secrets: neither their time nor the addresses they read may depend on the scalar or the point, and they erase the buffers they own. DoubleScalarMultiplyVariableTime takes public inputs and may branch on them.
internal interface ICurve448Kernel
{
	static abstract bool IsSupported { get; }

	// Sets x and z to the projective u-coordinate (x : z) of [k]P, by the ladder of RFC 7748 §5, for the point P of Curve448 or of its twist with u-coordinate u, which must be tight. k is clamped as decodeScalar448 leaves it: bits 0 and 1 clear, bit 447 set. z = 0 is the point at infinity. x and z are tight.
	static abstract void Ladder(ReadOnlySpan<byte> scalar, in Field448 u, out Field448 x, out Field448 z);

	// [s]B on edwards448 for any s. The extended coordinates of the result depend on s, not only on [s]B.
	static abstract void MultiplyBase(ReadOnlySpan<byte> scalar, out EdwardsPoint result);

	// [a]A + [b]B for any a and b and any point A of edwards448, whatever its order.
	static abstract void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, in EdwardsPoint point, ReadOnlySpan<byte> b, out EdwardsPoint result);

	// As above, with the table that EdwardsVariableTimePointTable builds for A.
	static abstract void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, ReadOnlySpan<EdwardsAffinePoint> pointTable, ReadOnlySpan<byte> b, out EdwardsPoint result);
}
