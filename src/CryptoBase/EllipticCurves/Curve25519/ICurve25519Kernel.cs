namespace CryptoBase.EllipticCurves.Curve25519;

// The scalar multiplications of X25519 and edwards25519, which take and give Field25519 and EdwardsPoint values whatever a kernel uses inside. Scalars are 32 little-endian bytes. Ladder and MultiplyBase take secrets: neither their time nor the addresses they read may depend on the scalar or the point, and they erase the buffers they own. DoubleScalarMultiplyVariableTime takes public inputs and may branch on them.
internal interface ICurve25519Kernel
{
	static abstract bool IsSupported { get; }

	// Sets x and z to the projective u-coordinate (x : z) of [k]P, by the ladder of RFC 7748 §5, for the point P of Curve25519 or of its twist with u-coordinate u, which must be tight. k is clamped as decodeScalar25519 leaves it: bits 0 to 2 and 255 clear, bit 254 set. z = 0 is the point at infinity. x and z are tight.
	static abstract void Ladder(ReadOnlySpan<byte> scalar, in Field25519 u, out Field25519 x, out Field25519 z);

	// [s]B for any s. The extended coordinates of the result depend on s, not only on [s]B.
	static abstract void MultiplyBase(ReadOnlySpan<byte> scalar, out EdwardsPoint result);

	// [a]A + [b]B for any a and b.
	static abstract void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, in EdwardsPoint point, ReadOnlySpan<byte> b, out EdwardsPoint result);

	// As above, with the table that EdwardsVariableTimePointTable builds for A.
	static abstract void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, ReadOnlySpan<EdwardsNielsPoint> pointTable, ReadOnlySpan<byte> b, out EdwardsPoint result);
}
