namespace CryptoBase.EllipticCurves.Curve25519;

// Projective coordinates (X : Y : Z) of the point (X/Z, Y/Z), which a doubling takes. Every coordinate is tight.
internal struct EdwardsProjectivePoint
{
	internal Field25519 X;
	internal Field25519 Y;
	internal Field25519 Z;
}
