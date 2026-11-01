namespace CryptoBase.EllipticCurves.Curve25519;

// Extended coordinates (X : Y : Z : T) of the point (X/Z, Y/Z), with XY = ZT. Every coordinate is tight.
internal struct EdwardsPoint
{
	internal Field25519 X;
	internal Field25519 Y;
	internal Field25519 Z;
	internal Field25519 T;
}
