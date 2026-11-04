namespace CryptoBase.EllipticCurves.Curve448;

// Extended coordinates (X : Y : Z : T) of the point (X/Z, Y/Z), with XY = ZT. Every coordinate is tight. TwistedEdwards448 also takes them as a point of the twisted curve, inside the fixed-base product alone.
internal struct EdwardsPoint
{
	internal Field448 X;
	internal Field448 Y;
	internal Field448 Z;
	internal Field448 T;
}
