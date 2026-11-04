namespace CryptoBase.EllipticCurves.Curve448;

// Projective coordinates (X : Y : Z) of the point (X/Z, Y/Z), which a doubling takes. Every coordinate is tight.
internal struct EdwardsProjectivePoint
{
	internal Field448 X;
	internal Field448 Y;
	internal Field448 Z;
}
