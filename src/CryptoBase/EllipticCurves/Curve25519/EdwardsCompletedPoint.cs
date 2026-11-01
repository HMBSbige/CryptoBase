namespace CryptoBase.EllipticCurves.Curve25519;

// ((X : Z), (Y : T)), the point (X/Z, Y/T) that the addition and doubling formulas give before the products that bring it to extended or projective coordinates. The coordinates are below 2^54 in every limb, which Multiply takes, but need not be tight.
internal struct EdwardsCompletedPoint
{
	internal Field25519 X;
	internal Field25519 Y;
	internal Field25519 Z;
	internal Field25519 T;
}
