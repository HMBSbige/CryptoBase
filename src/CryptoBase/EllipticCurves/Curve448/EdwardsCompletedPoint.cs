namespace CryptoBase.EllipticCurves.Curve448;

// ((X : Z), (Y : T)), the point (X/Z, Y/T) that the addition and doubling formulas give before the products that bring it to extended or projective coordinates. Each formula keeps the coordinates within what Field448.Multiply takes in ToExtended, but they need not be tight.
internal struct EdwardsCompletedPoint
{
	internal Field448 X;
	internal Field448 Y;
	internal Field448 Z;
	internal Field448 T;
}
