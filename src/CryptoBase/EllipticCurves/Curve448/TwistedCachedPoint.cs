namespace CryptoBase.EllipticCurves.Curve448;

// (Y + X, Y − X, 2Z, 2d'T) of a point of the twisted curve in extended coordinates, the right operand of TwistedEdwards448.Add. Every coordinate is tight.
internal struct TwistedCachedPoint
{
	internal Field448 YPlusX;
	internal Field448 YMinusX;
	internal Field448 TwoZ;
	internal Field448 TwoDT;
}
