namespace CryptoBase.EllipticCurves.Curve25519;

// (Y + X, Y − X, 2Z, 2dT) of a point in extended coordinates, the right operand of Edwards25519.Add and Subtract. Every coordinate is tight.
internal struct EdwardsCachedPoint
{
	internal Field25519 YPlusX;
	internal Field25519 YMinusX;
	internal Field25519 TwoZ;
	internal Field25519 TwoDT;
}
