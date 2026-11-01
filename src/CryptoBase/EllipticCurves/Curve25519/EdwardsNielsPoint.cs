namespace CryptoBase.EllipticCurves.Curve25519;

// (y + x, y − x, 2dxy) of an affine point, the entries of the tables and the right operand of Edwards25519.AddNiels and SubtractNiels. Every coordinate is tight. The identity is (1, 1, 0).
internal struct EdwardsNielsPoint
{
	internal Field25519 YPlusX;
	internal Field25519 YMinusX;
	internal Field25519 TwoDXY;
}
