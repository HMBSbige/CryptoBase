namespace CryptoBase.EllipticCurves.Curve448;

// (y + x, y − x, 2d'xy) of an affine point of the twisted curve, d' = d − 1: the entries of TwistedBaseTable and the right operand of TwistedEdwards448.AddNiels. Every coordinate is tight.
internal struct TwistedNielsPoint
{
	internal Field448 YPlusX;
	internal Field448 YMinusX;
	internal Field448 TwoDXY;
}
