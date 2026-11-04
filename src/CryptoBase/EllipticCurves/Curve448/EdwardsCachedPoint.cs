namespace CryptoBase.EllipticCurves.Curve448;

// (X, Y, Z, dT) of a point of edwards448 in extended coordinates, the right operand of Edwards448.Add and Subtract. Every coordinate is tight.
internal struct EdwardsCachedPoint
{
	internal Field448 X;
	internal Field448 Y;
	internal Field448 Z;
	internal Field448 DT;
}
