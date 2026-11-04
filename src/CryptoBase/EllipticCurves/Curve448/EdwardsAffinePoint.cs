namespace CryptoBase.EllipticCurves.Curve448;

// (x, y, dxy) of an affine point of edwards448, the entries of the variable-time tables and the right operand of Edwards448.AddAffine and SubtractAffine. Every coordinate is tight. The identity is (0, 1, 0).
internal struct EdwardsAffinePoint
{
	internal Field448 X;
	internal Field448 Y;
	internal Field448 DXY;
}
