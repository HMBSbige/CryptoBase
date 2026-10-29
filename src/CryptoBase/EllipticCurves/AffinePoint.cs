namespace CryptoBase.EllipticCurves;

// Coordinates are in Montgomery form.
internal struct AffinePoint<TField> where TField : unmanaged, IECField<TField>
{
	internal TField X;
	internal TField Y;
}
