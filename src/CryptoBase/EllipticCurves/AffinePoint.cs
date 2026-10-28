namespace CryptoBase.EllipticCurves;

// Coordinates are in Montgomery form.
internal struct AffinePoint<TField> where TField : unmanaged, IEcField<TField>
{
	internal TField X;
	internal TField Y;
}
