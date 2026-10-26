namespace CryptoBase.EllipticCurves;

// Coordinates are in Montgomery form.
internal struct AffinePoint<TField> where TField : unmanaged, IEcField<TField>
{
	internal TField X;
	internal TField Y;

	// mask is ulong.MaxValue or 0; result may be either input.
	internal static void ConditionalSelect(ulong mask, in AffinePoint<TField> whenSet, in AffinePoint<TField> whenClear, out AffinePoint<TField> result)
	{
		TField.ConditionalSelect(mask, in whenSet.X, in whenClear.X, out result.X);
		TField.ConditionalSelect(mask, in whenSet.Y, in whenClear.Y, out result.Y);
	}
}
