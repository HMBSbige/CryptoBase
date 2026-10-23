namespace CryptoBase.EllipticCurves;

// Coordinates are in Montgomery form.
internal struct AffinePoint<TField> where TField : struct, IMontgomeryModulus
{
	internal FieldElement<TField> X;
	internal FieldElement<TField> Y;

	// mask is ulong.MaxValue or 0; result may be either input.
	internal static void ConditionalSelect(ulong mask, in AffinePoint<TField> whenSet, in AffinePoint<TField> whenClear, out AffinePoint<TField> result)
	{
		FieldElement<TField>.ConditionalSelect(mask, in whenSet.X, in whenClear.X, out result.X);
		FieldElement<TField>.ConditionalSelect(mask, in whenSet.Y, in whenClear.Y, out result.Y);
	}
}
