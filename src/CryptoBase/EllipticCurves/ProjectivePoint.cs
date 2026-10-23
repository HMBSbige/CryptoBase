namespace CryptoBase.EllipticCurves;

// Coordinates are in Montgomery form.
internal struct ProjectivePoint<TField> where TField : struct, IMontgomeryModulus
{
	internal FieldElement<TField> X;
	internal FieldElement<TField> Y;
	internal FieldElement<TField> Z;

	internal static ProjectivePoint<TField> Identity => new() { Y = FieldElement<TField>.MontgomeryOne };

	internal static void FromAffine(in AffinePoint<TField> point, out ProjectivePoint<TField> result)
	{
		result.X = point.X;
		result.Y = point.Y;
		result.Z = FieldElement<TField>.MontgomeryOne;
	}

	// Returns ulong.MaxValue for the point at infinity and 0 otherwise.
	internal static ulong IsIdentity(in ProjectivePoint<TField> point)
	{
		return FieldElement<TField>.IsZero(in point.Z);
	}

	// mask is ulong.MaxValue or 0; result may be either input.
	internal static void ConditionalSelect(ulong mask, in ProjectivePoint<TField> whenSet, in ProjectivePoint<TField> whenClear, out ProjectivePoint<TField> result)
	{
		FieldElement<TField>.ConditionalSelect(mask, in whenSet.X, in whenClear.X, out result.X);
		FieldElement<TField>.ConditionalSelect(mask, in whenSet.Y, in whenClear.Y, out result.Y);
		FieldElement<TField>.ConditionalSelect(mask, in whenSet.Z, in whenClear.Z, out result.Z);
	}
}
