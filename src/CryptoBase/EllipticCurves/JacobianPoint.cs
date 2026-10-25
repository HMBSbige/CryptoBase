namespace CryptoBase.EllipticCurves;

// Coordinates are in Montgomery form.
internal struct JacobianPoint<TField> where TField : struct, IMontgomeryModulus
{
	internal FieldElement<TField> X;
	internal FieldElement<TField> Y;
	internal FieldElement<TField> Z;

	internal readonly bool IsInfinity => FieldElement<TField>.IsZero(in Z) is not 0;

	internal static void FromAffine(in AffinePoint<TField> point, out JacobianPoint<TField> result)
	{
		result.X = point.X;
		result.Y = point.Y;
		result.Z = FieldElement<TField>.MontgomeryOne;
	}

	// mask is ulong.MaxValue or 0; result may be either input.
	internal static void ConditionalSelect(ulong mask, in JacobianPoint<TField> whenSet, in JacobianPoint<TField> whenClear, out JacobianPoint<TField> result)
	{
		FieldElement<TField>.ConditionalSelect(mask, in whenSet.X, in whenClear.X, out result.X);
		FieldElement<TField>.ConditionalSelect(mask, in whenSet.Y, in whenClear.Y, out result.Y);
		FieldElement<TField>.ConditionalSelect(mask, in whenSet.Z, in whenClear.Z, out result.Z);
	}

	// As above, with whenSet taken in the form FromAffine gives it.
	internal static void ConditionalSelect(ulong mask, in AffinePoint<TField> whenSet, in JacobianPoint<TField> whenClear, out JacobianPoint<TField> result)
	{
		FieldElement<TField>.ConditionalSelect(mask, in whenSet.X, in whenClear.X, out result.X);
		FieldElement<TField>.ConditionalSelect(mask, in whenSet.Y, in whenClear.Y, out result.Y);
		FieldElement<TField>.ConditionalSelect(mask, in FieldElement<TField>.MontgomeryOne, in whenClear.Z, out result.Z);
	}
}
