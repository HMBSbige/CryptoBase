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
}
