namespace CryptoBase.EllipticCurves;

// Coordinates are in Montgomery form.
internal struct JacobianPoint<TField> where TField : unmanaged, IEcField<TField>
{
	internal TField X;
	internal TField Y;
	internal TField Z;

	internal readonly bool IsInfinity => TField.IsZero(in Z) is not 0;

	internal static void FromAffine(in AffinePoint<TField> point, out JacobianPoint<TField> result)
	{
		result.X = point.X;
		result.Y = point.Y;
		result.Z = TField.One;
	}

	// mask is ulong.MaxValue or 0; result may be either input.
	internal static void ConditionalSelect(ulong mask, in JacobianPoint<TField> whenSet, in JacobianPoint<TField> whenClear, out JacobianPoint<TField> result)
	{
		TField.ConditionalSelect(mask, in whenSet.X, in whenClear.X, out result.X);
		TField.ConditionalSelect(mask, in whenSet.Y, in whenClear.Y, out result.Y);
		TField.ConditionalSelect(mask, in whenSet.Z, in whenClear.Z, out result.Z);
	}

	// As above, with whenSet taken in the form FromAffine gives it.
	internal static void ConditionalSelect(ulong mask, in AffinePoint<TField> whenSet, in JacobianPoint<TField> whenClear, out JacobianPoint<TField> result)
	{
		TField.ConditionalSelect(mask, in whenSet.X, in whenClear.X, out result.X);
		TField.ConditionalSelect(mask, in whenSet.Y, in whenClear.Y, out result.Y);
		TField.ConditionalSelect(mask, in TField.One, in whenClear.Z, out result.Z);
	}
}
