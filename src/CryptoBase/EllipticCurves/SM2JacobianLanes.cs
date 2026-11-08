namespace CryptoBase.EllipticCurves;

// A Jacobian point in each lane of TField, coordinates in Montgomery form.
internal struct SM2JacobianLanes<TField> where TField : unmanaged, ISM2Field29Lanes<TField>
{
	internal TField X;
	internal TField Y;
	internal TField Z;

	// mask is a lane mask; result may be either input.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void ConditionalSelect(ref readonly ulong mask, in SM2JacobianLanes<TField> whenSet, in SM2JacobianLanes<TField> whenClear, out SM2JacobianLanes<TField> result)
	{
		TField.ConditionalSelect(in mask, in whenSet.X, in whenClear.X, out result.X);
		TField.ConditionalSelect(in mask, in whenSet.Y, in whenClear.Y, out result.Y);
		TField.ConditionalSelect(in mask, in whenSet.Z, in whenClear.Z, out result.Z);
	}
}
