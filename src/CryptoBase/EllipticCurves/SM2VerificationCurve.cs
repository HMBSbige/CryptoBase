namespace CryptoBase.EllipticCurves;

// SM2Curve with windows of 8 bits, for the products of public scalars, which read the entry of a digit in place rather than scan its window: wider windows take fewer rounds at no cost in scans, so the windows of G and the ECPointTable of a key that verification takes are of this curve, and those that the products of secret scalars scan are of SM2Curve.
internal readonly struct SM2VerificationCurve : IECCurve
{
	public static ReadOnlySpan<ulong> B => SM2Curve.B;

	public static ReadOnlySpan<ulong> GeneratorX => SM2Curve.GeneratorX;

	public static ReadOnlySpan<ulong> GeneratorY => SM2Curve.GeneratorY;

	// 8 bits divide the 256 of n, so that ECGroup.RecodeSpanning gives 32 digits, from k or k − n: four rounds on eight lanes, eight with two tables.
	public static int GeneratorWindowWidth => 8;

	// The products of SM2KernelDispatch for the windows of this curve, with the field and the order of SM2, which are the only ones that ECGroup takes with it.
	public static bool TryFillBases<TField, TOrder>(in AffinePoint<TField> point, Span<JacobianPoint<TField>> bases) where TField : unmanaged, IECField<TField> where TOrder : unmanaged, IMontgomeryModulus
	{
		if (typeof(TField) != typeof(SM2CurveField) || typeof(TOrder) != typeof(SM2Order))
		{
			return false;
		}

		SM2KernelDispatch.FillBases<SM2VerificationCurve>(in Unsafe.As<AffinePoint<TField>, AffinePoint<SM2CurveField>>(ref Unsafe.AsRef(in point)), MemoryMarshal.Cast<JacobianPoint<TField>, JacobianPoint<SM2CurveField>>(bases));
		return true;
	}

	public static bool TryFillWindows<TField, TOrder>(Span<ulong> windows) where TField : unmanaged, IECField<TField> where TOrder : unmanaged, IMontgomeryModulus
	{
		if (typeof(TField) != typeof(SM2CurveField) || typeof(TOrder) != typeof(SM2Order))
		{
			return false;
		}

		SM2KernelDispatch.FillWindows<SM2VerificationCurve>(windows);
		return true;
	}

	public static bool TryMultiplyAddFixed<TField, TOrder>(ReadOnlySpan<ulong> windows, in FieldElement<TOrder> u1, in FieldElement<TOrder> u2, out JacobianPoint<TField> result) where TField : unmanaged, IECField<TField> where TOrder : unmanaged, IMontgomeryModulus
	{
		Unsafe.SkipInit(out result);

		if (typeof(TField) != typeof(SM2CurveField) || typeof(TOrder) != typeof(SM2Order))
		{
			return false;
		}

		SM2KernelDispatch.MultiplyAddFixed(windows, in Unsafe.As<FieldElement<TOrder>, FieldElement<SM2Order>>(ref Unsafe.AsRef(in u1)), in Unsafe.As<FieldElement<TOrder>, FieldElement<SM2Order>>(ref Unsafe.AsRef(in u2)), out Unsafe.As<JacobianPoint<TField>, JacobianPoint<SM2CurveField>>(ref result));
		return true;
	}
}
