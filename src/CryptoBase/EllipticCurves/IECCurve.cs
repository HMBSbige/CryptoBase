namespace CryptoBase.EllipticCurves;

// The curve y² = x³ − 3x + b over the field of p, with a group of prime order n. The constants are plain values below p, least significant limb of 64 bits first, so that they hold for any IECField of p.
internal interface IECCurve
{
	static abstract ReadOnlySpan<ulong> B { get; }

	static abstract ReadOnlySpan<ulong> GeneratorX { get; }

	static abstract ReadOnlySpan<ulong> GeneratorY { get; }

	static abstract int GeneratorWindowWidth { get; }

	// Whether TryMultiplyAdd of two points has kernels of the curve's own.
	static virtual bool HasMultiplyAdd => false;

	// Sets result to k·G for k below n by kernels of the curve's own, with the contract of ECGroup.MultiplyBase, and returns true; or returns false, leaving result unset, so that ECGroup takes its own windows.
	static virtual bool TryMultiplyBase<TField, TOrder>(in FieldElement<TOrder> scalar, out JacobianPoint<TField> result) where TField : unmanaged, IECField<TField> where TOrder : unmanaged, IMontgomeryModulus
	{
		Unsafe.SkipInit(out result);
		return false;
	}

	// The same for u1·G + u2·Q with the table of Q, with the contract of ECVariableTimeGroup.MultiplyAdd: every input is public.
	static virtual bool TryMultiplyAdd<TField, TOrder>(in FieldElement<TOrder> u1, ReadOnlySpan<AffinePoint<TField>> pointTable, in FieldElement<TOrder> u2, out JacobianPoint<TField> result) where TField : unmanaged, IECField<TField> where TOrder : unmanaged, IMontgomeryModulus
	{
		Unsafe.SkipInit(out result);
		return false;
	}

	// Sets the bases of the windows of a table, 2^(wi)·P for w = GeneratorWindowWidth, as ECGeneratorTable.FillBases does, by kernels of the curve's own, and returns true; or returns false, so that ECGeneratorTable sets them itself. P is public, so the time may depend on it.
	static virtual bool TryFillBases<TField, TOrder>(in AffinePoint<TField> point, Span<JacobianPoint<TField>> bases) where TField : unmanaged, IECField<TField> where TOrder : unmanaged, IMontgomeryModulus
	{
		return false;
	}

	// Fills the windows of a table from their bases, as ECGeneratorTable.FillWindows does, by kernels of the curve's own, and returns true; or returns false, so that ECGeneratorTable fills them itself. The table is public, so the time may depend on it.
	static virtual bool TryFillWindows<TField, TOrder>(Span<ulong> windows) where TField : unmanaged, IECField<TField> where TOrder : unmanaged, IMontgomeryModulus
	{
		return false;
	}

	// The same for k·P from the windows of P that ECPointTable holds, with the contract of ECGroup.MultiplyFixed: neither the time nor the addresses may depend on k.
	static virtual bool TryMultiplyFixed<TField, TOrder>(ReadOnlySpan<ulong> windows, in FieldElement<TOrder> scalar, out JacobianPoint<TField> result) where TField : unmanaged, IECField<TField> where TOrder : unmanaged, IMontgomeryModulus
	{
		Unsafe.SkipInit(out result);
		return false;
	}

	// The same for u1·G + u2·P from the windows of P that ECPointTable holds, with the contract of ECVariableTimeGroup.MultiplyAdd: every input is public.
	static virtual bool TryMultiplyAddFixed<TField, TOrder>(ReadOnlySpan<ulong> windows, in FieldElement<TOrder> u1, in FieldElement<TOrder> u2, out JacobianPoint<TField> result) where TField : unmanaged, IECField<TField> where TOrder : unmanaged, IMontgomeryModulus
	{
		Unsafe.SkipInit(out result);
		return false;
	}

	// The same for k·G and k·P from the windows of P that ECPointTable holds, with the contract of ECGroup.MultiplyBaseAndFixed: neither the time nor the addresses may depend on k.
	static virtual bool TryMultiplyBaseAndFixed<TField, TOrder>(ReadOnlySpan<ulong> windows, in FieldElement<TOrder> scalar, out JacobianPoint<TField> baseResult, out JacobianPoint<TField> result) where TField : unmanaged, IECField<TField> where TOrder : unmanaged, IMontgomeryModulus
	{
		Unsafe.SkipInit(out baseResult);
		Unsafe.SkipInit(out result);
		return false;
	}

	// The same for k·P, with the contract of ECGroup.Multiply: neither the time nor the addresses may depend on k or P.
	static virtual bool TryMultiply<TField, TOrder>(in AffinePoint<TField> point, in FieldElement<TOrder> scalar, out JacobianPoint<TField> result) where TField : unmanaged, IECField<TField> where TOrder : unmanaged, IMontgomeryModulus
	{
		Unsafe.SkipInit(out result);
		return false;
	}

	// The same for u1·G + u2·Q without a table, with the contract of ECVariableTimeGroup.MultiplyAdd: every input is public.
	static virtual bool TryMultiplyAdd<TField, TOrder>(in FieldElement<TOrder> u1, in AffinePoint<TField> point, in FieldElement<TOrder> u2, out JacobianPoint<TField> result) where TField : unmanaged, IECField<TField> where TOrder : unmanaged, IMontgomeryModulus
	{
		Unsafe.SkipInit(out result);
		return false;
	}

	// Sets equals to whether u1·G + u2·Q is not the point at infinity and its x is r mod n, for u1, u2 and r below n and a point Q on the curve, by kernels of the curve's own, and returns true; or returns false, so that ECVariableTimeGroup takes MultiplyAdd and XModOrderEquals. Every input is public.
	static virtual bool TryMultiplyAddXModOrderEquals<TField, TOrder>(in FieldElement<TOrder> u1, in AffinePoint<TField> point, in FieldElement<TOrder> u2, in FieldElement<TOrder> r, out bool equals) where TField : unmanaged, IECField<TField> where TOrder : unmanaged, IMontgomeryModulus
	{
		equals = false;
		return false;
	}

	// The same for k·P + l·Q, with the contract of ECGroup.MultiplyAdd: neither the time nor the addresses may depend on k, l, P or Q.
	static virtual bool TryMultiplyAdd<TField, TOrder>(in AffinePoint<TField> point, in FieldElement<TOrder> scalar, in AffinePoint<TField> otherPoint, in FieldElement<TOrder> otherScalar, out JacobianPoint<TField> result) where TField : unmanaged, IECField<TField> where TOrder : unmanaged, IMontgomeryModulus
	{
		Unsafe.SkipInit(out result);
		return false;
	}
}
