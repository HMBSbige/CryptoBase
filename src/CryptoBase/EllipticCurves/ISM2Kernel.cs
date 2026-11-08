namespace CryptoBase.EllipticCurves;

// The products of the SM2 curve that kernels may speed up, which take and give SM2Field52 values whatever a kernel uses inside; SM2Curve hands them to ECGroup and ECVariableTimeGroup. MultiplyBase takes a secret: neither its time nor the addresses it reads may depend on the scalar, and it erases the buffers it owns. MultiplyAdd takes public inputs and may branch on them.
internal interface ISM2Kernel
{
	static abstract bool IsSupported { get; }

	// k·G for k below n, as ECGroup.MultiplyBase gives it: limbs of the form E of SM2Field52, Z = 0 for k = 0, and a Jacobian form that depends on k, not only on k·G.
	static abstract void MultiplyBase(in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> result);

	// u1·G + u2·Q for u1 and u2 below n and the table that ECVariableTimePointTable builds for Q, as ECVariableTimeGroup.MultiplyAdd gives it. Every input is public, so the time may depend on them.
	static abstract void MultiplyAdd(in FieldElement<SM2Order> u1, ReadOnlySpan<AffinePoint<SM2Field52>> pointTable, in FieldElement<SM2Order> u2, out JacobianPoint<SM2Field52> result);

	// Sets the bases of the windows of a table of TCurve, SM2Curve or SM2VerificationCurve, as ECGeneratorTable.FillBases does: each in the form E. P is public, so the time may depend on it.
	static abstract void FillBases<TCurve>(in AffinePoint<SM2Field52> point, Span<JacobianPoint<SM2Field52>> bases) where TCurve : struct, IECCurve;

	// Fills the windows of a table of TCurve from their bases, as ECGeneratorTable.FillWindows does. The table is public, so the time may depend on it.
	static abstract void FillWindows<TCurve>(Span<ulong> windows) where TCurve : struct, IECCurve;

	// k·P for k below n and the windows of P that ECPointTable holds, as ECGroup.MultiplyFixed gives it: as MultiplyBase gives k·G, with the same contract.
	static abstract void MultiplyFixed(ReadOnlySpan<ulong> windows, in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> result);

	// u1·G + u2·P for u1 and u2 below n and the windows of P that ECPointTable holds for SM2VerificationCurve, as ECVariableTimeGroup.MultiplyAdd gives it with them, from the windows of G of that curve. Every input is public, so the time may depend on them.
	static abstract void MultiplyAddFixed(ReadOnlySpan<ulong> windows, in FieldElement<SM2Order> u1, in FieldElement<SM2Order> u2, out JacobianPoint<SM2Field52> result);

	// k·G and k·P for k below n and the windows of P that ECPointTable holds, as ECGroup.MultiplyBaseAndFixed gives them: each as MultiplyBase gives k·G, with the same contract.
	static abstract void MultiplyBaseAndFixed(ReadOnlySpan<ulong> windows, in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> baseResult, out JacobianPoint<SM2Field52> result);

	// k·P for a point P on the curve and k below n, as ECGroup.Multiply gives it: limbs of the form E, Z = 0 for k = 0, and neither the time nor the addresses depending on k or P.
	static abstract void Multiply(in AffinePoint<SM2Field52> point, in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> result);

	// u1·G + u2·Q without a table, as ECVariableTimeGroup.MultiplyAdd gives it. Every input is public.
	static abstract void MultiplyAdd(in FieldElement<SM2Order> u1, in AffinePoint<SM2Field52> point, in FieldElement<SM2Order> u2, out JacobianPoint<SM2Field52> result);
}
