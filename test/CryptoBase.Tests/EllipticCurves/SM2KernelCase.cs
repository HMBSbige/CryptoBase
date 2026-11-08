using CryptoBase.EllipticCurves;

namespace CryptoBase.Tests.EllipticCurves;

public abstract class SM2KernelCase : IKernelCase
{
	public static IEnumerable<SM2KernelCase> All()
	{
		yield return new Kernel<SM2Scalar>();
		yield return new Kernel<SM2Avx512>();
		yield return new Kernel<SM2Avx2>();
		yield return new Kernel<SM2Sse41>();
		yield return new Kernel<SM2AdvSimd>();
		yield return new Kernel<SM2KernelDispatch>();
	}

	public abstract Type KernelType { get; }

	public abstract bool IsSupported { get; }

	internal abstract void MultiplyBase(in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> result);

	internal abstract void MultiplyAdd(in FieldElement<SM2Order> u1, ReadOnlySpan<AffinePoint<SM2Field52>> pointTable, in FieldElement<SM2Order> u2, out JacobianPoint<SM2Field52> result);

	internal abstract void FillBases<TCurve>(in AffinePoint<SM2Field52> point, Span<JacobianPoint<SM2Field52>> bases) where TCurve : struct, IECCurve;

	internal abstract void FillWindows<TCurve>(Span<ulong> windows) where TCurve : struct, IECCurve;

	internal abstract void MultiplyFixed(ReadOnlySpan<ulong> windows, in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> result);

	internal abstract void MultiplyAddFixed(ReadOnlySpan<ulong> windows, in FieldElement<SM2Order> u1, in FieldElement<SM2Order> u2, out JacobianPoint<SM2Field52> result);

	internal abstract void MultiplyBaseAndFixed(ReadOnlySpan<ulong> windows, in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> baseResult, out JacobianPoint<SM2Field52> result);

	internal abstract void Multiply(in AffinePoint<SM2Field52> point, in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> result);

	internal abstract void MultiplyAdd(in FieldElement<SM2Order> u1, in AffinePoint<SM2Field52> point, in FieldElement<SM2Order> u2, out JacobianPoint<SM2Field52> result);

	public override string ToString()
	{
		return KernelType.Name;
	}

	private sealed class Kernel<TKernel> : SM2KernelCase where TKernel : ISM2Kernel
	{
		public override Type KernelType => typeof(TKernel);

		public override bool IsSupported => TKernel.IsSupported;

		internal override void MultiplyBase(in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> result)
		{
			TKernel.MultiplyBase(in scalar, out result);
		}

		internal override void MultiplyAdd(in FieldElement<SM2Order> u1, ReadOnlySpan<AffinePoint<SM2Field52>> pointTable, in FieldElement<SM2Order> u2, out JacobianPoint<SM2Field52> result)
		{
			TKernel.MultiplyAdd(in u1, pointTable, in u2, out result);
		}

		internal override void FillBases<TCurve>(in AffinePoint<SM2Field52> point, Span<JacobianPoint<SM2Field52>> bases)
		{
			TKernel.FillBases<TCurve>(in point, bases);
		}

		internal override void FillWindows<TCurve>(Span<ulong> windows)
		{
			TKernel.FillWindows<TCurve>(windows);
		}

		internal override void MultiplyFixed(ReadOnlySpan<ulong> windows, in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> result)
		{
			TKernel.MultiplyFixed(windows, in scalar, out result);
		}

		internal override void MultiplyAddFixed(ReadOnlySpan<ulong> windows, in FieldElement<SM2Order> u1, in FieldElement<SM2Order> u2, out JacobianPoint<SM2Field52> result)
		{
			TKernel.MultiplyAddFixed(windows, in u1, in u2, out result);
		}

		internal override void MultiplyBaseAndFixed(ReadOnlySpan<ulong> windows, in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> baseResult, out JacobianPoint<SM2Field52> result)
		{
			TKernel.MultiplyBaseAndFixed(windows, in scalar, out baseResult, out result);
		}

		internal override void Multiply(in AffinePoint<SM2Field52> point, in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> result)
		{
			TKernel.Multiply(in point, in scalar, out result);
		}

		internal override void MultiplyAdd(in FieldElement<SM2Order> u1, in AffinePoint<SM2Field52> point, in FieldElement<SM2Order> u2, out JacobianPoint<SM2Field52> result)
		{
			TKernel.MultiplyAdd(in u1, in point, in u2, out result);
		}
	}
}
