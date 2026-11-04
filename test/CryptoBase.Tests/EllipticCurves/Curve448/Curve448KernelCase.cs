using CryptoBase.EllipticCurves.Curve448;

namespace CryptoBase.Tests.EllipticCurves.Curve448;

public abstract class Curve448KernelCase : IKernelCase
{
	public static IEnumerable<Curve448KernelCase> All()
	{
		yield return new Kernel<Curve448Scalar>();
		yield return new Kernel<Curve448Avx2>();
		yield return new Kernel<Curve448Avx512>();
		yield return new Kernel<Curve448Sse41>();
		yield return new Kernel<Curve448AdvSimd>();
		yield return new Kernel<Curve448KernelDispatch>();
	}

	public abstract Type KernelType { get; }

	public abstract bool IsSupported { get; }

	internal abstract void Ladder(ReadOnlySpan<byte> scalar, in Field448 u, out Field448 x, out Field448 z);

	internal abstract void MultiplyBase(ReadOnlySpan<byte> scalar, out EdwardsPoint result);

	internal abstract void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, in EdwardsPoint point, ReadOnlySpan<byte> b, out EdwardsPoint result);

	internal abstract void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, ReadOnlySpan<EdwardsAffinePoint> pointTable, ReadOnlySpan<byte> b, out EdwardsPoint result);

	public override string ToString()
	{
		return KernelType.Name;
	}

	private sealed class Kernel<TKernel> : Curve448KernelCase where TKernel : ICurve448Kernel
	{
		public override Type KernelType => typeof(TKernel);

		public override bool IsSupported => TKernel.IsSupported;

		internal override void Ladder(ReadOnlySpan<byte> scalar, in Field448 u, out Field448 x, out Field448 z)
		{
			TKernel.Ladder(scalar, in u, out x, out z);
		}

		internal override void MultiplyBase(ReadOnlySpan<byte> scalar, out EdwardsPoint result)
		{
			TKernel.MultiplyBase(scalar, out result);
		}

		internal override void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, in EdwardsPoint point, ReadOnlySpan<byte> b, out EdwardsPoint result)
		{
			TKernel.DoubleScalarMultiplyVariableTime(a, in point, b, out result);
		}

		internal override void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, ReadOnlySpan<EdwardsAffinePoint> pointTable, ReadOnlySpan<byte> b, out EdwardsPoint result)
		{
			TKernel.DoubleScalarMultiplyVariableTime(a, pointTable, b, out result);
		}
	}
}
