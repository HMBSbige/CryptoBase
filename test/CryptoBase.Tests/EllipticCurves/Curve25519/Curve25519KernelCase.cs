using CryptoBase.EllipticCurves.Curve25519;

namespace CryptoBase.Tests.EllipticCurves.Curve25519;

public abstract class Curve25519KernelCase : IKernelCase
{
	public static IEnumerable<Curve25519KernelCase> All()
	{
		yield return new Kernel<Curve25519Scalar>();
		yield return new Kernel<Curve25519Avx2>();
		yield return new Kernel<Curve25519Avx512>();
		yield return new Kernel<Curve25519Sse41>();
		yield return new Kernel<Curve25519KernelDispatch>();
	}

	public abstract Type KernelType { get; }

	public abstract bool IsSupported { get; }

	internal abstract void Ladder(ReadOnlySpan<byte> scalar, in Field25519 u, out Field25519 x, out Field25519 z);

	internal abstract void MultiplyBase(ReadOnlySpan<byte> scalar, out EdwardsPoint result);

	internal abstract void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, in EdwardsPoint point, ReadOnlySpan<byte> b, out EdwardsPoint result);

	internal abstract void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, ReadOnlySpan<EdwardsNielsPoint> pointTable, ReadOnlySpan<byte> b, out EdwardsPoint result);

	public override string ToString()
	{
		return KernelType.Name;
	}

	private sealed class Kernel<TKernel> : Curve25519KernelCase where TKernel : ICurve25519Kernel
	{
		public override Type KernelType => typeof(TKernel);

		public override bool IsSupported => TKernel.IsSupported;

		internal override void Ladder(ReadOnlySpan<byte> scalar, in Field25519 u, out Field25519 x, out Field25519 z)
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

		internal override void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, ReadOnlySpan<EdwardsNielsPoint> pointTable, ReadOnlySpan<byte> b, out EdwardsPoint result)
		{
			TKernel.DoubleScalarMultiplyVariableTime(a, pointTable, b, out result);
		}
	}
}
