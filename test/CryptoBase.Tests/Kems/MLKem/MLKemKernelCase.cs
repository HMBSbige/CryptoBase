using CryptoBase.Kems.MLKem;

namespace CryptoBase.Tests.Kems.MLKem;

public abstract class MLKemKernelCase
{
	public static IEnumerable<MLKemKernelCase> All()
	{
		yield return new Kernel<MLKemScalar>();
		yield return new Kernel<MLKemVector128>();
		yield return new Kernel<MLKemAvx2>();
		yield return new Kernel<MLKemAvx512>();
		yield return new Kernel<MLKemKernelDispatch>();
	}

	public abstract Type KernelType { get; }

	public abstract bool IsSupported { get; }

	internal abstract void Ntt(Span<short> f);

	internal abstract void InverseNtt(Span<short> f);

	internal abstract void MultiplyAccumulate(ReadOnlySpan<short> a, int aStride, ReadOnlySpan<short> b, Span<short> destination, int count);

	internal abstract void Reduce(Span<short> f);

	internal abstract void ToMontgomery(Span<short> f);

	internal abstract void Add(ReadOnlySpan<short> left, ReadOnlySpan<short> right, Span<short> destination);

	internal abstract void Subtract(ReadOnlySpan<short> left, ReadOnlySpan<short> right, Span<short> destination);

	internal abstract void Encode12(ReadOnlySpan<short> f, Span<byte> destination);

	internal abstract bool Decode12(ReadOnlySpan<byte> source, Span<short> f);

	internal abstract void Compress(ReadOnlySpan<short> f, Span<byte> destination, int bits);

	internal abstract void Decompress(ReadOnlySpan<byte> source, Span<short> f, int bits);

	internal abstract int RejectSample(ReadOnlySpan<byte> source, Span<short> destination);

	internal abstract void SampleCbd(ReadOnlySpan<byte> source, Span<short> f, int eta);

	public override string ToString()
	{
		return KernelType.Name;
	}

	private sealed class Kernel<TKernel> : MLKemKernelCase where TKernel : IMLKemKernel
	{
		public override Type KernelType => typeof(TKernel);

		public override bool IsSupported => TKernel.IsSupported;

		internal override void Ntt(Span<short> f)
		{
			TKernel.Ntt(f);
		}

		internal override void InverseNtt(Span<short> f)
		{
			TKernel.InverseNtt(f);
		}

		internal override void MultiplyAccumulate(ReadOnlySpan<short> a, int aStride, ReadOnlySpan<short> b, Span<short> destination, int count)
		{
			TKernel.MultiplyAccumulate(a, aStride, b, destination, count);
		}

		internal override void Reduce(Span<short> f)
		{
			TKernel.Reduce(f);
		}

		internal override void ToMontgomery(Span<short> f)
		{
			TKernel.ToMontgomery(f);
		}

		internal override void Add(ReadOnlySpan<short> left, ReadOnlySpan<short> right, Span<short> destination)
		{
			TKernel.Add(left, right, destination);
		}

		internal override void Subtract(ReadOnlySpan<short> left, ReadOnlySpan<short> right, Span<short> destination)
		{
			TKernel.Subtract(left, right, destination);
		}

		internal override void Encode12(ReadOnlySpan<short> f, Span<byte> destination)
		{
			TKernel.Encode12(f, destination);
		}

		internal override bool Decode12(ReadOnlySpan<byte> source, Span<short> f)
		{
			return TKernel.Decode12(source, f);
		}

		internal override void Compress(ReadOnlySpan<short> f, Span<byte> destination, int bits)
		{
			TKernel.Compress(f, destination, bits);
		}

		internal override void Decompress(ReadOnlySpan<byte> source, Span<short> f, int bits)
		{
			TKernel.Decompress(source, f, bits);
		}

		internal override int RejectSample(ReadOnlySpan<byte> source, Span<short> destination)
		{
			return TKernel.RejectSample(source, destination);
		}

		internal override void SampleCbd(ReadOnlySpan<byte> source, Span<short> f, int eta)
		{
			TKernel.SampleCbd(source, f, eta);
		}
	}
}
