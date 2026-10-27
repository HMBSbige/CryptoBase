using CryptoBase.Signatures.MLDsa;

namespace CryptoBase.Tests.Signatures.MLDsa;

public abstract class MLDsaKernelCase : IKernelCase
{
	public static IEnumerable<MLDsaKernelCase> All()
	{
		yield return new Kernel<MLDsaScalar>();
		yield return new Kernel<MLDsaVector128>();
		yield return new Kernel<MLDsaAvx2>();
		yield return new Kernel<MLDsaAvx512>();
		yield return new Kernel<MLDsaKernelDispatch>();
	}

	public abstract Type KernelType { get; }

	public abstract bool IsSupported { get; }

	internal abstract void Ntt(Span<int> f);

	internal abstract void InverseNtt(Span<int> f);

	internal abstract void MultiplyAccumulate(ReadOnlySpan<int> a, ReadOnlySpan<int> b, Span<int> destination, int count);

	internal abstract void Reduce(Span<int> f);

	internal abstract void Add(ReadOnlySpan<int> left, ReadOnlySpan<int> right, Span<int> destination);

	internal abstract bool ExceedsBound(ReadOnlySpan<int> f, int bound);

	internal abstract bool AddReduceExceedsBound(ReadOnlySpan<int> left, ReadOnlySpan<int> right, Span<int> destination, int bound);

	internal abstract bool SubtractReduceExceedsBound(ReadOnlySpan<int> left, ReadOnlySpan<int> right, Span<int> destination, int bound);

	internal abstract bool ReduceExceedsBound(Span<int> f, int bound);

	internal abstract void Power2Round(ReadOnlySpan<int> t, Span<int> high, Span<int> low);

	internal abstract void Decompose(ReadOnlySpan<int> r, Span<int> high, Span<int> low, int gamma2);

	internal abstract int MakeHint(ReadOnlySpan<int> low, ReadOnlySpan<int> high, Span<int> hint, int gamma2);

	internal abstract void UseHint(ReadOnlySpan<int> r, ReadOnlySpan<int> hint, Span<int> destination, int gamma2);

	internal abstract int RejectSample(ReadOnlySpan<byte> source, Span<int> destination);

	internal abstract int RejectEta(ReadOnlySpan<byte> source, Span<int> destination, int eta);

	internal abstract void EncodeT1(ReadOnlySpan<int> t1, Span<byte> destination);

	internal abstract void DecodeT1(ReadOnlySpan<byte> source, Span<int> f);

	internal abstract void EncodeT0(ReadOnlySpan<int> t0, Span<byte> destination);

	internal abstract void EncodeEta(ReadOnlySpan<int> s, Span<byte> destination, int eta);

	internal abstract bool DecodeEta(ReadOnlySpan<byte> source, Span<int> s, int eta);

	internal abstract void EncodeZ(ReadOnlySpan<int> z, Span<byte> destination, int gamma1Bits);

	internal abstract void DecodeZ(ReadOnlySpan<byte> source, Span<int> z, int gamma1Bits);

	internal abstract void EncodeW1(ReadOnlySpan<int> w1, Span<byte> destination, int gamma2);

	public override string ToString()
	{
		return KernelType.Name;
	}

	private sealed class Kernel<TKernel> : MLDsaKernelCase where TKernel : IMLDsaKernel
	{
		public override Type KernelType => typeof(TKernel);

		public override bool IsSupported => TKernel.IsSupported;

		internal override void Ntt(Span<int> f)
		{
			TKernel.Ntt(f);
		}

		internal override void InverseNtt(Span<int> f)
		{
			TKernel.InverseNtt(f);
		}

		internal override void MultiplyAccumulate(ReadOnlySpan<int> a, ReadOnlySpan<int> b, Span<int> destination, int count)
		{
			TKernel.MultiplyAccumulate(a, b, destination, count);
		}

		internal override void Reduce(Span<int> f)
		{
			TKernel.Reduce(f);
		}

		internal override void Add(ReadOnlySpan<int> left, ReadOnlySpan<int> right, Span<int> destination)
		{
			TKernel.Add(left, right, destination);
		}

		internal override bool ExceedsBound(ReadOnlySpan<int> f, int bound)
		{
			return TKernel.ExceedsBound(f, bound);
		}

		internal override bool AddReduceExceedsBound(ReadOnlySpan<int> left, ReadOnlySpan<int> right, Span<int> destination, int bound)
		{
			return TKernel.AddReduceExceedsBound(left, right, destination, bound);
		}

		internal override bool SubtractReduceExceedsBound(ReadOnlySpan<int> left, ReadOnlySpan<int> right, Span<int> destination, int bound)
		{
			return TKernel.SubtractReduceExceedsBound(left, right, destination, bound);
		}

		internal override bool ReduceExceedsBound(Span<int> f, int bound)
		{
			return TKernel.ReduceExceedsBound(f, bound);
		}

		internal override void Power2Round(ReadOnlySpan<int> t, Span<int> high, Span<int> low)
		{
			TKernel.Power2Round(t, high, low);
		}

		internal override void Decompose(ReadOnlySpan<int> r, Span<int> high, Span<int> low, int gamma2)
		{
			TKernel.Decompose(r, high, low, gamma2);
		}

		internal override int MakeHint(ReadOnlySpan<int> low, ReadOnlySpan<int> high, Span<int> hint, int gamma2)
		{
			return TKernel.MakeHint(low, high, hint, gamma2);
		}

		internal override void UseHint(ReadOnlySpan<int> r, ReadOnlySpan<int> hint, Span<int> destination, int gamma2)
		{
			TKernel.UseHint(r, hint, destination, gamma2);
		}

		internal override int RejectSample(ReadOnlySpan<byte> source, Span<int> destination)
		{
			return TKernel.RejectSample(source, destination);
		}

		internal override int RejectEta(ReadOnlySpan<byte> source, Span<int> destination, int eta)
		{
			return TKernel.RejectEta(source, destination, eta);
		}

		internal override void EncodeT1(ReadOnlySpan<int> t1, Span<byte> destination)
		{
			TKernel.EncodeT1(t1, destination);
		}

		internal override void DecodeT1(ReadOnlySpan<byte> source, Span<int> f)
		{
			TKernel.DecodeT1(source, f);
		}

		internal override void EncodeT0(ReadOnlySpan<int> t0, Span<byte> destination)
		{
			TKernel.EncodeT0(t0, destination);
		}

		internal override void EncodeEta(ReadOnlySpan<int> s, Span<byte> destination, int eta)
		{
			TKernel.EncodeEta(s, destination, eta);
		}

		internal override bool DecodeEta(ReadOnlySpan<byte> source, Span<int> s, int eta)
		{
			return TKernel.DecodeEta(source, s, eta);
		}

		internal override void EncodeZ(ReadOnlySpan<int> z, Span<byte> destination, int gamma1Bits)
		{
			TKernel.EncodeZ(z, destination, gamma1Bits);
		}

		internal override void DecodeZ(ReadOnlySpan<byte> source, Span<int> z, int gamma1Bits)
		{
			TKernel.DecodeZ(source, z, gamma1Bits);
		}

		internal override void EncodeW1(ReadOnlySpan<int> w1, Span<byte> destination, int gamma2)
		{
			TKernel.EncodeW1(w1, destination, gamma2);
		}
	}
}
