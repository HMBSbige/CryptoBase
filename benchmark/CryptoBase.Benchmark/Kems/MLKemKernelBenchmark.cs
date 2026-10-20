using BenchmarkDotNet.Attributes;
using CryptoBase.Hashes.Sha3;
using CryptoBase.Kems.MLKem;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Kems;

// A kernel the processor lacks throws in Setup and reports no result.
public class MLKemKernelBenchmark
{
	private const int N = 256;
	private const int K = 3;
	private const int Q = 3329;

	private readonly short[] _polynomial = new short[N];
	private readonly short[] _vector = new short[K * N];
	private readonly short[] _otherVector = new short[K * N];
	private readonly short[] _sum = new short[N];
	private readonly byte[] _seed = RandomNumberGenerator.GetBytes(34);
	private readonly byte[] _cbdSource = RandomNumberGenerator.GetBytes(64 * 3);
	private readonly byte[] _encoded = new byte[384];
	private readonly byte[] _compressed = new byte[32 * 11];
	private IKernel _kernel = new Kernel<MLKemScalar>();

	public enum KernelKind
	{
		Scalar,
		Vector128,
		Avx2,
		Avx512,
		Dispatch
	}

	[ParamsAllValues]
	public KernelKind Kind { get; set; }

	[GlobalSetup]
	public void Setup()
	{
		_kernel = Kind switch
		{
			KernelKind.Scalar => new Kernel<MLKemScalar>(),
			KernelKind.Vector128 => new Kernel<MLKemVector128>(),
			KernelKind.Avx2 => new Kernel<MLKemAvx2>(),
			KernelKind.Avx512 => new Kernel<MLKemAvx512>(),
			KernelKind.Dispatch => new Kernel<MLKemKernelDispatch>(),
			_ => throw new ArgumentOutOfRangeException(nameof(Kind))
		};

		if (!_kernel.IsSupported)
		{
			throw new PlatformNotSupportedException($"{Kind} is not supported in this process.");
		}

		foreach (short[] polynomials in (short[][])[_polynomial, _vector, _otherVector])
		{
			for (int i = 0; i < polynomials.Length; ++i)
			{
				polynomials[i] = (short)(RandomNumberGenerator.GetInt32(2 * Q - 1) - (Q - 1));
			}
		}

		_kernel.Encode12(_polynomial, _encoded);
		_kernel.Compress(_polynomial, _compressed, 11);
	}

	// Both transforms keep |f| < q, so the polynomial stays a valid input however often they run.
	[Benchmark]
	public void Ntt()
	{
		_kernel.Ntt(_polynomial);
	}

	[Benchmark]
	public void InverseNtt()
	{
		_kernel.InverseNtt(_polynomial);
	}

	// One row of Â^T ∘ ŷ for ML-KEM-768.
	[Benchmark]
	public void MultiplyAccumulate()
	{
		_kernel.MultiplyAccumulate(_vector, N, _otherVector, _sum, K);
	}

	[Benchmark]
	public void Reduce()
	{
		_kernel.Reduce(_polynomial);
	}

	[Benchmark]
	public void Encode12()
	{
		_kernel.Encode12(_polynomial, _encoded);
	}

	[Benchmark]
	public bool Decode12()
	{
		return _kernel.Decode12(_encoded, _sum);
	}

	[Benchmark]
	[Arguments(1)]
	[Arguments(4)]
	[Arguments(5)]
	[Arguments(10)]
	[Arguments(11)]
	public void Compress(int bits)
	{
		_kernel.Compress(_polynomial, _compressed, bits);
	}

	[Benchmark]
	[Arguments(1)]
	[Arguments(4)]
	[Arguments(5)]
	[Arguments(10)]
	[Arguments(11)]
	public void Decompress(int bits)
	{
		_kernel.Decompress(_compressed, _sum, bits);
	}

	// One polynomial of Â: SHAKE128(ρ ‖ j ‖ i) squeezed one block at a time until 256 coefficients are accepted.
	[Benchmark]
	public void SampleNtt()
	{
		Span<byte> block = stackalloc byte[KeccakRate168.RateInBytes];
		KeccakSponge<KeccakRate168> sponge = default;
		sponge.Absorb(_seed);
		sponge.Pad(KeccakDomainSeparator.Shake);

		for (int sampled = 0; sampled < N;)
		{
			sponge.Squeeze(block);
			sampled += _kernel.RejectSample(block, _sum.AsSpan(sampled));
		}
	}

	[Benchmark]
	[Arguments(2)]
	[Arguments(3)]
	public void SampleCbd(int eta)
	{
		_kernel.SampleCbd(_cbdSource.AsSpan(0, 64 * eta), _sum, eta);
	}

	private interface IKernel
	{
		bool IsSupported { get; }

		void Ntt(Span<short> f);

		void InverseNtt(Span<short> f);

		void MultiplyAccumulate(ReadOnlySpan<short> a, int aStride, ReadOnlySpan<short> b, Span<short> destination, int count);

		void Reduce(Span<short> f);

		void Encode12(ReadOnlySpan<short> f, Span<byte> destination);

		bool Decode12(ReadOnlySpan<byte> source, Span<short> f);

		void Compress(ReadOnlySpan<short> f, Span<byte> destination, int bits);

		void Decompress(ReadOnlySpan<byte> source, Span<short> f, int bits);

		int RejectSample(ReadOnlySpan<byte> source, Span<short> destination);

		void SampleCbd(ReadOnlySpan<byte> source, Span<short> f, int eta);
	}

	private sealed class Kernel<TKernel> : IKernel where TKernel : IMLKemKernel
	{
		public bool IsSupported => TKernel.IsSupported;

		public void Ntt(Span<short> f)
		{
			TKernel.Ntt(f);
		}

		public void InverseNtt(Span<short> f)
		{
			TKernel.InverseNtt(f);
		}

		public void MultiplyAccumulate(ReadOnlySpan<short> a, int aStride, ReadOnlySpan<short> b, Span<short> destination, int count)
		{
			TKernel.MultiplyAccumulate(a, aStride, b, destination, count);
		}

		public void Reduce(Span<short> f)
		{
			TKernel.Reduce(f);
		}

		public void Encode12(ReadOnlySpan<short> f, Span<byte> destination)
		{
			TKernel.Encode12(f, destination);
		}

		public bool Decode12(ReadOnlySpan<byte> source, Span<short> f)
		{
			return TKernel.Decode12(source, f);
		}

		public void Compress(ReadOnlySpan<short> f, Span<byte> destination, int bits)
		{
			TKernel.Compress(f, destination, bits);
		}

		public void Decompress(ReadOnlySpan<byte> source, Span<short> f, int bits)
		{
			TKernel.Decompress(source, f, bits);
		}

		public int RejectSample(ReadOnlySpan<byte> source, Span<short> destination)
		{
			return TKernel.RejectSample(source, destination);
		}

		public void SampleCbd(ReadOnlySpan<byte> source, Span<short> f, int eta)
		{
			TKernel.SampleCbd(source, f, eta);
		}
	}
}
