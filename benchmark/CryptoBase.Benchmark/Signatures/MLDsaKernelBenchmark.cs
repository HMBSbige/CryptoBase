using BenchmarkDotNet.Attributes;
using CryptoBase.Signatures.MLDsa;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Signatures;

// A kernel the processor lacks throws in Setup and reports no result. The sizes are those of ML-DSA-65 where an
// operation has no parameter of its own.
public class MLDsaKernelBenchmark
{
	private const int N = 256;
	private const int L = 5;
	private const int Q = 8380417;
	private const int Gamma1 = 1 << 19;
	private const int Beta = 196;

	private readonly int[] _polynomial = new int[N];
	private readonly int[] _work = new int[N];
	private readonly int[] _vector = new int[L * N];
	private readonly int[] _otherVector = new int[L * N];
	private readonly int[] _high = new int[N];
	private readonly int[] _low = new int[N];
	private readonly int[] _hint = new int[N];
	private readonly int[] _t1 = new int[N];
	private readonly int[] _t0 = new int[N];
	private readonly int[] _s = new int[N];
	private readonly int[] _z = new int[N];
	private readonly int[] _w1 = new int[N];
	private readonly int[] _output = new int[N];
	private readonly int[] _otherOutput = new int[N];
	private readonly byte[] _matrixStream = RandomNumberGenerator.GetBytes(5 * 168);
	private readonly byte[] _secretStream = RandomNumberGenerator.GetBytes(2 * 136);
	private readonly byte[] _encodedT1 = new byte[320];
	private readonly byte[] _encodedEta2 = new byte[96];
	private readonly byte[] _encodedEta4 = new byte[128];
	private readonly byte[] _encodedZ17 = new byte[576];
	private readonly byte[] _encodedZ19 = new byte[640];
	private readonly byte[] _encoded = new byte[640];
	private IKernel _kernel = new Kernel<MLDsaScalar>();

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
			KernelKind.Scalar => new Kernel<MLDsaScalar>(),
			KernelKind.Vector128 => new Kernel<MLDsaVector128>(),
			KernelKind.Avx2 => new Kernel<MLDsaAvx2>(),
			KernelKind.Avx512 => new Kernel<MLDsaAvx512>(),
			KernelKind.Dispatch => new Kernel<MLDsaKernelDispatch>(),
			_ => throw new ArgumentOutOfRangeException(nameof(Kind))
		};

		if (!_kernel.IsSupported)
		{
			throw new PlatformNotSupportedException($"{Kind} is not supported in this process.");
		}

		Fill(_polynomial, -(Q - 1), Q);
		Fill(_vector, -(Q - 1), Q);
		Fill(_otherVector, -(Q - 1), Q);
		Fill(_hint, 0, 2);
		Fill(_t1, 0, 1 << 10);
		Fill(_t0, -(1 << 12) + 1, (1 << 12) + 1);
		Fill(_s, -2, 3);
		Fill(_z, -(1 << 17) + 1, (1 << 17) + 1);
		Fill(_w1, 0, 16);

		_kernel.Decompose(_polynomial, _high, _low, MLDsaConstants.Gamma2Large);
		_kernel.EncodeT1(_t1, _encodedT1);
		_kernel.EncodeEta(_s, _encodedEta2, 2);
		_kernel.EncodeEta(_s, _encodedEta4, 4);
		_kernel.EncodeZ(_z, _encodedZ17, 17);
		_kernel.EncodeZ(_z, _encodedZ19, 19);
	}

	// Ntt takes |f| < q but leaves up to 9q, so each run transforms a fresh copy; InverseNtt and Reduce keep their input valid.
	[Benchmark]
	public void Ntt()
	{
		_polynomial.CopyTo(_work, 0);
		_kernel.Ntt(_work);
	}

	[Benchmark]
	public void InverseNtt()
	{
		_kernel.InverseNtt(_polynomial);
	}

	// One row of Â ∘ NTT(y).
	[Benchmark]
	public void MultiplyAccumulate()
	{
		_kernel.MultiplyAccumulate(_vector, _otherVector, _output, L);
	}

	[Benchmark]
	public void Reduce()
	{
		_kernel.Reduce(_polynomial);
	}

	[Benchmark]
	public void Add()
	{
		_kernel.Add(_polynomial, _low, _output);
	}

	// z = y + ⟨⟨cs1⟩⟩ reduced and checked against γ1 − β in one pass, and the other fused checks of signing.
	[Benchmark]
	public bool AddReduceExceedsBound()
	{
		return _kernel.AddReduceExceedsBound(_polynomial, _low, _output, Gamma1 - Beta);
	}

	[Benchmark]
	public bool SubtractReduceExceedsBound()
	{
		return _kernel.SubtractReduceExceedsBound(_polynomial, _low, _output, Gamma1 - Beta);
	}

	[Benchmark]
	public bool ReduceExceedsBound()
	{
		return _kernel.ReduceExceedsBound(_polynomial, Gamma1 - Beta);
	}

	// The check of z against γ1 − β.
	[Benchmark]
	public bool ExceedsBound()
	{
		return _kernel.ExceedsBound(_z, Gamma1 - Beta);
	}

	[Benchmark]
	public void Power2Round()
	{
		_kernel.Power2Round(_polynomial, _output, _otherOutput);
	}

	[Benchmark]
	[Arguments(MLDsaConstants.Gamma2Small)]
	[Arguments(MLDsaConstants.Gamma2Large)]
	public void Decompose(int gamma2)
	{
		_kernel.Decompose(_polynomial, _output, _otherOutput, gamma2);
	}

	[Benchmark]
	public int MakeHint()
	{
		return _kernel.MakeHint(_low, _high, _output, MLDsaConstants.Gamma2Large);
	}

	[Benchmark]
	[Arguments(MLDsaConstants.Gamma2Small)]
	[Arguments(MLDsaConstants.Gamma2Large)]
	public void UseHint(int gamma2)
	{
		_kernel.UseHint(_polynomial, _hint, _output, gamma2);
	}

	// The five SHAKE128 blocks that ExpandA squeezes for one polynomial.
	[Benchmark]
	public int RejectSample()
	{
		return _kernel.RejectSample(_matrixStream, _output);
	}

	// The two SHAKE256 blocks that ExpandS squeezes for one polynomial.
	[Benchmark]
	[Arguments(2)]
	[Arguments(4)]
	public int RejectEta(int eta)
	{
		return _kernel.RejectEta(_secretStream, _output, eta);
	}

	[Benchmark]
	public void EncodeT1()
	{
		_kernel.EncodeT1(_t1, _encoded);
	}

	[Benchmark]
	public void DecodeT1()
	{
		_kernel.DecodeT1(_encodedT1, _output);
	}

	[Benchmark]
	public void EncodeT0()
	{
		_kernel.EncodeT0(_t0, _encoded);
	}

	[Benchmark]
	[Arguments(2)]
	[Arguments(4)]
	public void EncodeEta(int eta)
	{
		_kernel.EncodeEta(_s, _encoded, eta);
	}

	[Benchmark]
	[Arguments(2)]
	[Arguments(4)]
	public bool DecodeEta(int eta)
	{
		return _kernel.DecodeEta(eta is 2 ? _encodedEta2 : _encodedEta4, _output, eta);
	}

	[Benchmark]
	[Arguments(17)]
	[Arguments(19)]
	public void EncodeZ(int gamma1Bits)
	{
		_kernel.EncodeZ(_z, _encoded, gamma1Bits);
	}

	[Benchmark]
	[Arguments(17)]
	[Arguments(19)]
	public void DecodeZ(int gamma1Bits)
	{
		_kernel.DecodeZ(gamma1Bits is 17 ? _encodedZ17 : _encodedZ19, _output, gamma1Bits);
	}

	[Benchmark]
	[Arguments(MLDsaConstants.Gamma2Small)]
	[Arguments(MLDsaConstants.Gamma2Large)]
	public void EncodeW1(int gamma2)
	{
		_kernel.EncodeW1(_w1, _encoded, gamma2);
	}

	private static void Fill(int[] values, int minimum, int limit)
	{
		for (int i = 0; i < values.Length; ++i)
		{
			values[i] = RandomNumberGenerator.GetInt32(minimum, limit);
		}
	}

	private interface IKernel
	{
		bool IsSupported { get; }

		void Ntt(Span<int> f);

		void InverseNtt(Span<int> f);

		void MultiplyAccumulate(ReadOnlySpan<int> a, ReadOnlySpan<int> b, Span<int> destination, int count);

		void Reduce(Span<int> f);

		void Add(ReadOnlySpan<int> left, ReadOnlySpan<int> right, Span<int> destination);

		bool ExceedsBound(ReadOnlySpan<int> f, int bound);

		bool AddReduceExceedsBound(ReadOnlySpan<int> left, ReadOnlySpan<int> right, Span<int> destination, int bound);

		bool SubtractReduceExceedsBound(ReadOnlySpan<int> left, ReadOnlySpan<int> right, Span<int> destination, int bound);

		bool ReduceExceedsBound(Span<int> f, int bound);

		void Power2Round(ReadOnlySpan<int> t, Span<int> high, Span<int> low);

		void Decompose(ReadOnlySpan<int> r, Span<int> high, Span<int> low, int gamma2);

		int MakeHint(ReadOnlySpan<int> low, ReadOnlySpan<int> high, Span<int> hint, int gamma2);

		void UseHint(ReadOnlySpan<int> r, ReadOnlySpan<int> hint, Span<int> destination, int gamma2);

		int RejectSample(ReadOnlySpan<byte> source, Span<int> destination);

		int RejectEta(ReadOnlySpan<byte> source, Span<int> destination, int eta);

		void EncodeT1(ReadOnlySpan<int> t1, Span<byte> destination);

		void DecodeT1(ReadOnlySpan<byte> source, Span<int> f);

		void EncodeT0(ReadOnlySpan<int> t0, Span<byte> destination);

		void EncodeEta(ReadOnlySpan<int> s, Span<byte> destination, int eta);

		bool DecodeEta(ReadOnlySpan<byte> source, Span<int> s, int eta);

		void EncodeZ(ReadOnlySpan<int> z, Span<byte> destination, int gamma1Bits);

		void DecodeZ(ReadOnlySpan<byte> source, Span<int> z, int gamma1Bits);

		void EncodeW1(ReadOnlySpan<int> w1, Span<byte> destination, int gamma2);
	}

	private sealed class Kernel<TKernel> : IKernel where TKernel : IMLDsaKernel
	{
		public bool IsSupported => TKernel.IsSupported;

		public void Ntt(Span<int> f)
		{
			TKernel.Ntt(f);
		}

		public void InverseNtt(Span<int> f)
		{
			TKernel.InverseNtt(f);
		}

		public void MultiplyAccumulate(ReadOnlySpan<int> a, ReadOnlySpan<int> b, Span<int> destination, int count)
		{
			TKernel.MultiplyAccumulate(a, b, destination, count);
		}

		public void Reduce(Span<int> f)
		{
			TKernel.Reduce(f);
		}

		public void Add(ReadOnlySpan<int> left, ReadOnlySpan<int> right, Span<int> destination)
		{
			TKernel.Add(left, right, destination);
		}

		public bool ExceedsBound(ReadOnlySpan<int> f, int bound)
		{
			return TKernel.ExceedsBound(f, bound);
		}

		public bool AddReduceExceedsBound(ReadOnlySpan<int> left, ReadOnlySpan<int> right, Span<int> destination, int bound)
		{
			return TKernel.AddReduceExceedsBound(left, right, destination, bound);
		}

		public bool SubtractReduceExceedsBound(ReadOnlySpan<int> left, ReadOnlySpan<int> right, Span<int> destination, int bound)
		{
			return TKernel.SubtractReduceExceedsBound(left, right, destination, bound);
		}

		public bool ReduceExceedsBound(Span<int> f, int bound)
		{
			return TKernel.ReduceExceedsBound(f, bound);
		}

		public void Power2Round(ReadOnlySpan<int> t, Span<int> high, Span<int> low)
		{
			TKernel.Power2Round(t, high, low);
		}

		public void Decompose(ReadOnlySpan<int> r, Span<int> high, Span<int> low, int gamma2)
		{
			TKernel.Decompose(r, high, low, gamma2);
		}

		public int MakeHint(ReadOnlySpan<int> low, ReadOnlySpan<int> high, Span<int> hint, int gamma2)
		{
			return TKernel.MakeHint(low, high, hint, gamma2);
		}

		public void UseHint(ReadOnlySpan<int> r, ReadOnlySpan<int> hint, Span<int> destination, int gamma2)
		{
			TKernel.UseHint(r, hint, destination, gamma2);
		}

		public int RejectSample(ReadOnlySpan<byte> source, Span<int> destination)
		{
			return TKernel.RejectSample(source, destination);
		}

		public int RejectEta(ReadOnlySpan<byte> source, Span<int> destination, int eta)
		{
			return TKernel.RejectEta(source, destination, eta);
		}

		public void EncodeT1(ReadOnlySpan<int> t1, Span<byte> destination)
		{
			TKernel.EncodeT1(t1, destination);
		}

		public void DecodeT1(ReadOnlySpan<byte> source, Span<int> f)
		{
			TKernel.DecodeT1(source, f);
		}

		public void EncodeT0(ReadOnlySpan<int> t0, Span<byte> destination)
		{
			TKernel.EncodeT0(t0, destination);
		}

		public void EncodeEta(ReadOnlySpan<int> s, Span<byte> destination, int eta)
		{
			TKernel.EncodeEta(s, destination, eta);
		}

		public bool DecodeEta(ReadOnlySpan<byte> source, Span<int> s, int eta)
		{
			return TKernel.DecodeEta(source, s, eta);
		}

		public void EncodeZ(ReadOnlySpan<int> z, Span<byte> destination, int gamma1Bits)
		{
			TKernel.EncodeZ(z, destination, gamma1Bits);
		}

		public void DecodeZ(ReadOnlySpan<byte> source, Span<int> z, int gamma1Bits)
		{
			TKernel.DecodeZ(source, z, gamma1Bits);
		}

		public void EncodeW1(ReadOnlySpan<int> w1, Span<byte> destination, int gamma2)
		{
			TKernel.EncodeW1(w1, destination, gamma2);
		}
	}
}
