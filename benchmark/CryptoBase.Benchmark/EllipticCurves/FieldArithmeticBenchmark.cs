using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using CryptoBase.EllipticCurves;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.EllipticCurves;

// Each operation takes the previous result as an input, as in the point formulas, so the time per operation is its latency.
public class FieldArithmeticBenchmark
{
	private const int Operations = 64;

	private IKernel _kernel = new Kernel<P256Order>();

	public enum ModulusKind
	{
		P256Order
	}

	[ParamsAllValues]
	public ModulusKind Modulus { get; set; }

	[GlobalSetup]
	public void Setup()
	{
		_kernel = Modulus switch
		{
			ModulusKind.P256Order => new Kernel<P256Order>(),
			_ => throw new ArgumentOutOfRangeException(nameof(Modulus))
		};
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void Multiply()
	{
		_kernel.Multiply(Operations);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void Add()
	{
		_kernel.Add(Operations);
	}

	private interface IKernel
	{
		void Multiply(int count);

		void Add(int count);
	}

	private sealed class Kernel<TModulus> : IKernel where TModulus : struct, IMontgomeryModulus
	{
		private FieldElement<TModulus> _left;
		private FieldElement<TModulus> _right;

		public Kernel()
		{
			FieldElement<TModulus>.ImportReduced(RandomNumberGenerator.GetBytes(TModulus.ByteLength), out _left);
			FieldElement<TModulus>.ImportReduced(RandomNumberGenerator.GetBytes(TModulus.ByteLength), out _right);
		}

		public void Multiply(int count)
		{
			FieldElement<TModulus> value = _left;

			for (int i = 0; i < count; ++i)
			{
				FieldElement<TModulus>.Multiply(in value, in _right, out value);
			}

			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in value);
		}

		public void Add(int count)
		{
			FieldElement<TModulus> value = _left;

			for (int i = 0; i < count; ++i)
			{
				FieldElement<TModulus>.Add(in value, in _right, out value);
			}

			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in value);
		}
	}
}
