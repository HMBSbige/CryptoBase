using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using CryptoBase.EllipticCurves;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.EllipticCurves;

// Each operation takes the previous result as an input, as in the point formulas, so the time per operation is its latency.
public class FieldArithmeticBenchmark
{
	private const int Operations = 64;

	private IKernel _kernel = new Kernel<P256Field>();

	public enum ModulusKind
	{
		P256Field,
		P256Order,
		P384Field,
		P521Field
	}

	[ParamsAllValues]
	public ModulusKind Modulus { get; set; }

	[GlobalSetup]
	public void Setup()
	{
		_kernel = Modulus switch
		{
			ModulusKind.P256Field => new Kernel<P256Field>(),
			ModulusKind.P256Order => new Kernel<P256Order>(),
			ModulusKind.P384Field => new Kernel<P384Field>(),
			ModulusKind.P521Field => new Kernel<P521Field>(),
			_ => throw new ArgumentOutOfRangeException(nameof(Modulus))
		};
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void Multiply()
	{
		_kernel.Multiply(Operations);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void Square()
	{
		_kernel.Square(Operations);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void Add()
	{
		_kernel.Add(Operations);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void Subtract()
	{
		_kernel.Subtract(Operations);
	}

	private interface IKernel
	{
		void Multiply(int count);

		void Square(int count);

		void Add(int count);

		void Subtract(int count);
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

		public void Square(int count)
		{
			FieldElement<TModulus> value = _left;

			for (int i = 0; i < count; ++i)
			{
				FieldElement<TModulus>.Square(in value, out value);
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

		public void Subtract(int count)
		{
			FieldElement<TModulus> value = _left;

			for (int i = 0; i < count; ++i)
			{
				FieldElement<TModulus>.Subtract(in value, in _right, out value);
			}

			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in value);
		}
	}
}
