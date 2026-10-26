using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using CryptoBase.EllipticCurves;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.EllipticCurves;

public class FieldElementBenchmark
{
	private IKernel _kernel = new Kernel<P256Order>();

	public enum ModulusKind
	{
		P256Order,
		P384Order,
		P521Order
	}

	[ParamsAllValues]
	public ModulusKind Modulus { get; set; }

	[GlobalSetup]
	public void Setup()
	{
		_kernel = Modulus switch
		{
			ModulusKind.P256Order => new Kernel<P256Order>(),
			ModulusKind.P384Order => new Kernel<P384Order>(),
			ModulusKind.P521Order => new Kernel<P521Order>(),
			_ => throw new ArgumentOutOfRangeException(nameof(Modulus))
		};
	}

	[Benchmark(Baseline = true)]
	public void Invert()
	{
		_kernel.Invert();
	}

	[Benchmark]
	public void InvertVariableTime()
	{
		_kernel.InvertVariableTime();
	}

	private interface IKernel
	{
		void Invert();

		void InvertVariableTime();
	}

	private sealed class Kernel<TModulus> : IKernel where TModulus : struct, IMontgomeryModulus
	{
		// The time of the variable-time inversion depends on the value, so the calls cycle through many.
		private readonly FieldElement<TModulus>[] _values = new FieldElement<TModulus>[64];
		private int _next;

		public Kernel()
		{
			for (int i = 0; i < _values.Length; ++i)
			{
				FieldElement<TModulus>.ImportReduced(RandomNumberGenerator.GetBytes(TModulus.ByteLength), out _values[i]);
			}
		}

		public void Invert()
		{
			FieldElement<TModulus>.Invert(in Next(), out FieldElement<TModulus> result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}

		public void InvertVariableTime()
		{
			FieldElement<TModulus>.InvertVariableTime(in Next(), out FieldElement<TModulus> result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}

		private ref readonly FieldElement<TModulus> Next()
		{
			return ref _values[_next++ & _values.Length - 1];
		}
	}
}
