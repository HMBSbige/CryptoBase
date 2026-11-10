using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using CryptoBase.EllipticCurves;
using CryptoBase.EllipticCurves.SM9;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.EllipticCurves;

// The heavy operations of SM9 through each kernel of ISM9Kernel, on random secrets, so that the kernels compare in one process. A kernel adds its own KernelKind; one the CPU lacks fails its setup.
public class SM9KernelBenchmark
{
	private IKernel _kernel = new Kernel<SM9Scalar>();
	private FieldElement<SM9Order> _scalar;
	private SM9AffinePoint<SM9Fp> _p;
	private SM9AffinePoint<SM9Fp2> _q;
	private SM9Fp12 _g;
	private SM9Fp12 _f;
	private SM9PrecomputedLine[] _lines = [];
	private SM9Fp12[] _table = [];
	private SM9Fp12 _inverse;
	private SM9Point<SM9Fp> _addendG1;
	private SM9Point<SM9Fp2> _addendG2;
	private SM9BaseTable<SM9Fp> _pointTable = null!;

	public enum KernelKind
	{
		Scalar,
		Avx512,
		Avx2,
		Sse41,
		AdvSimd
	}

	[ParamsAllValues]
	public KernelKind Backend { get; set; }

	[GlobalSetup]
	public void Setup()
	{
		_kernel = Backend switch
		{
			KernelKind.Scalar => new Kernel<SM9Scalar>(),
			KernelKind.Avx512 => new Kernel<SM9VectorKernel<SM9VectorAvx512>>(),
			KernelKind.Avx2 => new Kernel<SM9VectorKernel<SM9VectorAvx2>>(),
			KernelKind.Sse41 => new Kernel<SM9VectorKernel<SM9VectorSse41>>(),
			KernelKind.AdvSimd => new Kernel<SM9AdvSimd>(),
			_ => throw new ArgumentOutOfRangeException(nameof(Backend))
		};

		if (!_kernel.IsSupported)
		{
			throw new NotSupportedException($"{Backend} is not supported here.");
		}

		FieldElement<SM9Order>.ImportReduced(RandomNumberGenerator.GetBytes(32), out _scalar);
		FieldElement<SM9Order>.ImportReduced(RandomNumberGenerator.GetBytes(32), out FieldElement<SM9Order> a);
		FieldElement<SM9Order>.ImportReduced(RandomNumberGenerator.GetBytes(32), out FieldElement<SM9Order> b);
		SM9G1.MultiplyBase(in a, out _p);
		SM9G2.MultiplyBase(in b, out _q);
		SM9Scalar.MillerLoop(in _p, in _q, out _f);
		SM9Scalar.FinalExponentiation(in _f, out _g);
		_lines = new SM9PrecomputedLine[SM9MillerLoop.LineCount];
		SM9MillerLoop.Precompute(in _q, _lines);
		_table = new SM9Fp12[SM9GTPower.FixedTableLength];
		SM9GTPower.BuildFixedTable(in _g, _table, out _inverse);
		SM9Curve<SM9Fp>.FromAffine(in _p, out _addendG1);
		SM9Curve<SM9Fp2>.FromAffine(in _q, out _addendG2);
		_pointTable = new SM9BaseTable<SM9Fp>(in _p, 5);
	}

	[Benchmark]
	public void MillerLoop()
	{
		_kernel.MillerLoop(in _p, in _q, out SM9Fp12 result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
	}

	[Benchmark]
	public void MillerLoopWithLines()
	{
		_kernel.MillerLoop(in _p, _lines, out SM9Fp12 result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
	}

	[Benchmark]
	public void FinalExponentiation()
	{
		_kernel.FinalExponentiation(in _f, out SM9Fp12 result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
	}

	[Benchmark]
	public void Power()
	{
		_kernel.Power(in _g, in _scalar, out SM9Fp12 result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
	}

	[Benchmark]
	public void PowerWithTable()
	{
		_kernel.Power(_table, in _inverse, in _scalar, out SM9Fp12 result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
	}

	[Benchmark]
	public void MultiplyBaseG1()
	{
		_kernel.MultiplyBaseG1(SM9G1Group.BaseTable, in _scalar, out SM9Point<SM9Fp> result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
	}

	[Benchmark]
	public void MultiplyFixedG1()
	{
		_kernel.MultiplyBaseG1(_pointTable, in _scalar, out SM9Point<SM9Fp> result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
	}

	[Benchmark]
	public void MultiplyBaseSumG1()
	{
		_kernel.MultiplyBaseSumG1(SM9G1Group.BaseTable, in _scalar, _pointTable, in _scalar, out SM9Point<SM9Fp> result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
	}

	[Benchmark]
	public void MultiplyG1()
	{
		_kernel.MultiplyG1(in _p, in _scalar, out SM9Point<SM9Fp> result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
	}

	[Benchmark]
	public void MultiplyVariableTimeG1()
	{
		_kernel.MultiplyVariableTimeG1(in _p, in _scalar, out SM9Point<SM9Fp> result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
	}

	[Benchmark]
	public void MultiplyBaseAddVariableTimeG1()
	{
		_kernel.MultiplyBaseAddVariableTimeG1(in _scalar, in _addendG1, out SM9Point<SM9Fp> result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
	}

	[Benchmark]
	public void MultiplyBaseG2()
	{
		_kernel.MultiplyBaseG2(in _scalar, out SM9Point<SM9Fp2> result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
	}

	[Benchmark]
	public void MultiplyBaseAddVariableTimeG2()
	{
		_kernel.MultiplyBaseAddVariableTimeG2(in _scalar, in _addendG2, out SM9Point<SM9Fp2> result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
	}

	private interface IKernel
	{
		bool IsSupported { get; }

		void MillerLoop(in SM9AffinePoint<SM9Fp> p, in SM9AffinePoint<SM9Fp2> q, out SM9Fp12 result);

		void MillerLoop(in SM9AffinePoint<SM9Fp> p, ReadOnlySpan<SM9PrecomputedLine> lines, out SM9Fp12 result);

		void FinalExponentiation(in SM9Fp12 value, out SM9Fp12 result);

		void Power(in SM9Fp12 value, in FieldElement<SM9Order> exponent, out SM9Fp12 result);

		void Power(ReadOnlySpan<SM9Fp12> table, in SM9Fp12 inverse, in FieldElement<SM9Order> exponent, out SM9Fp12 result);

		void MultiplyBaseG1(SM9BaseTable<SM9Fp> table, in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp> result);

		void MultiplyBaseSumG1(SM9BaseTable<SM9Fp> first, in FieldElement<SM9Order> firstScalar, SM9BaseTable<SM9Fp> second, in FieldElement<SM9Order> secondScalar, out SM9Point<SM9Fp> result);

		void MultiplyG1(in SM9AffinePoint<SM9Fp> point, in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp> result);

		void MultiplyVariableTimeG1(in SM9AffinePoint<SM9Fp> point, in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp> result);

		void MultiplyBaseAddVariableTimeG1(in FieldElement<SM9Order> scalar, in SM9Point<SM9Fp> addend, out SM9Point<SM9Fp> result);

		void MultiplyBaseG2(in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp2> result);

		void MultiplyBaseAddVariableTimeG2(in FieldElement<SM9Order> scalar, in SM9Point<SM9Fp2> addend, out SM9Point<SM9Fp2> result);
	}

	private sealed class Kernel<TKernel> : IKernel where TKernel : ISM9Kernel
	{
		public bool IsSupported => TKernel.IsSupported;

		public void MillerLoop(in SM9AffinePoint<SM9Fp> p, in SM9AffinePoint<SM9Fp2> q, out SM9Fp12 result)
		{
			TKernel.MillerLoop(in p, in q, out result);
		}

		public void MillerLoop(in SM9AffinePoint<SM9Fp> p, ReadOnlySpan<SM9PrecomputedLine> lines, out SM9Fp12 result)
		{
			SM9MillerLoop.FactorsVariableTime(in p, out SM9Fp alpha, out SM9Fp beta);
			TKernel.MillerLoop(in alpha, in beta, lines, out result);
		}

		public void FinalExponentiation(in SM9Fp12 value, out SM9Fp12 result)
		{
			TKernel.FinalExponentiation(in value, out result);
		}

		public void Power(in SM9Fp12 value, in FieldElement<SM9Order> exponent, out SM9Fp12 result)
		{
			TKernel.Power(in value, in exponent, out result);
		}

		public void Power(ReadOnlySpan<SM9Fp12> table, in SM9Fp12 inverse, in FieldElement<SM9Order> exponent, out SM9Fp12 result)
		{
			TKernel.Power(table, in inverse, in exponent, out result);
		}

		public void MultiplyBaseG1(SM9BaseTable<SM9Fp> table, in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp> result)
		{
			TKernel.MultiplyBaseG1(table, in scalar, out result);
		}

		public void MultiplyBaseSumG1(SM9BaseTable<SM9Fp> first, in FieldElement<SM9Order> firstScalar, SM9BaseTable<SM9Fp> second, in FieldElement<SM9Order> secondScalar, out SM9Point<SM9Fp> result)
		{
			TKernel.MultiplyBaseSumG1(first, in firstScalar, second, in secondScalar, out result);
		}

		public void MultiplyG1(in SM9AffinePoint<SM9Fp> point, in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp> result)
		{
			TKernel.MultiplyG1(in point, in scalar, out result);
		}

		public void MultiplyVariableTimeG1(in SM9AffinePoint<SM9Fp> point, in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp> result)
		{
			TKernel.MultiplyVariableTimeG1(in point, in scalar, out result);
		}

		public void MultiplyBaseAddVariableTimeG1(in FieldElement<SM9Order> scalar, in SM9Point<SM9Fp> addend, out SM9Point<SM9Fp> result)
		{
			TKernel.MultiplyBaseAddVariableTimeG1(in scalar, in addend, out result);
		}

		public void MultiplyBaseG2(in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp2> result)
		{
			TKernel.MultiplyBaseG2(in scalar, out result);
		}

		public void MultiplyBaseAddVariableTimeG2(in FieldElement<SM9Order> scalar, in SM9Point<SM9Fp2> addend, out SM9Point<SM9Fp2> result)
		{
			TKernel.MultiplyBaseAddVariableTimeG2(in scalar, in addend, out result);
		}
	}
}
