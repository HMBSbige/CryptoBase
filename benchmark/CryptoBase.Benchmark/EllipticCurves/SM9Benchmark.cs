using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using CryptoBase.EllipticCurves;
using CryptoBase.EllipticCurves.SM9;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.EllipticCurves;

// The field operations of SM9, each taking the previous result as an input, so the time per operation is its latency.
public class SM9FieldBenchmark
{
	private const int Operations = 64;

	private SM9Fp _left;
	private SM9Fp _right;
	private SM9Fp2 _left2;
	private SM9Fp2 _right2;
	private SM9Fp12 _left12;
	private SM9Fp12 _right12;
	private SM9Fp12 _cyclotomic;
	private SM9Line _line;

	[GlobalSetup]
	public void Setup()
	{
		_left = Random();
		_right = Random();
		_left2 = new SM9Fp2 { A0 = Random(), A1 = Random() };
		_right2 = new SM9Fp2 { A0 = Random(), A1 = Random() };
		_left12 = Random12();
		_right12 = Random12();
		_line = new SM9Line { L0 = _left2, L2 = _right2, L3 = _left2 };
		SM9Pairing.Pair(in SM9G1.Generator, in SM9G2.Generator, out _cyclotomic);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void FpMultiply()
	{
		SM9Fp value = _left;

		for (int i = 0; i < Operations; ++i)
		{
			SM9Fp.Multiply(in value, in _right, out value);
		}

		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in value);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void FpSquare()
	{
		SM9Fp value = _left;

		for (int i = 0; i < Operations; ++i)
		{
			SM9Fp.Square(in value, out value);
		}

		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in value);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void Fp2Multiply()
	{
		SM9Fp2 value = _left2;

		for (int i = 0; i < Operations; ++i)
		{
			SM9Fp2.Multiply(in value, in _right2, out value);
		}

		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in value);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void Fp2Square()
	{
		SM9Fp2 value = _left2;

		for (int i = 0; i < Operations; ++i)
		{
			SM9Fp2.Square(in value, out value);
		}

		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in value);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void Fp12Multiply()
	{
		SM9Fp12 value = _left12;

		for (int i = 0; i < Operations; ++i)
		{
			SM9Fp12.Multiply(in value, in _right12, out value);
		}

		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in value);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void Fp12Square()
	{
		SM9Fp12 value = _left12;

		for (int i = 0; i < Operations; ++i)
		{
			SM9Fp12.Square(in value, out value);
		}

		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in value);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void Fp12CyclotomicSquare()
	{
		SM9Fp12 value = _cyclotomic;

		for (int i = 0; i < Operations; ++i)
		{
			SM9Fp12.CyclotomicSquare(in value, out value);
		}

		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in value);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void Fp12MultiplyByLine()
	{
		SM9Fp12 value = _left12;

		for (int i = 0; i < Operations; ++i)
		{
			SM9Fp12.MultiplyByLine(in value, in _line.L0, in _line.L2, in _line.L3, out value);
		}

		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in value);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void Fp12MultiplyByNormalizedLine()
	{
		SM9Fp12 value = _left12;

		for (int i = 0; i < Operations; ++i)
		{
			SM9Fp12.MultiplyByNormalizedLine(in value, in _line.L0, in _line.L2, out value);
		}

		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in value);
	}

	[Benchmark]
	public void FpInvert()
	{
		SM9Fp.Invert(in _left, out SM9Fp result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
	}

	private static SM9Fp Random()
	{
		SM9Fp.TryImport(RandomNumberGenerator.GetBytes(SM9Fp.ByteLength).AsSpan(), out SM9Fp value);
		value.L4 &= 0x7FFFFFFFFFFF;
		return value;
	}

	private static SM9Fp12 Random12()
	{
		SM9Fp12 value = default;
		value.C0.C0 = new SM9Fp2 { A0 = Random(), A1 = Random() };
		value.C0.C1 = new SM9Fp2 { A0 = Random(), A1 = Random() };
		value.C0.C2 = new SM9Fp2 { A0 = Random(), A1 = Random() };
		value.C1.C0 = new SM9Fp2 { A0 = Random(), A1 = Random() };
		value.C1.C1 = new SM9Fp2 { A0 = Random(), A1 = Random() };
		value.C1.C2 = new SM9Fp2 { A0 = Random(), A1 = Random() };
		return value;
	}
}

public class SM9Benchmark
{
	private FieldElement<SM9Order> _scalar;
	private SM9AffinePoint<SM9Fp> _p;
	private SM9AffinePoint<SM9Fp2> _q;
	private SM9Fp12 _g;
	private SM9Fp12 _f;
	private SM9PairingLines _lines = null!;
	private SM9GTTable _table = null!;
	private SM9BaseTable<SM9Fp> _pointTable = null!;
	private byte[] _encodedQ = [];

	[GlobalSetup]
	public void Setup()
	{
		FieldElement<SM9Order>.ImportReduced(RandomNumberGenerator.GetBytes(32), out _scalar);
		FieldElement<SM9Order>.ImportReduced(RandomNumberGenerator.GetBytes(32), out FieldElement<SM9Order> a);
		FieldElement<SM9Order>.ImportReduced(RandomNumberGenerator.GetBytes(32), out FieldElement<SM9Order> b);
		SM9G1.MultiplyBase(in a, out _p);
		SM9G2.MultiplyBase(in b, out _q);
		SM9Pairing.Pair(in _p, in _q, out _g);
		SM9KernelDispatch.MillerLoop(in _p, in _q, out _f);
		_lines = new SM9PairingLines(in _q);
		_table = new SM9GTTable(in _g);
		_pointTable = new SM9BaseTable<SM9Fp>(in _p, 5);
		_encodedQ = new byte[SM9G2.EncodedLength];
		SM9G2.Encode(in _q, _encodedQ);
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_lines.Dispose();
		_table.Dispose();
	}

	[Benchmark]
	public void Pairing()
	{
		SM9Pairing.Pair(in _p, in _q, out SM9Fp12 result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
	}

	[Benchmark]
	public void PairingWithLines()
	{
		_lines.PairVariableTime(in _p, out SM9Fp12 result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
	}

	[Benchmark]
	public void MillerLoop()
	{
		SM9KernelDispatch.MillerLoop(in _p, in _q, out SM9Fp12 result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
	}

	[Benchmark]
	public void FinalExponentiation()
	{
		SM9KernelDispatch.FinalExponentiation(in _f, out SM9Fp12 result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
	}

	[Benchmark]
	public void GTPower()
	{
		SM9GT.Power(in _g, in _scalar, out SM9Fp12 result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
	}

	[Benchmark]
	public void GTPowerWithTable()
	{
		_table.Power(in _scalar, out SM9Fp12 result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
	}

	[Benchmark]
	public void G1MultiplyBase()
	{
		SM9G1.MultiplyBase(in _scalar, out SM9AffinePoint<SM9Fp> result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
	}

	[Benchmark]
	public void G1Multiply()
	{
		SM9G1.Multiply(in _p, in _scalar, out SM9AffinePoint<SM9Fp> result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
	}

	[Benchmark]
	public void G1MultiplyFixed()
	{
		SM9G1.Multiply(_pointTable, in _scalar, out SM9AffinePoint<SM9Fp> result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
	}

	[Benchmark]
	public ulong G1MultiplyBaseSum()
	{
		return SM9G1.MultiplyBaseSum(in _scalar, in _p, _pointTable, in _scalar, out _);
	}

	[Benchmark]
	public int G1BuildTable()
	{
		return new SM9BaseTable<SM9Fp>(in _p, 5).WindowCount;
	}

	[Benchmark]
	public int G1BuildSecretTable()
	{
		return new SM9BaseTable<SM9Fp>(in _p, 5, true).WindowCount;
	}

	[Benchmark]
	public bool G1MultiplyBaseAddVariableTime()
	{
		return SM9G1.MultiplyBaseAddVariableTime(in _scalar, in _p, out SM9AffinePoint<SM9Fp> _);
	}

	[Benchmark]
	public void G2MultiplyBase()
	{
		SM9G2.MultiplyBase(in _scalar, out SM9AffinePoint<SM9Fp2> result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
	}

	[Benchmark]
	public bool G2MultiplyBaseAddVariableTime()
	{
		return SM9G2.MultiplyBaseAddVariableTime(in _scalar, in _q, out _);
	}

	[Benchmark]
	public bool G2Decode()
	{
		return SM9G2.TryDecode(_encodedQ, out _);
	}
}
