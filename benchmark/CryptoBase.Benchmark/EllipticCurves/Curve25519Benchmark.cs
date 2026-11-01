using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using CryptoBase.EllipticCurves;
using CryptoBase.EllipticCurves.Curve25519;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.EllipticCurves;

// The field operations of Field25519, each taking the previous result as an input, so the time per operation is its latency. The saturated Montgomery product of FieldElement and the constant-time inversion by SafeGcd are there to compare the representations.
public class Curve25519FieldBenchmark
{
	private const int Operations = 64;

	private Field25519 _left;
	private Field25519 _right;
	private FieldElement<Curve25519Modulus> _saturatedLeft;
	private FieldElement<Curve25519Modulus> _saturatedRight;

	[GlobalSetup]
	public void Setup()
	{
		Field25519.FromBytes(RandomNumberGenerator.GetBytes(Field25519.ByteLength), out _left);
		Field25519.FromBytes(RandomNumberGenerator.GetBytes(Field25519.ByteLength), out _right);
		FieldElement<Curve25519Modulus>.ImportReduced(RandomNumberGenerator.GetBytes(Curve25519Modulus.ByteLength), out _saturatedLeft);
		FieldElement<Curve25519Modulus>.ImportReduced(RandomNumberGenerator.GetBytes(Curve25519Modulus.ByteLength), out _saturatedRight);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void Multiply()
	{
		Field25519 value = _left;

		for (int i = 0; i < Operations; ++i)
		{
			Field25519.Multiply(in value, in _right, out value);
		}

		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in value);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void Square()
	{
		Field25519 value = _left;

		for (int i = 0; i < Operations; ++i)
		{
			Field25519.Square(in value, out value);
		}

		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in value);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void MultiplySmall()
	{
		Field25519 value = _left;

		for (int i = 0; i < Operations; ++i)
		{
			Field25519.MultiplySmall(in value, 121665, out value);
		}

		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in value);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void SaturatedMontgomeryMultiply()
	{
		FieldElement<Curve25519Modulus> value = _saturatedLeft;

		for (int i = 0; i < Operations; ++i)
		{
			FieldElement<Curve25519Modulus>.Multiply(in value, in _saturatedRight, out value);
		}

		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in value);
	}

	[Benchmark]
	public void Invert()
	{
		Field25519.Invert(in _left, out Field25519 result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
	}

	// The conversions to and from four 64-bit limbs are part of what an inversion by SafeGcd would cost.
	[Benchmark]
	[SkipLocalsInit]
	public void InvertBySafeGcd()
	{
		Span<ulong> limbs = stackalloc ulong[4];
		Field25519.ToLimbs(in _left, limbs);
		SafeGcd<Curve25519Modulus>.Invert(in Unsafe.As<ulong, FieldElement<Curve25519Modulus>>(ref MemoryMarshal.GetReference(limbs)), Curve25519Modulus.One, out FieldElement<Curve25519Modulus> inverse);
		ReadOnlySpan<ulong> inverseLimbs = FieldElement<Curve25519Modulus>.GetLimbs(in inverse);
		Field25519.FromLimbs(inverseLimbs[0], inverseLimbs[1], inverseLimbs[2], inverseLimbs[3], out Field25519 result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
	}

	[Benchmark]
	public void InvertVariableTime()
	{
		Field25519.InvertVariableTime(in _left, out Field25519 result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
	}

	[Benchmark]
	public ulong SqrtRatio()
	{
		return Field25519.SqrtRatio(in _left, in _right, out _);
	}
}

// The point operations of Edwards25519 and the multiplications of each kernel; a vector kernel adds its own KernelKind.
public class Curve25519KernelBenchmark
{
	private readonly byte[] _scalar = RandomNumberGenerator.GetBytes(32);
	private readonly byte[] _otherScalar = RandomNumberGenerator.GetBytes(32);
	private readonly byte[] _encoded = new byte[Edwards25519.EncodedLength];
	private IKernel _kernel = new Kernel<Curve25519Scalar>();
	private Field25519 _u;
	private EdwardsPoint _point;
	private EdwardsPoint _otherPoint;
	private EdwardsCachedPoint _cached;
	private EdwardsNielsPoint _niels;
	private EdwardsNielsPoint[] _pointTable = [];

	public enum KernelKind
	{
		Scalar,
		Avx2,
		Avx512,
		Sse41,
		Dispatch
	}

	[ParamsAllValues]
	public KernelKind Backend { get; set; }

	[GlobalSetup]
	public void Setup()
	{
		_kernel = Backend switch
		{
			KernelKind.Scalar => new Kernel<Curve25519Scalar>(),
			KernelKind.Avx2 => new Kernel<Curve25519Avx2>(),
			KernelKind.Avx512 => new Kernel<Curve25519Avx512>(),
			KernelKind.Sse41 => new Kernel<Curve25519Sse41>(),
			KernelKind.Dispatch => new Kernel<Curve25519KernelDispatch>(),
			_ => throw new ArgumentOutOfRangeException(nameof(Backend))
		};

		if (!_kernel.IsSupported)
		{
			throw new NotSupportedException($"{Backend} is not supported here.");
		}

		_scalar[0] &= 0xF8;
		_scalar[31] = (byte)(_scalar[31] & 0x7F | 0x40);
		Edwards25519.MultiplyBase(_scalar, out _point);
		Edwards25519.MultiplyBase(_otherScalar, out _otherPoint);
		Edwards25519.Encode(in _point, _encoded);
		Edwards25519.ToMontgomeryU(in _otherPoint, _encoded);
		Field25519.FromBytes(_encoded, out _u);
		Edwards25519.Encode(in _point, _encoded);
		Edwards25519.ToCached(in _otherPoint, out _cached);
		EdwardsNielsPoint[] niels = new EdwardsNielsPoint[1];
		Edwards25519.ToNielsVariableTime([_otherPoint], niels);
		_niels = niels[0];
		_pointTable = EdwardsVariableTimePointTable.Build(in _point);

		if (!TryDecode())
		{
			throw new InvalidOperationException("The encoded point does not decode.");
		}
	}

	[Benchmark]
	public void Ladder()
	{
		_kernel.Ladder(_scalar, in _u);
	}

	[Benchmark]
	public void MultiplyBase()
	{
		_kernel.MultiplyBase(_scalar);
	}

	[Benchmark]
	public void DoubleScalarMultiplyVariableTime()
	{
		_kernel.DoubleScalarMultiplyVariableTime(_scalar, in _point, _otherScalar);
	}

	[Benchmark]
	public void DoubleScalarMultiplyWithTable()
	{
		_kernel.DoubleScalarMultiplyVariableTime(_scalar, _pointTable, _otherScalar);
	}

	[Benchmark]
	public int BuildPointTable()
	{
		return EdwardsVariableTimePointTable.Build(in _point).Length;
	}

	[Benchmark]
	public void Add()
	{
		Edwards25519.Add(in _point, in _cached, out EdwardsCompletedPoint sum);
		Edwards25519.ToExtended(in sum, out EdwardsPoint result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
	}

	[Benchmark]
	public void AddNiels()
	{
		Edwards25519.AddNiels(in _point, in _niels, out EdwardsCompletedPoint sum);
		Edwards25519.ToExtended(in sum, out EdwardsPoint result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
	}

	[Benchmark]
	public void Double()
	{
		Edwards25519.Double(in _point, out EdwardsPoint result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
	}

	[Benchmark]
	public bool TryDecode()
	{
		bool decoded = Edwards25519.TryDecode(_encoded, out EdwardsPoint result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		return decoded;
	}

	[Benchmark]
	public void Encode()
	{
		Edwards25519.Encode(in _point, _encoded);
	}

	[Benchmark]
	public void EncodeVariableTime()
	{
		Edwards25519.EncodeVariableTime(in _point, _encoded);
	}

	private interface IKernel
	{
		bool IsSupported { get; }

		void Ladder(ReadOnlySpan<byte> scalar, in Field25519 u);

		void MultiplyBase(ReadOnlySpan<byte> scalar);

		void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, in EdwardsPoint point, ReadOnlySpan<byte> b);

		void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, ReadOnlySpan<EdwardsNielsPoint> pointTable, ReadOnlySpan<byte> b);
	}

	private sealed class Kernel<TKernel> : IKernel where TKernel : ICurve25519Kernel
	{
		public bool IsSupported => TKernel.IsSupported;

		public void Ladder(ReadOnlySpan<byte> scalar, in Field25519 u)
		{
			TKernel.Ladder(scalar, in u, out Field25519 x, out Field25519 z);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in x);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in z);
		}

		public void MultiplyBase(ReadOnlySpan<byte> scalar)
		{
			TKernel.MultiplyBase(scalar, out EdwardsPoint result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}

		public void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, in EdwardsPoint point, ReadOnlySpan<byte> b)
		{
			TKernel.DoubleScalarMultiplyVariableTime(a, in point, b, out EdwardsPoint result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}

		public void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, ReadOnlySpan<EdwardsNielsPoint> pointTable, ReadOnlySpan<byte> b)
		{
			TKernel.DoubleScalarMultiplyVariableTime(a, pointTable, b, out EdwardsPoint result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}
	}
}
