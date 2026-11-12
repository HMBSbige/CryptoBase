using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using CryptoBase.EllipticCurves.Curve448;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.EllipticCurves;

// The field operations of Field448, each taking the previous result as an input, so the time per operation is its latency. InvertByPower, value^(p − 2), is there to compare with Invert by SafeGcd.
public class Curve448FieldBenchmark
{
	private const int Operations = 64;

	private Field448 _left;
	private Field448 _right;

	[GlobalSetup]
	public void Setup()
	{
		Field448.FromBytes(RandomNumberGenerator.GetBytes(Field448.ByteLength), out _left);
		Field448.FromBytes(RandomNumberGenerator.GetBytes(Field448.ByteLength), out _right);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void Multiply()
	{
		Field448 value = _left;

		for (int i = 0; i < Operations; ++i)
		{
			Field448.Multiply(in value, in _right, out value);
		}

		DeadCodeEliminationHelper.KeepAliveWithoutBoxing(in value);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void Square()
	{
		Field448 value = _left;

		for (int i = 0; i < Operations; ++i)
		{
			Field448.Square(in value, out value);
		}

		DeadCodeEliminationHelper.KeepAliveWithoutBoxing(in value);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void SquareTimes()
	{
		Field448.SquareTimes(in _left, Operations, out Field448 value);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxing(in value);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void MultiplySmall()
	{
		Field448 value = _left;

		for (int i = 0; i < Operations; ++i)
		{
			Field448.MultiplySmall(in value, 39081, out value);
		}

		DeadCodeEliminationHelper.KeepAliveWithoutBoxing(in value);
	}

	[Benchmark]
	public void Invert()
	{
		Field448.Invert(in _left, out Field448 result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxing(in result);
	}

	[Benchmark]
	public void InvertByPower()
	{
		Field448.PowerP34(in _left, out Field448 result);
		Field448.SquareTimes(in result, 2, out result);
		Field448.Multiply(in result, in _left, out result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxing(in result);
	}

	[Benchmark]
	public void InvertVariableTime()
	{
		Field448.InvertVariableTime(in _left, out Field448 result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxing(in result);
	}

	[Benchmark]
	public ulong SqrtRatio()
	{
		return Field448.SqrtRatio(in _left, in _right, out _);
	}
}

// The point operations of Edwards448 and the multiplications of each kernel; a vector kernel adds its own KernelKind.
public class Curve448KernelBenchmark
{
	private readonly byte[] _scalar = RandomNumberGenerator.GetBytes(56);
	private readonly byte[] _otherScalar = RandomNumberGenerator.GetBytes(56);
	private readonly byte[] _encoded = new byte[Edwards448.EncodedLength];
	private IKernel _kernel = new Kernel<Curve448Scalar>();
	private Field448 _u;
	private EdwardsPoint _point;
	private EdwardsPoint _otherPoint;
	private EdwardsCachedPoint _cached;
	private EdwardsAffinePoint _affine;
	private EdwardsAffinePoint[] _pointTable = [];

	public enum KernelKind
	{
		Scalar,
		Avx2,
		Avx512,
		Sse41,
		AdvSimd,
		Dispatch
	}

	[ParamsAllValues]
	public KernelKind Backend { get; set; }

	[GlobalSetup]
	public void Setup()
	{
		_kernel = Backend switch
		{
			KernelKind.Scalar => new Kernel<Curve448Scalar>(),
			KernelKind.Avx2 => new Kernel<Curve448Avx2>(),
			KernelKind.Avx512 => new Kernel<Curve448Avx512>(),
			KernelKind.Sse41 => new Kernel<Curve448Sse41>(),
			KernelKind.AdvSimd => new Kernel<Curve448AdvSimd>(),
			KernelKind.Dispatch => new Kernel<Curve448KernelDispatch>(),
			_ => throw new ArgumentOutOfRangeException(nameof(Backend))
		};

		if (!_kernel.IsSupported)
		{
			throw new NotSupportedException($"{Backend} is not supported here.");
		}

		_scalar[0] &= 0xFC;
		_scalar[55] |= 0x80;
		Edwards448.MultiplyBase(_scalar, out _point);
		Edwards448.MultiplyBase(_otherScalar, out _otherPoint);
		byte[] u = new byte[Field448.ByteLength];
		Edwards448.ToMontgomeryU(in _otherPoint, u);
		Field448.FromBytes(u, out _u);
		Edwards448.Encode(in _point, _encoded);
		Edwards448.ToCached(in _otherPoint, out _cached);
		EdwardsAffinePoint[] affine = new EdwardsAffinePoint[1];
		Edwards448.ToAffineVariableTime([_otherPoint], affine);
		_affine = affine[0];
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
		Edwards448.Add(in _point, in _cached, out EdwardsCompletedPoint sum);
		Edwards448.ToExtended(in sum, out EdwardsPoint result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxing(in result);
	}

	[Benchmark]
	public void AddAffine()
	{
		Edwards448.AddAffine(in _point, in _affine, out EdwardsCompletedPoint sum);
		Edwards448.ToExtended(in sum, out EdwardsPoint result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxing(in result);
	}

	[Benchmark]
	public void Double()
	{
		Edwards448.Double(in _point, out EdwardsPoint result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxing(in result);
	}

	[Benchmark]
	public bool TryDecode()
	{
		bool decoded = Edwards448.TryDecode(_encoded, out EdwardsPoint result);
		DeadCodeEliminationHelper.KeepAliveWithoutBoxing(in result);
		return decoded;
	}

	[Benchmark]
	public void Encode()
	{
		Edwards448.Encode(in _point, _encoded);
	}

	[Benchmark]
	public void EncodeVariableTime()
	{
		Edwards448.EncodeVariableTime(in _point, _encoded);
	}

	private interface IKernel
	{
		bool IsSupported { get; }

		void Ladder(ReadOnlySpan<byte> scalar, in Field448 u);

		void MultiplyBase(ReadOnlySpan<byte> scalar);

		void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, in EdwardsPoint point, ReadOnlySpan<byte> b);

		void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, ReadOnlySpan<EdwardsAffinePoint> pointTable, ReadOnlySpan<byte> b);
	}

	private sealed class Kernel<TKernel> : IKernel where TKernel : ICurve448Kernel
	{
		public bool IsSupported => TKernel.IsSupported;

		public void Ladder(ReadOnlySpan<byte> scalar, in Field448 u)
		{
			TKernel.Ladder(scalar, in u, out Field448 x, out Field448 z);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxing(in x);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxing(in z);
		}

		public void MultiplyBase(ReadOnlySpan<byte> scalar)
		{
			TKernel.MultiplyBase(scalar, out EdwardsPoint result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxing(in result);
		}

		public void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, in EdwardsPoint point, ReadOnlySpan<byte> b)
		{
			TKernel.DoubleScalarMultiplyVariableTime(a, in point, b, out EdwardsPoint result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxing(in result);
		}

		public void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, ReadOnlySpan<EdwardsAffinePoint> pointTable, ReadOnlySpan<byte> b)
		{
			TKernel.DoubleScalarMultiplyVariableTime(a, pointTable, b, out EdwardsPoint result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxing(in result);
		}
	}
}
