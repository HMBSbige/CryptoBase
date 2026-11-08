using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using CryptoBase.EllipticCurves;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.EllipticCurves;

// The products of each SM2 kernel: k·G, k·G and k·P with the table of P, as encryption takes them, k·P without it, and u1·G + u2·Q with the windows of Q of SM2VerificationCurve, with the table of Q and without, as verification takes them; and the windows of the table of P filled from their bases. A vector kernel adds its own KernelKind.
public class SM2KernelBenchmark
{
	private IKernel _kernel = new Kernel<SM2Scalar>();
	private FieldElement<SM2Order> _scalar;
	private FieldElement<SM2Order> _otherScalar;
	private AffinePoint<SM2Field52>[] _pointTable = [];
	private ECPointTable<SM2Curve, SM2Field52, SM2Order> _windows = null!;
	private ECPointTable<SM2VerificationCurve, SM2Field52, SM2Order> _verificationWindows = null!;
	// The bases of the windows of P, entry 1 of each, which filling the rest leaves as they are.
	private ulong[] _bases = [];
	private AffinePoint<SM2Field52> _point;

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
			KernelKind.Scalar => new Kernel<SM2Scalar>(),
			KernelKind.Avx2 => new Kernel<SM2Avx2>(),
			KernelKind.Avx512 => new Kernel<SM2Avx512>(),
			KernelKind.Sse41 => new Kernel<SM2Sse41>(),
			KernelKind.AdvSimd => new Kernel<SM2AdvSimd>(),
			KernelKind.Dispatch => new Kernel<SM2KernelDispatch>(),
			_ => throw new ArgumentOutOfRangeException(nameof(Backend))
		};

		if (!_kernel.IsSupported)
		{
			throw new NotSupportedException($"{Backend} is not supported here.");
		}

		RandomScalar(out _scalar);
		RandomScalar(out _otherScalar);
		RandomScalar(out FieldElement<SM2Order> privateKey);
		ECGroup<SM2Curve, SM2Field52, SM2Order>.MultiplyBaseToAffine(in privateKey, out AffinePoint<SM2Field52> point);
		_pointTable = ECVariableTimePointTable<SM2Curve, SM2Field52, SM2Order>.Build(in point);
		_windows = new ECPointTable<SM2Curve, SM2Field52, SM2Order>(in point);
		_verificationWindows = new ECPointTable<SM2VerificationCurve, SM2Field52, SM2Order>(in point);
		_bases = _windows.Windows.ToArray();
		_point = point;
	}

	[Benchmark]
	public void MultiplyBase()
	{
		_kernel.MultiplyBase(in _scalar);
	}

	[Benchmark]
	public void MultiplyAddWithTable()
	{
		_kernel.MultiplyAdd(in _scalar, _pointTable, in _otherScalar);
	}

	[Benchmark]
	public void MultiplyAddFixed()
	{
		_kernel.MultiplyAddFixed(_verificationWindows.Windows, in _scalar, in _otherScalar);
	}

	[Benchmark]
	public void FillWindows()
	{
		_kernel.FillWindows(_bases);
	}

	[Benchmark]
	public void MultiplyBaseAndFixed()
	{
		_kernel.MultiplyBaseAndFixed(_windows.Windows, in _scalar);
	}

	[Benchmark]
	public void Multiply()
	{
		_kernel.Multiply(in _point, in _scalar);
	}

	[Benchmark]
	public void MultiplyAdd()
	{
		_kernel.MultiplyAdd(in _scalar, in _point, in _otherScalar);
	}

	private static void RandomScalar(out FieldElement<SM2Order> result)
	{
		FieldElement<SM2Order>.ImportReduced(RandomNumberGenerator.GetBytes(SM2Order.ByteLength), out result);
	}

	private interface IKernel
	{
		bool IsSupported { get; }

		void MultiplyBase(in FieldElement<SM2Order> scalar);

		void MultiplyAdd(in FieldElement<SM2Order> u1, ReadOnlySpan<AffinePoint<SM2Field52>> pointTable, in FieldElement<SM2Order> u2);

		void FillWindows(Span<ulong> windows);

		void MultiplyAddFixed(ReadOnlySpan<ulong> windows, in FieldElement<SM2Order> u1, in FieldElement<SM2Order> u2);

		void MultiplyBaseAndFixed(ReadOnlySpan<ulong> windows, in FieldElement<SM2Order> scalar);

		void Multiply(in AffinePoint<SM2Field52> point, in FieldElement<SM2Order> scalar);

		void MultiplyAdd(in FieldElement<SM2Order> u1, in AffinePoint<SM2Field52> point, in FieldElement<SM2Order> u2);
	}

	private sealed class Kernel<TKernel> : IKernel where TKernel : ISM2Kernel
	{
		public bool IsSupported => TKernel.IsSupported;

		public void MultiplyBase(in FieldElement<SM2Order> scalar)
		{
			TKernel.MultiplyBase(in scalar, out JacobianPoint<SM2Field52> result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}

		public void MultiplyAdd(in FieldElement<SM2Order> u1, ReadOnlySpan<AffinePoint<SM2Field52>> pointTable, in FieldElement<SM2Order> u2)
		{
			TKernel.MultiplyAdd(in u1, pointTable, in u2, out JacobianPoint<SM2Field52> result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}

		public void FillWindows(Span<ulong> windows)
		{
			TKernel.FillWindows<SM2Curve>(windows);
		}

		public void MultiplyAddFixed(ReadOnlySpan<ulong> windows, in FieldElement<SM2Order> u1, in FieldElement<SM2Order> u2)
		{
			TKernel.MultiplyAddFixed(windows, in u1, in u2, out JacobianPoint<SM2Field52> result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}

		public void MultiplyBaseAndFixed(ReadOnlySpan<ulong> windows, in FieldElement<SM2Order> scalar)
		{
			TKernel.MultiplyBaseAndFixed(windows, in scalar, out JacobianPoint<SM2Field52> baseResult, out JacobianPoint<SM2Field52> result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in baseResult);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}

		public void Multiply(in AffinePoint<SM2Field52> point, in FieldElement<SM2Order> scalar)
		{
			TKernel.Multiply(in point, in scalar, out JacobianPoint<SM2Field52> result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}

		public void MultiplyAdd(in FieldElement<SM2Order> u1, in AffinePoint<SM2Field52> point, in FieldElement<SM2Order> u2)
		{
			TKernel.MultiplyAdd(in u1, in point, in u2, out JacobianPoint<SM2Field52> result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}
	}
}
