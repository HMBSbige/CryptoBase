using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using CryptoBase.EllipticCurves;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.EllipticCurves;

public class EcKernelBenchmark
{
	private IKernel _kernel = new Kernel<P256Curve, P256Field, P256Order>();

	public enum CurveKind
	{
		P256,
		P384,
		P521
	}

	[ParamsAllValues]
	public CurveKind Curve { get; set; }

	[GlobalSetup]
	public void Setup()
	{
		_kernel = Curve switch
		{
			CurveKind.P256 => new Kernel<P256Curve, P256Field, P256Order>(),
			CurveKind.P384 => new Kernel<P384Curve, P384Field, P384Order>(),
			CurveKind.P521 => new Kernel<P521Curve, P521Field, P521Order>(),
			_ => throw new ArgumentOutOfRangeException(nameof(Curve))
		};
	}

	[Benchmark]
	public void FieldMultiply()
	{
		_kernel.FieldMultiply();
	}

	[Benchmark]
	public void FieldSquare()
	{
		_kernel.FieldSquare();
	}

	[Benchmark]
	public void FieldInvert()
	{
		_kernel.FieldInvert();
	}

	[Benchmark]
	public void OrderMultiply()
	{
		_kernel.OrderMultiply();
	}

	[Benchmark]
	public void OrderSquare()
	{
		_kernel.OrderSquare();
	}

	[Benchmark]
	public void OrderInvert()
	{
		_kernel.OrderInvert();
	}

	[Benchmark]
	public void Add()
	{
		_kernel.Add();
	}

	[Benchmark]
	public void AddAffine()
	{
		_kernel.AddAffine();
	}

	[Benchmark]
	public void AddDistinct()
	{
		_kernel.AddDistinct();
	}

	[Benchmark]
	public void AddDistinctAffine()
	{
		_kernel.AddDistinctAffine();
	}

	[Benchmark]
	public void Double()
	{
		_kernel.Double();
	}

	[Benchmark]
	public void MultiplyBase()
	{
		_kernel.MultiplyBase();
	}

	[Benchmark]
	public void Multiply()
	{
		_kernel.Multiply();
	}

	[Benchmark]
	public void MultiplyAdd()
	{
		_kernel.MultiplyAdd();
	}

	[Benchmark]
	public bool TryDecode()
	{
		return _kernel.TryDecode();
	}

	private interface IKernel
	{
		void FieldMultiply();

		void FieldSquare();

		void FieldInvert();

		void OrderMultiply();

		void OrderSquare();

		void OrderInvert();

		void Add();

		void AddAffine();

		void AddDistinct();

		void AddDistinctAffine();

		void Double();

		void MultiplyBase();

		void Multiply();

		void MultiplyAdd();

		bool TryDecode();
	}

	private sealed class Kernel<TCurve, TField, TOrder> : IKernel
		where TCurve : struct, IEcCurve
		where TField : unmanaged, IMontgomeryModulus
		where TOrder : unmanaged, IMontgomeryModulus
	{
		private readonly byte[] _encoded = new byte[EcGroup<TCurve, TField, TOrder>.EncodedLength];
		private FieldElement<TField> _fieldLeft;
		private FieldElement<TField> _fieldRight;
		private FieldElement<TOrder> _orderLeft;
		private FieldElement<TOrder> _orderRight;
		private AffinePoint<TField> _affine;
		private JacobianPoint<TField> _jacobian;
		private JacobianPoint<TField> _otherJacobian;

		public Kernel()
		{
			RandomField(out _fieldLeft);
			RandomField(out _fieldRight);
			RandomScalar(out _orderLeft);
			RandomScalar(out _orderRight);
			RandomScalar(out FieldElement<TOrder> scalar);
			EcGroup<TCurve, TField, TOrder>.MultiplyBaseToAffine(in scalar, out _affine);
			EcGroup<TCurve, TField, TOrder>.Encode(in _affine, _encoded);
			RandomScalar(out scalar);
			EcGroup<TCurve, TField, TOrder>.MultiplyBase(in scalar, out _jacobian);
			RandomScalar(out scalar);
			EcGroup<TCurve, TField, TOrder>.MultiplyBase(in scalar, out _otherJacobian);

			if (!TryDecode())
			{
				throw new InvalidOperationException("The encoded point does not decode.");
			}
		}

		public void FieldMultiply()
		{
			FieldElement<TField>.Multiply(in _fieldLeft, in _fieldRight, out FieldElement<TField> result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}

		public void FieldSquare()
		{
			FieldElement<TField>.Square(in _fieldLeft, out FieldElement<TField> result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}

		public void FieldInvert()
		{
			FieldElement<TField>.Invert(in _fieldLeft, out FieldElement<TField> result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}

		public void OrderMultiply()
		{
			FieldElement<TOrder>.Multiply(in _orderLeft, in _orderRight, out FieldElement<TOrder> result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}

		public void OrderSquare()
		{
			FieldElement<TOrder>.Square(in _orderLeft, out FieldElement<TOrder> result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}

		public void OrderInvert()
		{
			FieldElement<TOrder>.Invert(in _orderLeft, out FieldElement<TOrder> result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}

		public void Add()
		{
			EcGroup<TCurve, TField, TOrder>.Add(in _jacobian, in _otherJacobian, out JacobianPoint<TField> result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}

		public void AddAffine()
		{
			EcGroup<TCurve, TField, TOrder>.Add(in _jacobian, in _affine, out JacobianPoint<TField> result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}

		public void AddDistinct()
		{
			ulong equal = EcGroup<TCurve, TField, TOrder>.AddDistinct(in _jacobian, in _otherJacobian, out JacobianPoint<TField> result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxing(equal);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}

		public void AddDistinctAffine()
		{
			ulong equal = EcGroup<TCurve, TField, TOrder>.AddDistinct(in _jacobian, in _affine, out JacobianPoint<TField> result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxing(equal);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}

		public void Double()
		{
			EcGroup<TCurve, TField, TOrder>.Double(in _jacobian, out JacobianPoint<TField> result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}

		public void MultiplyBase()
		{
			EcGroup<TCurve, TField, TOrder>.MultiplyBase(in _orderLeft, out JacobianPoint<TField> result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}

		public void Multiply()
		{
			EcGroup<TCurve, TField, TOrder>.Multiply(in _affine, in _orderLeft, out JacobianPoint<TField> result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}

		public void MultiplyAdd()
		{
			EcVariableTimeGroup<TCurve, TField, TOrder>.MultiplyAdd(in _orderLeft, in _affine, in _orderRight, out JacobianPoint<TField> result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}

		public bool TryDecode()
		{
			bool decoded = EcGroup<TCurve, TField, TOrder>.TryDecode(_encoded, out AffinePoint<TField> result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
			return decoded;
		}

		private static void RandomField(out FieldElement<TField> result)
		{
			FieldElement<TField>.ImportReduced(RandomNumberGenerator.GetBytes(TField.ByteLength), out result);
		}

		private static void RandomScalar(out FieldElement<TOrder> result)
		{
			FieldElement<TOrder>.ImportReduced(RandomNumberGenerator.GetBytes(TOrder.ByteLength), out result);
		}
	}
}
