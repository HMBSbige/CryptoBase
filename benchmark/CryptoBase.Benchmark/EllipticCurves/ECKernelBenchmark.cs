using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using CryptoBase.EllipticCurves;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.EllipticCurves;

public class ECKernelBenchmark
{
	private IKernel _kernel = new Kernel<P256Curve, P256Field52, P256Order>();

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
			CurveKind.P256 => new Kernel<P256Curve, P256Field52, P256Order>(),
			CurveKind.P384 => new Kernel<P384Curve, P384Field56, P384Order>(),
			CurveKind.P521 => new Kernel<P521Curve, P521Field58, P521Order>(),
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
	public void OrderInvert()
	{
		_kernel.OrderInvert();
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
	public int BuildPointTable()
	{
		return _kernel.BuildPointTable();
	}

	[Benchmark]
	public void MultiplyAddWithTable()
	{
		_kernel.MultiplyAddWithTable();
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

		void OrderInvert();

		void AddAffine();

		void AddDistinct();

		void AddDistinctAffine();

		void Double();

		void MultiplyBase();

		void Multiply();

		void MultiplyAdd();

		int BuildPointTable();

		void MultiplyAddWithTable();

		bool TryDecode();
	}

	private sealed class Kernel<TCurve, TField, TOrder> : IKernel
		where TCurve : struct, IECCurve
		where TField : unmanaged, IECField<TField>
		where TOrder : unmanaged, IMontgomeryModulus
	{
		private readonly byte[] _encoded = new byte[ECGroup<TCurve, TField, TOrder>.EncodedLength];
		private readonly AffinePoint<TField>[] _pointTable;
		private TField _fieldLeft;
		private TField _fieldRight;
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
			ECGroup<TCurve, TField, TOrder>.MultiplyBaseToAffine(in scalar, out _affine);
			ECGroup<TCurve, TField, TOrder>.Encode(in _affine, _encoded);
			_pointTable = ECVariableTimePointTable<TCurve, TField, TOrder>.Build(in _affine);
			RandomScalar(out scalar);
			ECGroup<TCurve, TField, TOrder>.MultiplyBase(in scalar, out _jacobian);
			RandomScalar(out scalar);
			ECGroup<TCurve, TField, TOrder>.MultiplyBase(in scalar, out _otherJacobian);

			if (!TryDecode())
			{
				throw new InvalidOperationException("The encoded point does not decode.");
			}
		}

		public void FieldMultiply()
		{
			TField.Multiply(in _fieldLeft, in _fieldRight, out TField result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}

		public void FieldSquare()
		{
			TField.Square(in _fieldLeft, out TField result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}

		public void FieldInvert()
		{
			TField.Invert(in _fieldLeft, out TField result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}

		public void OrderMultiply()
		{
			FieldElement<TOrder>.Multiply(in _orderLeft, in _orderRight, out FieldElement<TOrder> result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}

		public void OrderInvert()
		{
			FieldElement<TOrder>.Invert(in _orderLeft, out FieldElement<TOrder> result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}

		public void AddAffine()
		{
			ECGroup<TCurve, TField, TOrder>.Add(in _jacobian, in _affine, out JacobianPoint<TField> result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}

		public void AddDistinct()
		{
			ulong equal = ECGroup<TCurve, TField, TOrder>.AddDistinct(in _jacobian, in _otherJacobian, out JacobianPoint<TField> result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxing(equal);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}

		public void AddDistinctAffine()
		{
			ulong equal = ECGroup<TCurve, TField, TOrder>.AddDistinct(in _jacobian, in _affine, out JacobianPoint<TField> result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxing(equal);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}

		public void Double()
		{
			ECGroup<TCurve, TField, TOrder>.Double(in _jacobian, out JacobianPoint<TField> result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}

		public void MultiplyBase()
		{
			ECGroup<TCurve, TField, TOrder>.MultiplyBase(in _orderLeft, out JacobianPoint<TField> result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}

		public void Multiply()
		{
			ECGroup<TCurve, TField, TOrder>.Multiply(in _affine, in _orderLeft, out JacobianPoint<TField> result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}

		public void MultiplyAdd()
		{
			ECVariableTimeGroup<TCurve, TField, TOrder>.MultiplyAdd(in _orderLeft, in _affine, in _orderRight, out JacobianPoint<TField> result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}

		public int BuildPointTable()
		{
			return ECVariableTimePointTable<TCurve, TField, TOrder>.Build(in _affine).Length;
		}

		public void MultiplyAddWithTable()
		{
			ECVariableTimeGroup<TCurve, TField, TOrder>.MultiplyAdd(in _orderLeft, _pointTable, in _orderRight, out JacobianPoint<TField> result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
		}

		public bool TryDecode()
		{
			bool decoded = ECGroup<TCurve, TField, TOrder>.TryDecode(_encoded, out AffinePoint<TField> result);
			DeadCodeEliminationHelper.KeepAliveWithoutBoxingReadonly(in result);
			return decoded;
		}

		private static void RandomField(out TField result)
		{
			while (!TField.TryImport(RandomNumberGenerator.GetBytes(TField.ByteLength), out result))
			{
			}
		}

		private static void RandomScalar(out FieldElement<TOrder> result)
		{
			FieldElement<TOrder>.ImportReduced(RandomNumberGenerator.GetBytes(TOrder.ByteLength), out result);
		}
	}
}
