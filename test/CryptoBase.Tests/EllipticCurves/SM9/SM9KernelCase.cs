using CryptoBase.EllipticCurves;
using CryptoBase.EllipticCurves.SM9;

namespace CryptoBase.Tests.EllipticCurves.SM9;

public abstract class SM9KernelCase : IKernelCase
{
	public static IEnumerable<SM9KernelCase> All()
	{
		yield return new Kernel<SM9Scalar>();
		yield return new Kernel<SM9Avx512>();
		yield return new Kernel<SM9Avx2>();
		yield return new Kernel<SM9Sse41>();
		yield return new Kernel<SM9AdvSimd>();
		yield return new Kernel<SM9KernelDispatch>();
	}

	public abstract Type KernelType { get; }

	public abstract bool IsSupported { get; }

	internal abstract void MillerLoop(in SM9AffinePoint<SM9Fp> p, in SM9AffinePoint<SM9Fp2> q, out SM9Fp12 result);

	internal abstract void MillerLoop(in SM9AffinePoint<SM9Fp> p, ReadOnlySpan<SM9PrecomputedLine> lines, out SM9Fp12 result);

	internal abstract void MillerLoop(in SM9AffinePoint<SM9Fp> p, ReadOnlySpan<SM9PrecomputedLine> lines, in SM9AffinePoint<SM9Fp> other, ReadOnlySpan<SM9PrecomputedLine> otherLines, out SM9Fp12 result);

	internal abstract void FinalExponentiation(in SM9Fp12 value, out SM9Fp12 result);

	internal abstract void Power(in SM9Fp12 value, in FieldElement<SM9Order> exponent, out SM9Fp12 result);

	internal abstract void BuildPowerTable(in SM9Fp12 value, Span<SM9Fp12> table, out SM9Fp12 inverse);

	internal abstract void Power(ReadOnlySpan<SM9Fp12> table, in SM9Fp12 inverse, in FieldElement<SM9Order> exponent, out SM9Fp12 result);

	internal abstract void BuildBaseTable(in SM9AffinePoint<SM9Fp> generator, int width, bool secret, Span<SM9AffinePoint<SM9Fp>> entries);

	internal abstract void BuildBaseTable(in SM9AffinePoint<SM9Fp2> generator, int width, bool secret, Span<SM9AffinePoint<SM9Fp2>> entries);

	internal abstract void ToAffine(ReadOnlySpan<SM9Point<SM9Fp2>> points, Span<SM9AffinePoint<SM9Fp2>> result, bool variableTime);

	internal abstract void MultiplyBaseG1(SM9BaseTable<SM9Fp> table, in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp> result);

	internal abstract void MultiplyBaseSumG1(SM9BaseTable<SM9Fp> first, in FieldElement<SM9Order> firstScalar, SM9BaseTable<SM9Fp> second, in FieldElement<SM9Order> secondScalar, out SM9Point<SM9Fp> result);

	internal abstract void MultiplyG1(in SM9AffinePoint<SM9Fp> point, in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp> result);

	internal abstract void MultiplyVariableTimeG1(in SM9AffinePoint<SM9Fp> point, in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp> result);

	internal abstract void MultiplyBaseAddVariableTimeG1(in FieldElement<SM9Order> scalar, in SM9Point<SM9Fp> addend, out SM9Point<SM9Fp> result);

	internal abstract void MultiplyBaseG2(in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp2> result);

	internal abstract void MultiplyBaseAddVariableTimeG2(in FieldElement<SM9Order> scalar, in SM9Point<SM9Fp2> addend, out SM9Point<SM9Fp2> result);

	internal abstract void MultiplyByLoopScalarG2(in SM9Point<SM9Fp2> point, out SM9Point<SM9Fp2> result);

	public override string ToString()
	{
		return KernelType.Name;
	}

	private sealed class Kernel<TKernel> : SM9KernelCase where TKernel : ISM9Kernel
	{
		public override Type KernelType => typeof(TKernel);

		public override bool IsSupported => TKernel.IsSupported;

		internal override void MillerLoop(in SM9AffinePoint<SM9Fp> p, in SM9AffinePoint<SM9Fp2> q, out SM9Fp12 result)
		{
			TKernel.MillerLoop(in p, in q, out result);
		}

		// The kernels take the factors of the points, which SM9MillerLoop.FactorsVariableTime gives.
		internal override void MillerLoop(in SM9AffinePoint<SM9Fp> p, ReadOnlySpan<SM9PrecomputedLine> lines, out SM9Fp12 result)
		{
			SM9MillerLoop.FactorsVariableTime(in p, out SM9Fp alpha, out SM9Fp beta);
			TKernel.MillerLoop(in alpha, in beta, lines, out result);
		}

		internal override void MillerLoop(in SM9AffinePoint<SM9Fp> p, ReadOnlySpan<SM9PrecomputedLine> lines, in SM9AffinePoint<SM9Fp> other, ReadOnlySpan<SM9PrecomputedLine> otherLines, out SM9Fp12 result)
		{
			SM9MillerLoop.FactorsVariableTime(in p, out SM9Fp alpha, out SM9Fp beta);
			SM9MillerLoop.FactorsVariableTime(in other, out SM9Fp otherAlpha, out SM9Fp otherBeta);
			TKernel.MillerLoop(in alpha, in beta, lines, in otherAlpha, in otherBeta, otherLines, out result);
		}

		internal override void FinalExponentiation(in SM9Fp12 value, out SM9Fp12 result)
		{
			TKernel.FinalExponentiation(in value, out result);
		}

		internal override void Power(in SM9Fp12 value, in FieldElement<SM9Order> exponent, out SM9Fp12 result)
		{
			TKernel.Power(in value, in exponent, out result);
		}

		internal override void BuildPowerTable(in SM9Fp12 value, Span<SM9Fp12> table, out SM9Fp12 inverse)
		{
			TKernel.BuildPowerTable(in value, table, out inverse);
		}

		internal override void Power(ReadOnlySpan<SM9Fp12> table, in SM9Fp12 inverse, in FieldElement<SM9Order> exponent, out SM9Fp12 result)
		{
			TKernel.Power(table, in inverse, in exponent, out result);
		}

		internal override void BuildBaseTable(in SM9AffinePoint<SM9Fp> generator, int width, bool secret, Span<SM9AffinePoint<SM9Fp>> entries)
		{
			TKernel.BuildBaseTable(in generator, width, secret, entries);
		}

		internal override void BuildBaseTable(in SM9AffinePoint<SM9Fp2> generator, int width, bool secret, Span<SM9AffinePoint<SM9Fp2>> entries)
		{
			TKernel.BuildBaseTable(in generator, width, secret, entries);
		}

		internal override void ToAffine(ReadOnlySpan<SM9Point<SM9Fp2>> points, Span<SM9AffinePoint<SM9Fp2>> result, bool variableTime)
		{
			TKernel.ToAffine(points, result, variableTime);
		}

		internal override void MultiplyBaseG1(SM9BaseTable<SM9Fp> table, in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp> result)
		{
			TKernel.MultiplyBaseG1(table, in scalar, out result);
		}

		internal override void MultiplyBaseSumG1(SM9BaseTable<SM9Fp> first, in FieldElement<SM9Order> firstScalar, SM9BaseTable<SM9Fp> second, in FieldElement<SM9Order> secondScalar, out SM9Point<SM9Fp> result)
		{
			TKernel.MultiplyBaseSumG1(first, in firstScalar, second, in secondScalar, out result);
		}

		internal override void MultiplyG1(in SM9AffinePoint<SM9Fp> point, in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp> result)
		{
			TKernel.MultiplyG1(in point, in scalar, out result);
		}

		internal override void MultiplyVariableTimeG1(in SM9AffinePoint<SM9Fp> point, in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp> result)
		{
			TKernel.MultiplyVariableTimeG1(in point, in scalar, out result);
		}

		internal override void MultiplyBaseAddVariableTimeG1(in FieldElement<SM9Order> scalar, in SM9Point<SM9Fp> addend, out SM9Point<SM9Fp> result)
		{
			TKernel.MultiplyBaseAddVariableTimeG1(in scalar, in addend, out result);
		}

		internal override void MultiplyBaseG2(in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp2> result)
		{
			TKernel.MultiplyBaseG2(in scalar, out result);
		}

		internal override void MultiplyBaseAddVariableTimeG2(in FieldElement<SM9Order> scalar, in SM9Point<SM9Fp2> addend, out SM9Point<SM9Fp2> result)
		{
			TKernel.MultiplyBaseAddVariableTimeG2(in scalar, in addend, out result);
		}

		internal override void MultiplyByLoopScalarG2(in SM9Point<SM9Fp2> point, out SM9Point<SM9Fp2> result)
		{
			TKernel.MultiplyByLoopScalarG2(in point, out result);
		}
	}
}
