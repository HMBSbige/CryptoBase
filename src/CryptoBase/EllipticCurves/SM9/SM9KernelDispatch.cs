using SM9Avx2 = CryptoBase.EllipticCurves.SM9.SM9VectorKernel<CryptoBase.EllipticCurves.SM9.SM9VectorAvx2>;
using SM9Avx512 = CryptoBase.EllipticCurves.SM9.SM9VectorKernel<CryptoBase.EllipticCurves.SM9.SM9VectorAvx512>;
using SM9Sse41 = CryptoBase.EllipticCurves.SM9.SM9VectorKernel<CryptoBase.EllipticCurves.SM9.SM9VectorSse41>;

namespace CryptoBase.EllipticCurves.SM9;

// Each operation takes the vector kernel chosen for it on the platform, if any, and otherwise the scalar one. SM9Avx512 and SM9Avx2 take every heavy operation of GT. SM9Sse41 serves x86 without AVX2 where LimbArithmetic.IsMultiplyAccelerated is false and the scalar products fall back to software; where it is true the scalar kernel serves. On ARM64, SM9AdvSimd takes the Miller loop on two points, with its products by the lines, and the powers with a fixed table with the builds of those tables, while the Miller loops on precomputed lines, the other powers and the final exponentiation stay in the scalar kernel. The products of G1 and G2 from fixed-base tables, the builds of those tables, the products of G1 with a variable point and the product of the subgroup check of G2 take the lanes on x64, and the products of G1 from fixed-base tables on ARM64 too; ARM64 keeps the others scalar. The affine forms over Fp2 that divide the precomputed lines take the lanes on x64. A kernel member that the dispatch never takes forwards to SM9Scalar.
internal readonly struct SM9KernelDispatch : ISM9Kernel
{
	public static bool IsSupported => true;

	// SSE4.1 where the scalar products fall back to software; a CPU with AVX2 or AVX-512 takes those first.
	private static bool UseSse41
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => SM9Sse41.IsSupported && !LimbArithmetic.IsMultiplyAccelerated;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void MillerLoop(in SM9AffinePoint<SM9Fp> p, in SM9AffinePoint<SM9Fp2> q, out SM9Fp12 result)
	{
		if (SM9Avx512.IsSupported)
		{
			SM9Avx512.MillerLoop(in p, in q, out result);
		}
		else if (SM9Avx2.IsSupported)
		{
			SM9Avx2.MillerLoop(in p, in q, out result);
		}
		else if (UseSse41)
		{
			SM9Sse41.MillerLoop(in p, in q, out result);
		}
		else if (SM9AdvSimd.IsSupported)
		{
			SM9AdvSimd.MillerLoop(in p, in q, out result);
		}
		else
		{
			SM9Scalar.MillerLoop(in p, in q, out result);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void MillerLoop(in SM9Fp alpha, in SM9Fp beta, ReadOnlySpan<SM9PrecomputedLine> lines, out SM9Fp12 result)
	{
		if (SM9Avx512.IsSupported)
		{
			SM9Avx512.MillerLoop(in alpha, in beta, lines, out result);
		}
		else if (SM9Avx2.IsSupported)
		{
			SM9Avx2.MillerLoop(in alpha, in beta, lines, out result);
		}
		else if (UseSse41)
		{
			SM9Sse41.MillerLoop(in alpha, in beta, lines, out result);
		}
		else
		{
			SM9Scalar.MillerLoop(in alpha, in beta, lines, out result);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void MillerLoop(in SM9Fp alpha, in SM9Fp beta, ReadOnlySpan<SM9PrecomputedLine> lines, in SM9Fp otherAlpha, in SM9Fp otherBeta, ReadOnlySpan<SM9PrecomputedLine> otherLines, out SM9Fp12 result)
	{
		if (SM9Avx512.IsSupported)
		{
			SM9Avx512.MillerLoop(in alpha, in beta, lines, in otherAlpha, in otherBeta, otherLines, out result);
		}
		else if (SM9Avx2.IsSupported)
		{
			SM9Avx2.MillerLoop(in alpha, in beta, lines, in otherAlpha, in otherBeta, otherLines, out result);
		}
		else if (UseSse41)
		{
			SM9Sse41.MillerLoop(in alpha, in beta, lines, in otherAlpha, in otherBeta, otherLines, out result);
		}
		else
		{
			SM9Scalar.MillerLoop(in alpha, in beta, lines, in otherAlpha, in otherBeta, otherLines, out result);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void FinalExponentiation(in SM9Fp12 value, out SM9Fp12 result)
	{
		if (SM9Avx512.IsSupported)
		{
			SM9Avx512.FinalExponentiation(in value, out result);
		}
		else if (SM9Avx2.IsSupported)
		{
			SM9Avx2.FinalExponentiation(in value, out result);
		}
		else if (UseSse41)
		{
			SM9Sse41.FinalExponentiation(in value, out result);
		}
		else
		{
			SM9Scalar.FinalExponentiation(in value, out result);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Power(in SM9Fp12 value, in FieldElement<SM9Order> exponent, out SM9Fp12 result)
	{
		if (SM9Avx512.IsSupported)
		{
			SM9Avx512.Power(in value, in exponent, out result);
		}
		else if (SM9Avx2.IsSupported)
		{
			SM9Avx2.Power(in value, in exponent, out result);
		}
		else if (UseSse41)
		{
			SM9Sse41.Power(in value, in exponent, out result);
		}
		else
		{
			SM9Scalar.Power(in value, in exponent, out result);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void BuildPowerTable(in SM9Fp12 value, Span<SM9Fp12> table, out SM9Fp12 inverse)
	{
		if (SM9Avx512.IsSupported)
		{
			SM9Avx512.BuildPowerTable(in value, table, out inverse);
		}
		else if (SM9Avx2.IsSupported)
		{
			SM9Avx2.BuildPowerTable(in value, table, out inverse);
		}
		else if (UseSse41)
		{
			SM9Sse41.BuildPowerTable(in value, table, out inverse);
		}
		else if (SM9AdvSimd.IsSupported)
		{
			SM9AdvSimd.BuildPowerTable(in value, table, out inverse);
		}
		else
		{
			SM9Scalar.BuildPowerTable(in value, table, out inverse);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Power(ReadOnlySpan<SM9Fp12> table, in SM9Fp12 inverse, in FieldElement<SM9Order> exponent, out SM9Fp12 result)
	{
		if (SM9Avx512.IsSupported)
		{
			SM9Avx512.Power(table, in inverse, in exponent, out result);
		}
		else if (SM9Avx2.IsSupported)
		{
			SM9Avx2.Power(table, in inverse, in exponent, out result);
		}
		else if (UseSse41)
		{
			SM9Sse41.Power(table, in inverse, in exponent, out result);
		}
		else if (SM9AdvSimd.IsSupported)
		{
			SM9AdvSimd.Power(table, in inverse, in exponent, out result);
		}
		else
		{
			SM9Scalar.Power(table, in inverse, in exponent, out result);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void BuildBaseTable(in SM9AffinePoint<SM9Fp> generator, int width, bool secret, Span<SM9AffinePoint<SM9Fp>> entries)
	{
		if (SM9Avx512.IsSupported)
		{
			SM9Avx512.BuildBaseTable(in generator, width, secret, entries);
		}
		else if (SM9Avx2.IsSupported)
		{
			SM9Avx2.BuildBaseTable(in generator, width, secret, entries);
		}
		else if (UseSse41)
		{
			SM9Sse41.BuildBaseTable(in generator, width, secret, entries);
		}
		else
		{
			SM9Scalar.BuildBaseTable(in generator, width, secret, entries);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void BuildBaseTable(in SM9AffinePoint<SM9Fp2> generator, int width, bool secret, Span<SM9AffinePoint<SM9Fp2>> entries)
	{
		if (SM9Avx512.IsSupported)
		{
			SM9Avx512.BuildBaseTable(in generator, width, secret, entries);
		}
		else if (SM9Avx2.IsSupported)
		{
			SM9Avx2.BuildBaseTable(in generator, width, secret, entries);
		}
		else if (UseSse41)
		{
			SM9Sse41.BuildBaseTable(in generator, width, secret, entries);
		}
		else
		{
			SM9Scalar.BuildBaseTable(in generator, width, secret, entries);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ToAffine(ReadOnlySpan<SM9Point<SM9Fp2>> points, Span<SM9AffinePoint<SM9Fp2>> result, bool variableTime)
	{
		if (SM9Avx512.IsSupported)
		{
			SM9Avx512.ToAffine(points, result, variableTime);
		}
		else if (SM9Avx2.IsSupported)
		{
			SM9Avx2.ToAffine(points, result, variableTime);
		}
		else if (UseSse41)
		{
			SM9Sse41.ToAffine(points, result, variableTime);
		}
		else
		{
			SM9Scalar.ToAffine(points, result, variableTime);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void MultiplyBaseG1(SM9BaseTable<SM9Fp> table, in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp> result)
	{
		if (SM9Avx512.IsSupported)
		{
			SM9Avx512.MultiplyBaseG1(table, in scalar, out result);
		}
		else if (SM9Avx2.IsSupported)
		{
			SM9Avx2.MultiplyBaseG1(table, in scalar, out result);
		}
		else if (UseSse41)
		{
			SM9Sse41.MultiplyBaseG1(table, in scalar, out result);
		}
		else if (SM9AdvSimd.IsSupported)
		{
			SM9AdvSimd.MultiplyBaseG1(table, in scalar, out result);
		}
		else
		{
			SM9Scalar.MultiplyBaseG1(table, in scalar, out result);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void MultiplyBaseSumG1(SM9BaseTable<SM9Fp> first, in FieldElement<SM9Order> firstScalar, SM9BaseTable<SM9Fp> second, in FieldElement<SM9Order> secondScalar, out SM9Point<SM9Fp> result)
	{
		if (SM9Avx512.IsSupported)
		{
			SM9Avx512.MultiplyBaseSumG1(first, in firstScalar, second, in secondScalar, out result);
		}
		else if (SM9Avx2.IsSupported)
		{
			SM9Avx2.MultiplyBaseSumG1(first, in firstScalar, second, in secondScalar, out result);
		}
		else if (UseSse41)
		{
			SM9Sse41.MultiplyBaseSumG1(first, in firstScalar, second, in secondScalar, out result);
		}
		else if (SM9AdvSimd.IsSupported)
		{
			SM9AdvSimd.MultiplyBaseSumG1(first, in firstScalar, second, in secondScalar, out result);
		}
		else
		{
			SM9Scalar.MultiplyBaseSumG1(first, in firstScalar, second, in secondScalar, out result);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void MultiplyG1(in SM9AffinePoint<SM9Fp> point, in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp> result)
	{
		if (SM9Avx512.IsSupported)
		{
			SM9Avx512.MultiplyG1(in point, in scalar, out result);
		}
		else if (SM9Avx2.IsSupported)
		{
			SM9Avx2.MultiplyG1(in point, in scalar, out result);
		}
		else if (UseSse41)
		{
			SM9Sse41.MultiplyG1(in point, in scalar, out result);
		}
		else
		{
			SM9Scalar.MultiplyG1(in point, in scalar, out result);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void MultiplyVariableTimeG1(in SM9AffinePoint<SM9Fp> point, in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp> result)
	{
		if (SM9Avx512.IsSupported)
		{
			SM9Avx512.MultiplyVariableTimeG1(in point, in scalar, out result);
		}
		else if (SM9Avx2.IsSupported)
		{
			SM9Avx2.MultiplyVariableTimeG1(in point, in scalar, out result);
		}
		else if (UseSse41)
		{
			SM9Sse41.MultiplyVariableTimeG1(in point, in scalar, out result);
		}
		else
		{
			SM9Scalar.MultiplyVariableTimeG1(in point, in scalar, out result);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void MultiplyBaseAddVariableTimeG1(in FieldElement<SM9Order> scalar, in SM9Point<SM9Fp> addend, out SM9Point<SM9Fp> result)
	{
		if (SM9Avx512.IsSupported)
		{
			SM9Avx512.MultiplyBaseAddVariableTimeG1(in scalar, in addend, out result);
		}
		else if (SM9Avx2.IsSupported)
		{
			SM9Avx2.MultiplyBaseAddVariableTimeG1(in scalar, in addend, out result);
		}
		else if (UseSse41)
		{
			SM9Sse41.MultiplyBaseAddVariableTimeG1(in scalar, in addend, out result);
		}
		else if (SM9AdvSimd.IsSupported)
		{
			SM9AdvSimd.MultiplyBaseAddVariableTimeG1(in scalar, in addend, out result);
		}
		else
		{
			SM9Scalar.MultiplyBaseAddVariableTimeG1(in scalar, in addend, out result);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void MultiplyBaseG2(in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp2> result)
	{
		if (SM9Avx512.IsSupported)
		{
			SM9Avx512.MultiplyBaseG2(in scalar, out result);
		}
		else if (SM9Avx2.IsSupported)
		{
			SM9Avx2.MultiplyBaseG2(in scalar, out result);
		}
		else if (UseSse41)
		{
			SM9Sse41.MultiplyBaseG2(in scalar, out result);
		}
		else
		{
			SM9Scalar.MultiplyBaseG2(in scalar, out result);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void MultiplyByLoopScalarG2(in SM9Point<SM9Fp2> point, out SM9Point<SM9Fp2> result)
	{
		if (SM9Avx512.IsSupported)
		{
			SM9Avx512.MultiplyByLoopScalarG2(in point, out result);
		}
		else if (SM9Avx2.IsSupported)
		{
			SM9Avx2.MultiplyByLoopScalarG2(in point, out result);
		}
		else if (UseSse41)
		{
			SM9Sse41.MultiplyByLoopScalarG2(in point, out result);
		}
		else
		{
			SM9Scalar.MultiplyByLoopScalarG2(in point, out result);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void MultiplyBaseAddVariableTimeG2(in FieldElement<SM9Order> scalar, in SM9Point<SM9Fp2> addend, out SM9Point<SM9Fp2> result)
	{
		if (SM9Avx512.IsSupported)
		{
			SM9Avx512.MultiplyBaseAddVariableTimeG2(in scalar, in addend, out result);
		}
		else if (SM9Avx2.IsSupported)
		{
			SM9Avx2.MultiplyBaseAddVariableTimeG2(in scalar, in addend, out result);
		}
		else if (UseSse41)
		{
			SM9Sse41.MultiplyBaseAddVariableTimeG2(in scalar, in addend, out result);
		}
		else
		{
			SM9Scalar.MultiplyBaseAddVariableTimeG2(in scalar, in addend, out result);
		}
	}
}
