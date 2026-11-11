namespace CryptoBase.EllipticCurves.Curve25519;

// Each operation tries the vector kernels before the scalar one, which supports every platform. Curve25519Avx512 only adds a second chain where the additions fall into two, so the ladder and the double-base product stay on Curve25519Avx2. Curve25519Sse41 serves x86 without AVX2 where LimbArithmetic.IsMultiplyAccelerated is false and the scalar products fall back to software; where it is true the scalar kernel serves.
internal readonly struct Curve25519KernelDispatch : ICurve25519Kernel
{
	public static bool IsSupported => true;

	private static bool UseSse41
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => Curve25519Sse41.IsSupported && !LimbArithmetic.IsMultiplyAccelerated;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Ladder(ReadOnlySpan<byte> scalar, in Field25519 u, out Field25519 x, out Field25519 z)
	{
		if (Curve25519Avx2.IsSupported)
		{
			Curve25519Avx2.Ladder(scalar, in u, out x, out z);
		}
		else if (UseSse41)
		{
			Curve25519Sse41.Ladder(scalar, in u, out x, out z);
		}
		else
		{
			Curve25519Scalar.Ladder(scalar, in u, out x, out z);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void MultiplyBase(ReadOnlySpan<byte> scalar, out EdwardsPoint result)
	{
		if (Curve25519Avx512.IsSupported)
		{
			Curve25519Avx512.MultiplyBase(scalar, out result);
		}
		else if (Curve25519Avx2.IsSupported)
		{
			Curve25519Avx2.MultiplyBase(scalar, out result);
		}
		else if (UseSse41)
		{
			Curve25519Sse41.MultiplyBase(scalar, out result);
		}
		else
		{
			Curve25519Scalar.MultiplyBase(scalar, out result);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, in EdwardsPoint point, ReadOnlySpan<byte> b, out EdwardsPoint result)
	{
		if (Curve25519Avx2.IsSupported)
		{
			Curve25519Avx2.DoubleScalarMultiplyVariableTime(a, in point, b, out result);
		}
		else if (UseSse41)
		{
			Curve25519Sse41.DoubleScalarMultiplyVariableTime(a, in point, b, out result);
		}
		else
		{
			Curve25519Scalar.DoubleScalarMultiplyVariableTime(a, in point, b, out result);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, ReadOnlySpan<EdwardsNielsPoint> pointTable, ReadOnlySpan<byte> b, out EdwardsPoint result)
	{
		if (Curve25519Avx512.IsSupported)
		{
			Curve25519Avx512.DoubleScalarMultiplyVariableTime(a, pointTable, b, out result);
		}
		else if (Curve25519Avx2.IsSupported)
		{
			Curve25519Avx2.DoubleScalarMultiplyVariableTime(a, pointTable, b, out result);
		}
		else if (UseSse41)
		{
			Curve25519Sse41.DoubleScalarMultiplyVariableTime(a, pointTable, b, out result);
		}
		else
		{
			Curve25519Scalar.DoubleScalarMultiplyVariableTime(a, pointTable, b, out result);
		}
	}
}
