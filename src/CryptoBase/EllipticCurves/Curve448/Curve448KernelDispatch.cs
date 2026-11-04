namespace CryptoBase.EllipticCurves.Curve448;

// Each operation tries the vector kernels before the scalar one, which supports every platform. Curve448Sse41 serves x64 without AVX2, where the scalar products also lack BMI2. On ARM64 the scalar kernel takes the double-base product without a table, as fast as Curve448AdvSimd.
internal readonly struct Curve448KernelDispatch : ICurve448Kernel
{
	public static bool IsSupported => true;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Ladder(ReadOnlySpan<byte> scalar, in Field448 u, out Field448 x, out Field448 z)
	{
		if (Curve448Avx512.IsSupported)
		{
			Curve448Avx512.Ladder(scalar, in u, out x, out z);
		}
		else if (Curve448Avx2.IsSupported)
		{
			Curve448Avx2.Ladder(scalar, in u, out x, out z);
		}
		else if (Curve448Sse41.IsSupported)
		{
			Curve448Sse41.Ladder(scalar, in u, out x, out z);
		}
		else if (Curve448AdvSimd.IsSupported)
		{
			Curve448AdvSimd.Ladder(scalar, in u, out x, out z);
		}
		else
		{
			Curve448Scalar.Ladder(scalar, in u, out x, out z);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void MultiplyBase(ReadOnlySpan<byte> scalar, out EdwardsPoint result)
	{
		if (Curve448Avx512.IsSupported)
		{
			Curve448Avx512.MultiplyBase(scalar, out result);
		}
		else if (Curve448Avx2.IsSupported)
		{
			Curve448Avx2.MultiplyBase(scalar, out result);
		}
		else if (Curve448Sse41.IsSupported)
		{
			Curve448Sse41.MultiplyBase(scalar, out result);
		}
		else if (Curve448AdvSimd.IsSupported)
		{
			Curve448AdvSimd.MultiplyBase(scalar, out result);
		}
		else
		{
			Curve448Scalar.MultiplyBase(scalar, out result);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, in EdwardsPoint point, ReadOnlySpan<byte> b, out EdwardsPoint result)
	{
		if (Curve448Avx512.IsSupported)
		{
			Curve448Avx512.DoubleScalarMultiplyVariableTime(a, in point, b, out result);
		}
		else if (Curve448Avx2.IsSupported)
		{
			Curve448Avx2.DoubleScalarMultiplyVariableTime(a, in point, b, out result);
		}
		else if (Curve448Sse41.IsSupported)
		{
			Curve448Sse41.DoubleScalarMultiplyVariableTime(a, in point, b, out result);
		}
		else
		{
			Curve448Scalar.DoubleScalarMultiplyVariableTime(a, in point, b, out result);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, ReadOnlySpan<EdwardsAffinePoint> pointTable, ReadOnlySpan<byte> b, out EdwardsPoint result)
	{
		if (Curve448Avx512.IsSupported)
		{
			Curve448Avx512.DoubleScalarMultiplyVariableTime(a, pointTable, b, out result);
		}
		else if (Curve448Avx2.IsSupported)
		{
			Curve448Avx2.DoubleScalarMultiplyVariableTime(a, pointTable, b, out result);
		}
		else if (Curve448Sse41.IsSupported)
		{
			Curve448Sse41.DoubleScalarMultiplyVariableTime(a, pointTable, b, out result);
		}
		else if (Curve448AdvSimd.IsSupported)
		{
			Curve448AdvSimd.DoubleScalarMultiplyVariableTime(a, pointTable, b, out result);
		}
		else
		{
			Curve448Scalar.DoubleScalarMultiplyVariableTime(a, pointTable, b, out result);
		}
	}
}
