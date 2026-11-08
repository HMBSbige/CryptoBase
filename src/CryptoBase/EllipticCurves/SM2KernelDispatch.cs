namespace CryptoBase.EllipticCurves;

// Each product tries the vector kernels before the scalar one, which supports every platform: SM2Sse41 serves x64 without AVX2, where the scalar products also lack BMI2, and SM2AdvSimd serves ARM64. k·P and u2·Q of u1·G + u2·Q without a table hold one point at a time, which SM2QuadFormulas spreads over four lanes where AVX2 is and SM2PairFormulas over two lanes elsewhere; where AVX-512 is, SM2OctoFormulas splits k·P into two chains, one in each half of eight lanes, and takes k·P + l·Q as a chain of each in one half, which fewer lanes have no room for.
internal readonly struct SM2KernelDispatch : ISM2Kernel
{
	public static bool IsSupported => true;

	public static bool HasMultiplyAdd => SM2Avx512.IsSupported;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void MultiplyBase(in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> result)
	{
		if (SM2Avx512.IsSupported)
		{
			SM2Avx512.MultiplyBase(in scalar, out result);
		}
		else if (SM2Avx2.IsSupported)
		{
			SM2Avx2.MultiplyBase(in scalar, out result);
		}
		else if (SM2Sse41.IsSupported)
		{
			SM2Sse41.MultiplyBase(in scalar, out result);
		}
		else if (SM2AdvSimd.IsSupported)
		{
			SM2AdvSimd.MultiplyBase(in scalar, out result);
		}
		else
		{
			SM2Scalar.MultiplyBase(in scalar, out result);
		}
	}

	public static void FillBases<TCurve>(in AffinePoint<SM2Field52> point, Span<JacobianPoint<SM2Field52>> bases) where TCurve : struct, IECCurve
	{
		if (SM2Avx512.IsSupported)
		{
			SM2Avx512.FillBases<TCurve>(in point, bases);
		}
		else if (SM2Avx2.IsSupported)
		{
			SM2Avx2.FillBases<TCurve>(in point, bases);
		}
		else if (SM2Sse41.IsSupported)
		{
			SM2Sse41.FillBases<TCurve>(in point, bases);
		}
		else if (SM2AdvSimd.IsSupported)
		{
			SM2AdvSimd.FillBases<TCurve>(in point, bases);
		}
		else
		{
			SM2Scalar.FillBases<TCurve>(in point, bases);
		}
	}

	public static void FillWindows<TCurve>(Span<ulong> windows) where TCurve : struct, IECCurve
	{
		if (SM2Avx512.IsSupported)
		{
			SM2Avx512.FillWindows<TCurve>(windows);
		}
		else if (SM2Avx2.IsSupported)
		{
			SM2Avx2.FillWindows<TCurve>(windows);
		}
		else if (SM2Sse41.IsSupported)
		{
			SM2Sse41.FillWindows<TCurve>(windows);
		}
		else if (SM2AdvSimd.IsSupported)
		{
			SM2AdvSimd.FillWindows<TCurve>(windows);
		}
		else
		{
			SM2Scalar.FillWindows<TCurve>(windows);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void MultiplyFixed(ReadOnlySpan<ulong> windows, in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> result)
	{
		if (SM2Avx512.IsSupported)
		{
			SM2Avx512.MultiplyFixed(windows, in scalar, out result);
		}
		else if (SM2Avx2.IsSupported)
		{
			SM2Avx2.MultiplyFixed(windows, in scalar, out result);
		}
		else if (SM2Sse41.IsSupported)
		{
			SM2Sse41.MultiplyFixed(windows, in scalar, out result);
		}
		else if (SM2AdvSimd.IsSupported)
		{
			SM2AdvSimd.MultiplyFixed(windows, in scalar, out result);
		}
		else
		{
			SM2Scalar.MultiplyFixed(windows, in scalar, out result);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void MultiplyAddFixed(ReadOnlySpan<ulong> windows, in FieldElement<SM2Order> u1, in FieldElement<SM2Order> u2, out JacobianPoint<SM2Field52> result)
	{
		if (SM2Avx512.IsSupported)
		{
			SM2Avx512.MultiplyAddFixed(windows, in u1, in u2, out result);
		}
		else if (SM2Avx2.IsSupported)
		{
			SM2Avx2.MultiplyAddFixed(windows, in u1, in u2, out result);
		}
		else if (SM2Sse41.IsSupported)
		{
			SM2Sse41.MultiplyAddFixed(windows, in u1, in u2, out result);
		}
		else if (SM2AdvSimd.IsSupported)
		{
			SM2AdvSimd.MultiplyAddFixed(windows, in u1, in u2, out result);
		}
		else
		{
			SM2Scalar.MultiplyAddFixed(windows, in u1, in u2, out result);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void MultiplyBaseAndFixed(ReadOnlySpan<ulong> windows, in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> baseResult, out JacobianPoint<SM2Field52> result)
	{
		if (SM2Avx512.IsSupported)
		{
			SM2Avx512.MultiplyBaseAndFixed(windows, in scalar, out baseResult, out result);
		}
		else if (SM2Avx2.IsSupported)
		{
			SM2Avx2.MultiplyBaseAndFixed(windows, in scalar, out baseResult, out result);
		}
		else if (SM2Sse41.IsSupported)
		{
			SM2Sse41.MultiplyBaseAndFixed(windows, in scalar, out baseResult, out result);
		}
		else if (SM2AdvSimd.IsSupported)
		{
			SM2AdvSimd.MultiplyBaseAndFixed(windows, in scalar, out baseResult, out result);
		}
		else
		{
			SM2Scalar.MultiplyBaseAndFixed(windows, in scalar, out baseResult, out result);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void MultiplyAdd(in FieldElement<SM2Order> u1, ReadOnlySpan<AffinePoint<SM2Field52>> pointTable, in FieldElement<SM2Order> u2, out JacobianPoint<SM2Field52> result)
	{
		if (SM2Avx512.IsSupported)
		{
			SM2Avx512.MultiplyAdd(in u1, pointTable, in u2, out result);
		}
		else if (SM2Avx2.IsSupported)
		{
			SM2Avx2.MultiplyAdd(in u1, pointTable, in u2, out result);
		}
		else if (SM2Sse41.IsSupported)
		{
			SM2Sse41.MultiplyAdd(in u1, pointTable, in u2, out result);
		}
		else if (SM2AdvSimd.IsSupported)
		{
			SM2AdvSimd.MultiplyAdd(in u1, pointTable, in u2, out result);
		}
		else
		{
			SM2Scalar.MultiplyAdd(in u1, pointTable, in u2, out result);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Multiply(in AffinePoint<SM2Field52> point, in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> result)
	{
		if (SM2Avx512.IsSupported)
		{
			SM2Avx512.Multiply(in point, in scalar, out result);
		}
		else if (SM2Avx2.IsSupported)
		{
			SM2Avx2.Multiply(in point, in scalar, out result);
		}
		else if (SM2Sse41.IsSupported)
		{
			SM2Sse41.Multiply(in point, in scalar, out result);
		}
		else if (SM2AdvSimd.IsSupported)
		{
			SM2AdvSimd.Multiply(in point, in scalar, out result);
		}
		else
		{
			SM2Scalar.Multiply(in point, in scalar, out result);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void MultiplyAdd(in FieldElement<SM2Order> u1, in AffinePoint<SM2Field52> point, in FieldElement<SM2Order> u2, out JacobianPoint<SM2Field52> result)
	{
		if (SM2Avx512.IsSupported)
		{
			SM2Avx512.MultiplyAdd(in u1, in point, in u2, out result);
		}
		else if (SM2Avx2.IsSupported)
		{
			SM2Avx2.MultiplyAdd(in u1, in point, in u2, out result);
		}
		else if (SM2Sse41.IsSupported)
		{
			SM2Sse41.MultiplyAdd(in u1, in point, in u2, out result);
		}
		else if (SM2AdvSimd.IsSupported)
		{
			SM2AdvSimd.MultiplyAdd(in u1, in point, in u2, out result);
		}
		else
		{
			SM2Scalar.MultiplyAdd(in u1, in point, in u2, out result);
		}
	}

	public static void MultiplyAdd(in AffinePoint<SM2Field52> point, in FieldElement<SM2Order> scalar, in AffinePoint<SM2Field52> otherPoint, in FieldElement<SM2Order> otherScalar, out JacobianPoint<SM2Field52> result)
	{
		Debug.Assert(HasMultiplyAdd);

		SM2Avx512.MultiplyAdd(in point, in scalar, in otherPoint, in otherScalar, out result);
	}

	// Where AVX-512 is, the eight lanes take the chains of half scalars that the comparison of the x of u1·G + u2·Q with r needs, which fewer lanes have no room for.
	public static bool HasMultiplyAddXModOrderEquals => SM2Avx512.IsSupported;

	public static bool MultiplyAddXModOrderEquals(in FieldElement<SM2Order> u1, in AffinePoint<SM2Field52> point, in FieldElement<SM2Order> u2, in FieldElement<SM2Order> r)
	{
		Debug.Assert(HasMultiplyAddXModOrderEquals);

		return SM2Avx512.MultiplyAddXModOrderEquals(in u1, in point, in u2, in r);
	}
}
