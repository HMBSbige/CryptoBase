namespace CryptoBase.EllipticCurves;

// The products of SM2Vector on SM2Field29x8Avx512, k·P as the two chains of SM2OctoFormulas, u1·G + u2·Q without a table as u1·G from the windows of G and u2·Q from those chains, and k·P + l·Q as a chain of each in one half of the lanes.
internal readonly struct SM2Avx512 : ISM2Kernel
{
	public static bool IsSupported => SM2Field29x8Avx512.IsSupported;

	public static void MultiplyBase(in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> result)
	{
		SM2Vector<SM2Field29x8Avx512>.MultiplyBase(in scalar, out result);
	}

	public static void FillBases<TCurve>(in AffinePoint<SM2Field52> point, Span<JacobianPoint<SM2Field52>> bases) where TCurve : struct, IECCurve
	{
		SM2QuadFormulas.FillBases(in point, TCurve.GeneratorWindowWidth, bases);
	}

	public static void FillWindows<TCurve>(Span<ulong> windows) where TCurve : struct, IECCurve
	{
		SM2Vector<SM2Field29x8Avx512>.FillWindows<TCurve>(windows);
	}

	public static void MultiplyFixed(ReadOnlySpan<ulong> windows, in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> result)
	{
		SM2Vector<SM2Field29x8Avx512>.MultiplyFixed(windows, in scalar, out result);
	}

	public static void MultiplyAddFixed(ReadOnlySpan<ulong> windows, in FieldElement<SM2Order> u1, in FieldElement<SM2Order> u2, out JacobianPoint<SM2Field52> result)
	{
		SM2Vector<SM2Field29x8Avx512>.MultiplyAddFixed(windows, in u1, in u2, out result);
	}

	public static void MultiplyBaseAndFixed(ReadOnlySpan<ulong> windows, in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> baseResult, out JacobianPoint<SM2Field52> result)
	{
		SM2Vector<SM2Field29x8Avx512>.MultiplyBaseAndFixed(windows, in scalar, out baseResult, out result);
	}

	public static void MultiplyAdd(in FieldElement<SM2Order> u1, ReadOnlySpan<AffinePoint<SM2Field52>> pointTable, in FieldElement<SM2Order> u2, out JacobianPoint<SM2Field52> result)
	{
		SM2Vector<SM2Field29x8Avx512>.MultiplyAdd(in u1, pointTable, in u2, out result);
	}

	public static void Multiply(in AffinePoint<SM2Field52> point, in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> result)
	{
		SM2OctoFormulas.Multiply(in point, in scalar, out result);
	}

	public static void MultiplyAdd(in FieldElement<SM2Order> u1, in AffinePoint<SM2Field52> point, in FieldElement<SM2Order> u2, out JacobianPoint<SM2Field52> result)
	{
		SM2OctoFormulas.MultiplyVariableTime(in point, in u2, out result);
		SM2Vector<SM2Field29x8Avx512>.MultiplyBaseVariableTime(in u1, out JacobianPoint<SM2Field52> product);
		ECVariableTimeGroup<SM2Curve, SM2Field52, SM2Order>.Add(ref result, in product);
	}

	public static void MultiplyAdd(in AffinePoint<SM2Field52> point, in FieldElement<SM2Order> scalar, in AffinePoint<SM2Field52> otherPoint, in FieldElement<SM2Order> otherScalar, out JacobianPoint<SM2Field52> result)
	{
		SM2OctoFormulas.MultiplyAdd(in point, in scalar, in otherPoint, in otherScalar, out result);
	}

	// Whether S = u1·G + u2·Q is not the point at infinity and its x is r mod n, for u1, u2 and r below n, as ECVariableTimeGroup.XModOrderEquals tells it of MultiplyAdd. Every input is public. For r ≥ p − n, r is the only x below p that is r mod n, so S must be ±R for R = (r, y) and a square root y of r³ − 3r + b, and r with no such y gives false; r below p − n, where S may also have the x of r + n, goes to MultiplyAdd. S = ±R just if v2·S = ±v2·R, as v2 is not 0 mod n, and HalfScalars gives v1 = v2·u2 mod n with v1 and v2 below 2^128, so that v2·S = (v2·u1)·G + v1·Q. The chains of SM2OctoFormulas take v1·Q and |v2|·R side by side, each from the odd scalar that the value or one more than it is, which one subtraction of the point corrects; the sum T of v1·Q and (v2·u1)·G from the windows of G must not be the point at infinity, which it is just if S is, and must have the x of |v2|·R.
	[SkipLocalsInit]
	internal static bool MultiplyAddXModOrderEquals(in FieldElement<SM2Order> u1, in AffinePoint<SM2Field52> point, in FieldElement<SM2Order> u2, in FieldElement<SM2Order> r)
	{
		ReadOnlySpan<ulong> x = FieldElement<SM2Order>.GetLimbs(in r);
		ReadOnlySpan<ulong> gap = FieldGap;

		if ((x[3] | x[2]) is 0 && (x[1] < gap[1] || x[1] == gap[1] && x[0] < gap[0]))
		{
			MultiplyAdd(in u1, in point, in u2, out JacobianPoint<SM2Field52> sum);
			return ECVariableTimeGroup<SM2Curve, SM2Field52, SM2Order>.XModOrderEquals(in sum, in r);
		}

		Unsafe.SkipInit(out AffinePoint<SM2Field52> lifted);
		SM2Field52.FromLimbs(x, out SM2Field52 plain);
		SM2Field52.ToMontgomery(in plain, out lifted.X);
		ECGroup<SM2Curve, SM2Field52, SM2Order>.RightSide(in lifted.X, out SM2Field52 square);

		if (!SM2Field52.TrySquareRoot(in square, out lifted.Y))
		{
			return false;
		}

		HalfScalars<SM2Order>.Split(in u2, out UInt128 first, out UInt128 second, out bool negative);
		Span<sbyte> digits = stackalloc sbyte[2 * SM2OddWindows.HalfCount];
		Span<sbyte> otherDigits = digits.Slice(SM2OddWindows.HalfCount);
		digits = digits.Slice(0, SM2OddWindows.HalfCount);
		SM2OddWindows.RecodeHalf(first | 1, digits);
		SM2OddWindows.RecodeHalf(second | 1, otherDigits);
		SM2OctoFormulas.MultiplyVariableTime(in point, digits, in lifted, otherDigits, out JacobianPoint<SM2Field52> total, out JacobianPoint<SM2Field52> product);

		if ((first & 1) == 0)
		{
			ECVariableTimeGroup<SM2Curve, SM2Field52, SM2Order>.Subtract(ref total, in point);
		}

		if ((second & 1) == 0)
		{
			ECVariableTimeGroup<SM2Curve, SM2Field52, SM2Order>.Subtract(ref product, in lifted);
		}

		// |v2|·R times a plain u1 is the plain |v2|·u1, negated for v2 < 0.
		Unsafe.SkipInit(out FieldElement<SM2Order> factor);
		Span<ulong> limbs = MemoryMarshal.Cast<FieldElement<SM2Order>, ulong>(new Span<FieldElement<SM2Order>>(ref factor));
		limbs[0] = (ulong)second;
		limbs[1] = (ulong)(second >> 64);
		limbs[2] = 0;
		limbs[3] = 0;
		FieldElement<SM2Order>.ToMontgomery(in factor, out factor);
		FieldElement<SM2Order>.Multiply(in factor, in u1, out factor);

		if (negative)
		{
			FieldElement<SM2Order> zero = default;
			FieldElement<SM2Order>.Subtract(in zero, in factor, out factor);
		}

		SM2Vector<SM2Field29x8Avx512>.MultiplyBaseVariableTime(in factor, out JacobianPoint<SM2Field52> baseProduct);
		ECVariableTimeGroup<SM2Curve, SM2Field52, SM2Order>.Add(ref total, in baseProduct);
		return !total.IsInfinity && ECVariableTimeGroup<SM2Curve, SM2Field52, SM2Order>.XEquals(in total, in product);
	}

	// p − n, below 2^128.
	internal static ReadOnlySpan<ulong> FieldGap => [0xAC440BF6C62ABEDCUL, 0x8DFC2093DE39FAD5UL];
}
