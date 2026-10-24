using static CryptoBase.EllipticCurves.LimbArithmetic;

namespace CryptoBase.EllipticCurves;

// Scalars are plain values below n. Nothing here branches on or indexes by a point or a scalar, except where a method says that its input is public.
internal static class EcGroup<TCurve, TField, TOrder>
	where TCurve : struct, IEcCurve
	where TField : unmanaged, IMontgomeryModulus
	where TOrder : unmanaged, IMontgomeryModulus
{
	private const int WindowWidth = 5;

	internal static int EncodedLength => 1 + 2 * TField.ByteLength;

	private static ref readonly FieldElement<TField> B => ref FieldElement<TField>.FromLimbs(TCurve.B);

	// Complete for a = −3 on a curve of odd order: any two points, equal, opposite or at infinity. The result may be either input: it is written only after the last read of the inputs.
	internal static void Add(in ProjectivePoint<TField> left, in ProjectivePoint<TField> right, out ProjectivePoint<TField> result)
	{
		FieldElement<TField>.Multiply(in left.X, in right.X, out FieldElement<TField> t0);
		FieldElement<TField>.Multiply(in left.Y, in right.Y, out FieldElement<TField> t1);
		FieldElement<TField>.Multiply(in left.Z, in right.Z, out FieldElement<TField> t2);
		FieldElement<TField>.Add(in left.X, in left.Y, out FieldElement<TField> t3);
		FieldElement<TField>.Add(in right.X, in right.Y, out FieldElement<TField> t4);
		FieldElement<TField>.Multiply(in t3, in t4, out t3);
		FieldElement<TField>.Add(in t0, in t1, out t4);
		FieldElement<TField>.Subtract(in t3, in t4, out t3);
		FieldElement<TField>.Add(in left.Y, in left.Z, out t4);
		FieldElement<TField>.Add(in right.Y, in right.Z, out FieldElement<TField> x3);
		FieldElement<TField>.Multiply(in t4, in x3, out t4);
		FieldElement<TField>.Add(in t1, in t2, out x3);
		FieldElement<TField>.Subtract(in t4, in x3, out t4);
		FieldElement<TField>.Add(in left.X, in left.Z, out x3);
		FieldElement<TField>.Add(in right.X, in right.Z, out FieldElement<TField> y3);
		FieldElement<TField>.Multiply(in x3, in y3, out x3);
		FieldElement<TField>.Add(in t0, in t2, out y3);
		FieldElement<TField>.Subtract(in x3, in y3, out y3);
		FieldElement<TField>.Multiply(in B, in t2, out FieldElement<TField> z3);
		FieldElement<TField>.Subtract(in y3, in z3, out x3);
		FieldElement<TField>.Add(in x3, in x3, out z3);
		FieldElement<TField>.Add(in x3, in z3, out x3);
		FieldElement<TField>.Subtract(in t1, in x3, out z3);
		FieldElement<TField>.Add(in t1, in x3, out x3);
		FieldElement<TField>.Multiply(in B, in y3, out y3);
		FieldElement<TField>.Add(in t2, in t2, out t1);
		FieldElement<TField>.Add(in t1, in t2, out t2);
		FieldElement<TField>.Subtract(in y3, in t2, out y3);
		FieldElement<TField>.Subtract(in y3, in t0, out y3);
		FieldElement<TField>.Add(in y3, in y3, out t1);
		FieldElement<TField>.Add(in t1, in y3, out y3);
		FieldElement<TField>.Add(in t0, in t0, out t1);
		FieldElement<TField>.Add(in t1, in t0, out t0);
		FieldElement<TField>.Subtract(in t0, in t2, out t0);
		FieldElement<TField>.Multiply(in t4, in y3, out t1);
		FieldElement<TField>.Multiply(in t0, in y3, out t2);
		FieldElement<TField>.Multiply(in x3, in z3, out y3);
		FieldElement<TField>.Add(in y3, in t2, out y3);
		FieldElement<TField>.Multiply(in t3, in x3, out x3);
		FieldElement<TField>.Subtract(in x3, in t1, out result.X);
		FieldElement<TField>.Multiply(in t4, in z3, out z3);
		FieldElement<TField>.Multiply(in t3, in t0, out t1);
		FieldElement<TField>.Add(in z3, in t1, out result.Z);
		result.Y = y3;
	}

	// As above, with an affine right, which cannot be the point at infinity; the left may be.
	internal static void Add(in ProjectivePoint<TField> left, in AffinePoint<TField> right, out ProjectivePoint<TField> result)
	{
		FieldElement<TField>.Multiply(in left.X, in right.X, out FieldElement<TField> t0);
		FieldElement<TField>.Multiply(in left.Y, in right.Y, out FieldElement<TField> t1);
		FieldElement<TField>.Add(in right.X, in right.Y, out FieldElement<TField> t3);
		FieldElement<TField>.Add(in left.X, in left.Y, out FieldElement<TField> t4);
		FieldElement<TField>.Multiply(in t3, in t4, out t3);
		FieldElement<TField>.Add(in t0, in t1, out t4);
		FieldElement<TField>.Subtract(in t3, in t4, out t3);
		FieldElement<TField>.Multiply(in right.Y, in left.Z, out t4);
		FieldElement<TField>.Add(in t4, in left.Y, out t4);
		FieldElement<TField>.Multiply(in right.X, in left.Z, out FieldElement<TField> y3);
		FieldElement<TField>.Add(in y3, in left.X, out y3);
		FieldElement<TField>.Multiply(in B, in left.Z, out FieldElement<TField> z3);
		FieldElement<TField>.Subtract(in y3, in z3, out FieldElement<TField> x3);
		FieldElement<TField>.Add(in x3, in x3, out z3);
		FieldElement<TField>.Add(in x3, in z3, out x3);
		FieldElement<TField>.Subtract(in t1, in x3, out z3);
		FieldElement<TField>.Add(in t1, in x3, out x3);
		FieldElement<TField>.Multiply(in B, in y3, out y3);
		FieldElement<TField>.Add(in left.Z, in left.Z, out t1);
		FieldElement<TField>.Add(in t1, in left.Z, out FieldElement<TField> t2);
		FieldElement<TField>.Subtract(in y3, in t2, out y3);
		FieldElement<TField>.Subtract(in y3, in t0, out y3);
		FieldElement<TField>.Add(in y3, in y3, out t1);
		FieldElement<TField>.Add(in t1, in y3, out y3);
		FieldElement<TField>.Add(in t0, in t0, out t1);
		FieldElement<TField>.Add(in t1, in t0, out t0);
		FieldElement<TField>.Subtract(in t0, in t2, out t0);
		FieldElement<TField>.Multiply(in t4, in y3, out t1);
		FieldElement<TField>.Multiply(in t0, in y3, out t2);
		FieldElement<TField>.Multiply(in x3, in z3, out y3);
		FieldElement<TField>.Add(in y3, in t2, out y3);
		FieldElement<TField>.Multiply(in t3, in x3, out x3);
		FieldElement<TField>.Subtract(in x3, in t1, out result.X);
		FieldElement<TField>.Multiply(in t4, in z3, out z3);
		FieldElement<TField>.Multiply(in t3, in t0, out t1);
		FieldElement<TField>.Add(in z3, in t1, out result.Z);
		result.Y = y3;
	}

	internal static void Double(in ProjectivePoint<TField> value, out ProjectivePoint<TField> result)
	{
		FieldElement<TField>.Square(in value.X, out FieldElement<TField> t0);
		FieldElement<TField>.Square(in value.Y, out FieldElement<TField> t1);
		FieldElement<TField>.Square(in value.Z, out FieldElement<TField> t2);
		FieldElement<TField>.Multiply(in value.X, in value.Y, out FieldElement<TField> t3);
		FieldElement<TField>.Add(in t3, in t3, out t3);
		FieldElement<TField>.Multiply(in value.X, in value.Z, out FieldElement<TField> z3);
		FieldElement<TField>.Add(in z3, in z3, out z3);
		FieldElement<TField>.Multiply(in B, in t2, out FieldElement<TField> y3);
		FieldElement<TField>.Subtract(in y3, in z3, out y3);
		FieldElement<TField>.Add(in y3, in y3, out FieldElement<TField> x3);
		FieldElement<TField>.Add(in x3, in y3, out y3);
		FieldElement<TField>.Subtract(in t1, in y3, out x3);
		FieldElement<TField>.Add(in t1, in y3, out y3);
		FieldElement<TField>.Multiply(in x3, in y3, out y3);
		FieldElement<TField>.Multiply(in x3, in t3, out x3);
		FieldElement<TField>.Add(in t2, in t2, out t3);
		FieldElement<TField>.Add(in t2, in t3, out t2);
		FieldElement<TField>.Multiply(in B, in z3, out z3);
		FieldElement<TField>.Subtract(in z3, in t2, out z3);
		FieldElement<TField>.Subtract(in z3, in t0, out z3);
		FieldElement<TField>.Add(in z3, in z3, out t3);
		FieldElement<TField>.Add(in z3, in t3, out z3);
		FieldElement<TField>.Add(in t0, in t0, out t3);
		FieldElement<TField>.Add(in t3, in t0, out t0);
		FieldElement<TField>.Subtract(in t0, in t2, out t0);
		FieldElement<TField>.Multiply(in t0, in z3, out t0);
		FieldElement<TField>.Add(in y3, in t0, out y3);
		FieldElement<TField>.Multiply(in value.Y, in value.Z, out t0);
		FieldElement<TField>.Add(in t0, in t0, out t0);
		FieldElement<TField>.Multiply(in t0, in z3, out z3);
		FieldElement<TField>.Subtract(in x3, in z3, out result.X);
		FieldElement<TField>.Multiply(in t0, in t1, out z3);
		FieldElement<TField>.Add(in z3, in z3, out z3);
		FieldElement<TField>.Add(in z3, in z3, out result.Z);
		result.Y = y3;
	}

	// Sets result to k·G for k below n. Neither the time nor the addresses depend on k. The projective form of the result depends on k and not only on k·G, so for a secret k use MultiplyBaseToAffine or MultiplyBaseReduceX, which clear it.
	[SkipLocalsInit]
	internal static void MultiplyBase(in FieldElement<TOrder> scalar, out ProjectivePoint<TField> result)
	{
		int entries = EcGeneratorTable<TCurve, TField, TOrder>.WindowLength;
		Span<sbyte> digits = stackalloc sbyte[EcGeneratorTable<TCurve, TField, TOrder>.WindowCount];
		Recode(in scalar, TCurve.GeneratorWindowWidth, digits);
		ref AffinePoint<TField> window = ref MemoryMarshal.GetArrayDataReference(EcGeneratorTable<TCurve, TField, TOrder>.Entries);
		result = ProjectivePoint<TField>.Identity;
		Unsafe.SkipInit(out AffinePoint<TField> entry);
		Unsafe.SkipInit(out ProjectivePoint<TField> sum);

		for (int i = 0; i < digits.Length; ++i)
		{
			// A digit of 0 selects (0, 0), which is not a point, so the sum is discarded.
			Select(in window, entries, digits[i], out entry);
			Add(in result, in entry, out sum);
			ProjectivePoint<TField>.ConditionalSelect(ZeroMask((ulong)digits[i]), in result, in sum, out result);
			window = ref Unsafe.Add(ref window, entries);
		}

		digits.ZeroMemory();
		entry.ZeroMemory();
		sum.ZeroMemory();
	}

	// Sets result to k·P for a point P on the curve and k below n. Neither the time nor the addresses depend on k or P. As with MultiplyBase, the projective form depends on k, so for a secret k use TryMultiplyExportX.
	[SkipLocalsInit]
	internal static void Multiply(in AffinePoint<TField> point, in FieldElement<TOrder> scalar, out ProjectivePoint<TField> result)
	{
		Span<sbyte> digits = stackalloc sbyte[DigitCount(WindowWidth)];
		Span<ProjectivePoint<TField>> multiples = stackalloc ProjectivePoint<TField>[(1 << WindowWidth - 1) + 1];
		Recode(in scalar, WindowWidth, digits);
		multiples[0] = ProjectivePoint<TField>.Identity;
		ProjectivePoint<TField>.FromAffine(in point, out multiples[1]);
		Double(in multiples[1], out multiples[2]);

		for (int j = 3; j < multiples.Length; ++j)
		{
			Add(in multiples[j - 1], in point, out multiples[j]);
		}

		Select(multiples, digits[^1], out result);
		Unsafe.SkipInit(out ProjectivePoint<TField> entry);

		for (int i = digits.Length - 2; i >= 0; --i)
		{
			for (int k = 0; k < WindowWidth; ++k)
			{
				Double(in result, out result);
			}

			Select(multiples, digits[i], out entry);
			Add(in result, in entry, out result);
		}

		digits.ZeroMemory();
		entry.ZeroMemory();
	}

	// k must lie in [1, n − 1].
	internal static void MultiplyBaseToAffine(in FieldElement<TOrder> scalar, out AffinePoint<TField> result)
	{
		MultiplyBase(in scalar, out ProjectivePoint<TField> product);
		ToAffine(in product, out result);
		product.ZeroMemory();
	}

	// k must lie in [1, n − 1].
	internal static void MultiplyBaseReduceX(in FieldElement<TOrder> scalar, out FieldElement<TOrder> result)
	{
		MultiplyBase(in scalar, out ProjectivePoint<TField> product);
		ReduceX(in product, out result);
		product.ZeroMemory();
	}

	// For a point P on the curve and k below n. Returns false, leaving destination unchanged, if k·P is the point at infinity; the return value reveals that anyway, so it may decide a branch.
	internal static bool TryMultiplyExportX(in AffinePoint<TField> point, in FieldElement<TOrder> scalar, Span<byte> destination)
	{
		Multiply(in point, in scalar, out ProjectivePoint<TField> product);
		bool valid = ProjectivePoint<TField>.IsIdentity(in product) is 0;

		if (valid)
		{
			ExportX(in product, destination);
		}

		product.ZeroMemory();
		return valid;
	}

	// The point at infinity gives (0, 0), which is not on the curve.
	internal static void ToAffine(in ProjectivePoint<TField> point, out AffinePoint<TField> result)
	{
		FieldElement<TField>.Invert(in point.Z, out FieldElement<TField> inverse);
		FieldElement<TField>.Multiply(in point.X, in inverse, out result.X);
		FieldElement<TField>.Multiply(in point.Y, in inverse, out result.Y);
		// With the affine form, Z⁻¹ gives back the projective one.
		inverse.ZeroMemory();
	}

	// None of the points may be the point at infinity. They are public, so nothing is cleared.
	internal static void ToAffine(ReadOnlySpan<ProjectivePoint<TField>> points, Span<AffinePoint<TField>> result)
	{
		Debug.Assert(points.Length > 0 && result.Length == points.Length);

		FieldElement<TField>[] products = new FieldElement<TField>[points.Length];
		products[0] = points[0].Z;

		for (int i = 1; i < points.Length; ++i)
		{
			FieldElement<TField>.Multiply(in products[i - 1], in points[i].Z, out products[i]);
		}

		FieldElement<TField>.Invert(in products[^1], out FieldElement<TField> inverse);

		for (int i = points.Length - 1; i > 0; --i)
		{
			FieldElement<TField>.Multiply(in inverse, in products[i - 1], out FieldElement<TField> zInverse);
			FieldElement<TField>.Multiply(in inverse, in points[i].Z, out inverse);
			FieldElement<TField>.Multiply(in points[i].X, in zInverse, out result[i].X);
			FieldElement<TField>.Multiply(in points[i].Y, in zInverse, out result[i].Y);
		}

		FieldElement<TField>.Multiply(in points[0].X, in inverse, out result[0].X);
		FieldElement<TField>.Multiply(in points[0].Y, in inverse, out result[0].Y);
	}

	// point must not be the point at infinity.
	internal static void ExportX(in ProjectivePoint<TField> point, Span<byte> destination)
	{
		FieldElement<TField>.Invert(in point.Z, out FieldElement<TField> inverse);
		// The inverse is Z⁻¹R; with R taken off, the product with X comes out in plain form.
		FieldElement<TField>.FromMontgomery(in inverse, out inverse);
		FieldElement<TField>.Multiply(in point.X, in inverse, out FieldElement<TField> x);
		FieldElement<TField>.Export(in x, destination);
		x.ZeroMemory();
		inverse.ZeroMemory();
	}

	// point must not be the point at infinity.
	[SkipLocalsInit]
	internal static void ReduceX(in ProjectivePoint<TField> point, out FieldElement<TOrder> result)
	{
		Debug.Assert(TField.ByteLength == TOrder.ByteLength);

		Span<byte> x = stackalloc byte[TField.ByteLength];
		ExportX(in point, x);
		FieldElement<TOrder>.ImportReduced(x, out result);
	}

	internal static void Encode(in AffinePoint<TField> point, Span<byte> destination)
	{
		Debug.Assert(destination.Length == EncodedLength);

		int length = TField.ByteLength;
		destination[0] = 0x04;
		FieldElement<TField>.FromMontgomery(in point.X, out FieldElement<TField> coordinate);
		FieldElement<TField>.Export(in coordinate, destination.Slice(1, length));
		FieldElement<TField>.FromMontgomery(in point.Y, out coordinate);
		FieldElement<TField>.Export(in coordinate, destination.Slice(1 + length, length));
	}

	// The cofactor is 1, so every point on the curve is in the group of G. The input is public, so the checks may branch.
	internal static bool TryDecode(ReadOnlySpan<byte> source, out AffinePoint<TField> result)
	{
		int length = TField.ByteLength;

		if (source.Length != 1 + 2 * length
			|| source[0] is not 0x04
			|| !FieldElement<TField>.TryImport(source.Slice(1, length), out FieldElement<TField> x)
			|| !FieldElement<TField>.TryImport(source.Slice(1 + length, length), out FieldElement<TField> y))
		{
			result = default;
			return false;
		}

		FieldElement<TField>.ToMontgomery(in x, out result.X);
		FieldElement<TField>.ToMontgomery(in y, out result.Y);

		if (!IsOnCurve(in result))
		{
			result = default;
			return false;
		}

		return true;
	}

	private static bool IsOnCurve(in AffinePoint<TField> point)
	{
		FieldElement<TField>.Square(in point.X, out FieldElement<TField> right);
		FieldElement<TField>.Multiply(in right, in point.X, out right);
		FieldElement<TField>.MultiplySmall(in point.X, 3, out FieldElement<TField> threeX);
		FieldElement<TField>.Subtract(in right, in threeX, out right);
		FieldElement<TField>.Add(in right, in B, out right);
		FieldElement<TField>.Square(in point.Y, out FieldElement<TField> left);
		return FieldElement<TField>.AreEqual(in left, in right) is not 0;
	}

	// The digit beyond ⌊N/w⌋, N = TOrder.BitLength, holds the top N mod w bits, if any, and the carry into them.
	internal static int DigitCount(int width)
	{
		return TOrder.BitLength / width + 1;
	}

	// Writes digits d_i in [−2^(w − 1) + 1, 2^(w − 1)] with k = Σ d_i·2^(wi). Window i of k plus the carry from below, v in [0, 2^w], gives d_i = v and no carry if v ≤ 2^(w − 1), and d_i = v − 2^w and a carry otherwise. The top window holds at most w − 1 bits of k, so v ≤ 2^(w − 1) there and no carry is lost. The carry and digits come from arithmetic on v, not comparisons, and only i decides which limbs are read.
	private static void Recode(in FieldElement<TOrder> scalar, int width, Span<sbyte> digits)
	{
		// Digits up to 2^(w − 1) must fit in an sbyte.
		Debug.Assert(width is > 0 and < 8);
		Debug.Assert(digits.Length == DigitCount(width));

		ReadOnlySpan<ulong> limbs = FieldElement<TOrder>.GetLimbs(in scalar);
		uint mask = (1u << width) - 1;
		uint half = 1u << width - 1;
		uint carry = 0;

		for (int i = 0; i < digits.Length; ++i)
		{
			uint value = ((uint)ReadBits(limbs, i * width) & mask) + carry;
			carry = half - value >> 31;
			digits[i] = (sbyte)(value - (carry << width));
		}
	}

	// window holds the multiples 1·B to entries·B of a point B. A digit of 0 gives (0, 0), which is not a point.
	internal static void Select(ref readonly AffinePoint<TField> window, int entries, int digit, out AffinePoint<TField> result)
	{
		int sign = digit >> 31;
		MaskedSelect.Lookup(in window, entries, (uint)((digit ^ sign) - sign) - 1, out result);
		ConditionalNegate((ulong)sign, ref result.Y);
	}

	// multiples holds 0·P to (multiples.Length − 1)·P.
	internal static void Select(ReadOnlySpan<ProjectivePoint<TField>> multiples, int digit, out ProjectivePoint<TField> result)
	{
		int sign = digit >> 31;
		MaskedSelect.Lookup(in MemoryMarshal.GetReference(multiples), multiples.Length, (uint)((digit ^ sign) - sign), out result);
		ConditionalNegate((ulong)sign, ref result.Y);
	}

	private static void ConditionalNegate(ulong mask, ref FieldElement<TField> value)
	{
		FieldElement<TField>.Negate(in value, out FieldElement<TField> negated);
		FieldElement<TField>.ConditionalSelect(mask, in negated, in value, out value);
	}
}
