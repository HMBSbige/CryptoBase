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

	// For a = −3. Holds for every point: Z = 0 gives Z3 = 0, and no other point has Y = 0, as a curve of odd order has no point of order 2. The result may be the input.
	internal static void Double(in JacobianPoint<TField> value, out JacobianPoint<TField> result)
	{
		FieldElement<TField>.Square(in value.Y, out FieldElement<TField> gamma);
		FieldElement<TField>.Add(in gamma, in gamma, out FieldElement<TField> twoGamma);
		FieldElement<TField>.Multiply(in value.X, in twoGamma, out FieldElement<TField> fourBeta);
		FieldElement<TField>.Add(in fourBeta, in fourBeta, out fourBeta);
		FieldElement<TField>.Square(in value.Z, out FieldElement<TField> delta);
		FieldElement<TField>.Subtract(in value.X, in delta, out FieldElement<TField> alpha);
		FieldElement<TField>.Add(in value.X, in delta, out delta);
		FieldElement<TField>.Multiply(in alpha, in delta, out alpha);
		FieldElement<TField>.Add(in alpha, in alpha, out delta);
		FieldElement<TField>.Add(in alpha, in delta, out alpha);
		FieldElement<TField>.Multiply(in value.Y, in value.Z, out FieldElement<TField> z3);
		FieldElement<TField>.Add(in z3, in z3, out result.Z);
		FieldElement<TField>.Square(in alpha, out FieldElement<TField> x3);
		FieldElement<TField>.Subtract(in x3, in fourBeta, out x3);
		FieldElement<TField>.Subtract(in x3, in fourBeta, out x3);
		FieldElement<TField>.Subtract(in fourBeta, in x3, out fourBeta);
		FieldElement<TField>.Multiply(in alpha, in fourBeta, out alpha);
		FieldElement<TField>.Square(in twoGamma, out twoGamma);
		FieldElement<TField>.Add(in twoGamma, in twoGamma, out twoGamma);
		FieldElement<TField>.Subtract(in alpha, in twoGamma, out result.Y);
		result.X = x3;
	}

	// Any two points, equal, opposite or at infinity: masks take the other input where one is at infinity and the double where the points are equal. The result may be either input: it is written only after the last read of the inputs.
	internal static void Add(in JacobianPoint<TField> left, in JacobianPoint<TField> right, out JacobianPoint<TField> result)
	{
		ulong equal = AddDistinct(in left, in right, out JacobianPoint<TField> sum);
		Double(in left, out JacobianPoint<TField> twice);
		JacobianPoint<TField>.ConditionalSelect(equal, in twice, in sum, out sum);
		JacobianPoint<TField>.ConditionalSelect(FieldElement<TField>.IsZero(in left.Z), in right, in sum, out sum);
		JacobianPoint<TField>.ConditionalSelect(FieldElement<TField>.IsZero(in right.Z), in left, in sum, out result);
	}

	// As above, with an affine right, which cannot be the point at infinity; the left may be.
	internal static void Add(in JacobianPoint<TField> left, in AffinePoint<TField> right, out JacobianPoint<TField> result)
	{
		ulong equal = AddDistinct(in left, in right, out JacobianPoint<TField> sum);
		Double(in left, out JacobianPoint<TField> twice);
		JacobianPoint<TField>.ConditionalSelect(equal, in twice, in sum, out sum);
		JacobianPoint<TField>.ConditionalSelect(FieldElement<TField>.IsZero(in left.Z), in right, in sum, out result);
	}

	// Sets result to left + right for points that are not the point at infinity, except that equal points give (0, 0, 0); opposite points give Z = 0, the point at infinity. Returns ulong.MaxValue if the points are equal, which is where H = 0 and R = 0, and 0 otherwise. The result may be either input.
	internal static ulong AddDistinct(in JacobianPoint<TField> left, in JacobianPoint<TField> right, out JacobianPoint<TField> result)
	{
		FieldElement<TField>.Square(in left.Z, out FieldElement<TField> z1z1);
		FieldElement<TField>.Square(in right.Z, out FieldElement<TField> z2z2);
		FieldElement<TField>.Multiply(in left.X, in z2z2, out FieldElement<TField> u1);
		FieldElement<TField>.Multiply(in right.X, in z1z1, out FieldElement<TField> h);
		FieldElement<TField>.Subtract(in h, in u1, out h);
		FieldElement<TField>.Multiply(in z2z2, in right.Z, out z2z2);
		FieldElement<TField>.Multiply(in left.Y, in z2z2, out FieldElement<TField> s1);
		FieldElement<TField>.Multiply(in z1z1, in left.Z, out z1z1);
		FieldElement<TField>.Multiply(in right.Y, in z1z1, out FieldElement<TField> r);
		FieldElement<TField>.Subtract(in r, in s1, out r);
		FieldElement<TField>.Add(in r, in r, out r);
		ulong equal = FieldElement<TField>.IsZero(in h) & FieldElement<TField>.IsZero(in r);
		FieldElement<TField>.Multiply(in left.Z, in right.Z, out FieldElement<TField> z3);
		FieldElement<TField>.Multiply(in z3, in h, out z3);
		FieldElement<TField>.Add(in z3, in z3, out result.Z);
		FieldElement<TField>.Square(in h, out FieldElement<TField> i);
		FieldElement<TField>.Add(in i, in i, out i);
		FieldElement<TField>.Add(in i, in i, out i);
		FieldElement<TField>.Multiply(in h, in i, out FieldElement<TField> j);
		FieldElement<TField>.Multiply(in u1, in i, out FieldElement<TField> v);
		FieldElement<TField>.Multiply(in s1, in j, out s1);
		Combine(in r, in j, in v, in s1, out result.X, out result.Y);
		return equal;
	}

	// As above, with an affine right.
	internal static ulong AddDistinct(in JacobianPoint<TField> left, in AffinePoint<TField> right, out JacobianPoint<TField> result)
	{
		FieldElement<TField>.Square(in left.Z, out FieldElement<TField> zz);
		FieldElement<TField>.Multiply(in right.X, in zz, out FieldElement<TField> h);
		FieldElement<TField>.Subtract(in h, in left.X, out h);
		FieldElement<TField>.Multiply(in zz, in left.Z, out zz);
		FieldElement<TField>.Multiply(in right.Y, in zz, out FieldElement<TField> r);
		FieldElement<TField>.Subtract(in r, in left.Y, out r);
		FieldElement<TField>.Add(in r, in r, out r);
		ulong equal = FieldElement<TField>.IsZero(in h) & FieldElement<TField>.IsZero(in r);
		FieldElement<TField>.Square(in h, out FieldElement<TField> i);
		FieldElement<TField>.Add(in i, in i, out i);
		FieldElement<TField>.Add(in i, in i, out i);
		FieldElement<TField>.Multiply(in h, in i, out FieldElement<TField> j);
		FieldElement<TField>.Multiply(in left.X, in i, out FieldElement<TField> v);
		FieldElement<TField>.Multiply(in left.Y, in j, out FieldElement<TField> yj);
		FieldElement<TField>.Multiply(in left.Z, in h, out h);
		FieldElement<TField>.Add(in h, in h, out result.Z);
		Combine(in r, in j, in v, in yj, out result.X, out result.Y);
		return equal;
	}

	// Sets result to k·G for k below n. Neither the time nor the addresses depend on k. The Jacobian form of the result depends on k and not only on k·G, so for a secret k use MultiplyBaseToAffine or MultiplyBaseReduceX, which clear it.
	[SkipLocalsInit]
	internal static void MultiplyBase(in FieldElement<TOrder> scalar, out JacobianPoint<TField> result)
	{
		int entries = EcGeneratorTable<TCurve, TField, TOrder>.WindowLength;
		Span<sbyte> digits = stackalloc sbyte[EcGeneratorTable<TCurve, TField, TOrder>.WindowCount];
		Recode(in scalar, TCurve.GeneratorWindowWidth, digits);
		ref AffinePoint<TField> window = ref MemoryMarshal.GetArrayDataReference(EcGeneratorTable<TCurve, TField, TOrder>.Entries);
		Select(in window, entries, digits[0], out AffinePoint<TField> entry);
		// A digit of 0 selects (0, 0), which is not a point: the first window then leaves the point at infinity, Z = 0, and the later ones discard the sum.
		result = default;
		JacobianPoint<TField>.ConditionalSelect(~ZeroMask((ulong)digits[0]), in entry, in result, out result);
		Unsafe.SkipInit(out JacobianPoint<TField> sum);

		// Window i adds d·2^(wi)·G, 1 ≤ |d| ≤ 2^(w − 1), to L·G with L = Σ_{j<i} d_j·2^(wj), so −2^(wi)/2 < L < 2^(wi). Opposite points give Z = 0, which is right. Equal ones need L − d·2^(wi), which is not 0, to be a multiple of n. Let t = ⌊N/w⌋ for N = TOrder.BitLength, which w does not divide. Below window t, |L − d·2^(wi)| < 2^(w(i + 1)) ≤ 2^(wt) < n. In window t, 0 < d ≤ 2^(N − wt) puts L − d·2^(wt) in (−2n, 0), so it would be −n: then k = 2d·2^(wt) − n < n and L = d·2^(wt) − n > −2^(wt)/2 put d·2^(wt) in (n − 2^(wt)/2, n), which holds no multiple of 2^(wt), as 2^N − n < 2^(wt)/2 for each curve here.
		for (int i = 1; i < digits.Length; ++i)
		{
			window = ref Unsafe.Add(ref window, entries);
			Select(in window, entries, digits[i], out entry);
			_ = AddDistinct(in result, in entry, out sum);
			JacobianPoint<TField>.ConditionalSelect(FieldElement<TField>.IsZero(in result.Z), in entry, in sum, out sum);
			JacobianPoint<TField>.ConditionalSelect(ZeroMask((ulong)digits[i]), in result, in sum, out result);
		}

		digits.ZeroMemory();
		entry.ZeroMemory();
		sum.ZeroMemory();
	}

	// Sets result to k·P for a point P on the curve and k below n. Neither the time nor the addresses depend on k or P. As with MultiplyBase, the Jacobian form depends on k, so for a secret k use TryMultiplyExportX.
	[SkipLocalsInit]
	internal static void Multiply(in AffinePoint<TField> point, in FieldElement<TOrder> scalar, out JacobianPoint<TField> result)
	{
		Span<sbyte> digits = stackalloc sbyte[DigitCount(WindowWidth)];
		Span<JacobianPoint<TField>> multiples = stackalloc JacobianPoint<TField>[1 << WindowWidth - 1];
		Recode(in scalar, WindowWidth, digits);
		JacobianPoint<TField>.FromAffine(in point, out multiples[0]);

		// multiples[j − 1] is j·P. For odd j it is (j − 1)·P + P, two points that are neither equal, opposite nor at infinity, as 2 < j < n.
		for (int j = 2; j <= multiples.Length; ++j)
		{
			if (j % 2 is 0)
			{
				Double(in multiples[j / 2 - 1], out multiples[j - 1]);
			}
			else
			{
				_ = AddDistinct(in multiples[j - 2], in point, out multiples[j - 1]);
			}
		}

		Select(multiples, digits[^1], out result);
		Unsafe.SkipInit(out JacobianPoint<TField> entry);
		Unsafe.SkipInit(out JacobianPoint<TField> sum);

		for (int i = digits.Length - 2; i >= 0; --i)
		{
			for (int k = 0; k < WindowWidth; ++k)
			{
				Double(in result, out result);
			}

			Select(multiples, digits[i], out entry);

			// The doublings leave 32a·P for the value a ≥ 0 of the digits above i, and the entry is d·P, |d| ≤ 16. The digits from i down make more than −32^(i + 1)/2, so 32a < n/32^i + 16. Opposite points give Z = 0, which is right; equal ones need 32a ≡ d (mod n). For i ≥ 1, |32a − d| < n leaves 32a = d, so a = d = 0: both points at infinity, which the masks cover. In window 0, k = 32a + d, so equal points need k ≡ 2d (mod n) with d the low digit of k. For d > 0 that is k = 2d, whose low digit is not d; for d < 0 it is k = n + 2d, whose low digit is d just if d ≡ −n (mod 32). No d in [−15, −1] does that for P-256, n ≡ 17, or P-384, n ≡ 19, but d = −9 does for P-521, n ≡ 9, at k = n − 18, so that window doubles where the points are equal.
			if (i is not 0)
			{
				_ = AddDistinct(in result, in entry, out sum);
				JacobianPoint<TField>.ConditionalSelect(FieldElement<TField>.IsZero(in result.Z), in entry, in sum, out sum);
				JacobianPoint<TField>.ConditionalSelect(ZeroMask((ulong)digits[i]), in result, in sum, out result);
			}
			else
			{
				Add(in result, in entry, out result);
			}
		}

		digits.ZeroMemory();
		entry.ZeroMemory();
		sum.ZeroMemory();
	}

	// k must lie in [1, n − 1].
	internal static void MultiplyBaseToAffine(in FieldElement<TOrder> scalar, out AffinePoint<TField> result)
	{
		MultiplyBase(in scalar, out JacobianPoint<TField> product);
		ToAffine(in product, out result);
		product.ZeroMemory();
	}

	// k must lie in [1, n − 1].
	internal static void MultiplyBaseReduceX(in FieldElement<TOrder> scalar, out FieldElement<TOrder> result)
	{
		MultiplyBase(in scalar, out JacobianPoint<TField> product);
		ReduceX(in product, out result);
		product.ZeroMemory();
	}

	// For a point P on the curve and k below n. Returns false, leaving destination unchanged, if k·P is the point at infinity; the return value reveals that anyway, so it may decide a branch.
	internal static bool TryMultiplyExportX(in AffinePoint<TField> point, in FieldElement<TOrder> scalar, Span<byte> destination)
	{
		Multiply(in point, in scalar, out JacobianPoint<TField> product);
		bool valid = FieldElement<TField>.IsZero(in product.Z) is 0;

		if (valid)
		{
			ExportX(in product, destination);
		}

		product.ZeroMemory();
		return valid;
	}

	// The point at infinity gives (0, 0), which is not on the curve.
	internal static void ToAffine(in JacobianPoint<TField> point, out AffinePoint<TField> result)
	{
		FieldElement<TField>.Invert(in point.Z, out FieldElement<TField> inverse);
		FieldElement<TField>.Square(in inverse, out FieldElement<TField> square);
		FieldElement<TField>.Multiply(in point.X, in square, out result.X);
		FieldElement<TField>.Multiply(in square, in inverse, out inverse);
		FieldElement<TField>.Multiply(in point.Y, in inverse, out result.Y);
		// With the affine form, Z⁻² or Z⁻³ would give back the Jacobian one.
		square.ZeroMemory();
		inverse.ZeroMemory();
	}

	// None of the points may be the point at infinity. They are public, so the inversion may take variable time and nothing is cleared.
	internal static void ToAffine(ReadOnlySpan<JacobianPoint<TField>> points, Span<AffinePoint<TField>> result)
	{
		Debug.Assert(points.Length > 0 && result.Length == points.Length);

		FieldElement<TField>[] products = new FieldElement<TField>[points.Length];
		products[0] = points[0].Z;

		for (int i = 1; i < points.Length; ++i)
		{
			FieldElement<TField>.Multiply(in products[i - 1], in points[i].Z, out products[i]);
		}

		FieldElement<TField>.InvertVariableTime(in products[^1], out FieldElement<TField> inverse);

		for (int i = points.Length - 1; i > 0; --i)
		{
			FieldElement<TField>.Multiply(in inverse, in products[i - 1], out FieldElement<TField> zInverse);
			FieldElement<TField>.Multiply(in inverse, in points[i].Z, out inverse);
			Scale(in points[i], in zInverse, out result[i]);
		}

		Scale(in points[0], in inverse, out result[0]);
	}

	// point must not be the point at infinity.
	internal static void ExportX(in JacobianPoint<TField> point, Span<byte> destination)
	{
		FieldElement<TField>.Invert(in point.Z, out FieldElement<TField> inverse);
		FieldElement<TField>.Square(in inverse, out inverse);
		// The square is Z⁻²R; with R taken off, the product with X comes out in plain form.
		FieldElement<TField>.FromMontgomery(in inverse, out inverse);
		FieldElement<TField>.Multiply(in point.X, in inverse, out FieldElement<TField> x);
		FieldElement<TField>.Export(in x, destination);
		x.ZeroMemory();
		inverse.ZeroMemory();
	}

	// point must not be the point at infinity.
	[SkipLocalsInit]
	internal static void ReduceX(in JacobianPoint<TField> point, out FieldElement<TOrder> result)
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

	// multiples holds 1·P to multiples.Length·P. A digit of 0 gives (0, 0, 0), the point at infinity.
	internal static void Select(ReadOnlySpan<JacobianPoint<TField>> multiples, int digit, out JacobianPoint<TField> result)
	{
		int sign = digit >> 31;
		MaskedSelect.Lookup(in MemoryMarshal.GetReference(multiples), multiples.Length, (uint)((digit ^ sign) - sign) - 1, out result);
		ConditionalNegate((ulong)sign, ref result.Y);
	}

	// Sets result to (X·Z⁻², Y·Z⁻³) from zInverse = Z⁻¹.
	private static void Scale(in JacobianPoint<TField> point, in FieldElement<TField> zInverse, out AffinePoint<TField> result)
	{
		FieldElement<TField>.Square(in zInverse, out FieldElement<TField> power);
		FieldElement<TField>.Multiply(in point.X, in power, out result.X);
		FieldElement<TField>.Multiply(in power, in zInverse, out power);
		FieldElement<TField>.Multiply(in point.Y, in power, out result.Y);
	}

	private static void Combine(in FieldElement<TField> r, in FieldElement<TField> j, in FieldElement<TField> v, in FieldElement<TField> sj, out FieldElement<TField> x, out FieldElement<TField> y)
	{
		FieldElement<TField>.Square(in r, out FieldElement<TField> x3);
		FieldElement<TField>.Subtract(in x3, in j, out x3);
		FieldElement<TField>.Subtract(in x3, in v, out x3);
		FieldElement<TField>.Subtract(in x3, in v, out x3);
		FieldElement<TField>.Subtract(in v, in x3, out FieldElement<TField> y3);
		FieldElement<TField>.Multiply(in r, in y3, out y3);
		FieldElement<TField>.Subtract(in y3, in sj, out y3);
		FieldElement<TField>.Subtract(in y3, in sj, out y);
		x = x3;
	}

	private static void ConditionalNegate(ulong mask, ref FieldElement<TField> value)
	{
		FieldElement<TField>.Negate(in value, out FieldElement<TField> negated);
		FieldElement<TField>.ConditionalSelect(mask, in negated, in value, out value);
	}
}
