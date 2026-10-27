using static CryptoBase.EllipticCurves.LimbArithmetic;

namespace CryptoBase.EllipticCurves;

// Scalars are plain values below n. Nothing here branches on or indexes by a point or a scalar, except where a method says that its input is public.
internal static class EcGroup<TCurve, TField, TOrder>
	where TCurve : struct, IEcCurve
	where TField : unmanaged, IEcField<TField>
	where TOrder : unmanaged, IMontgomeryModulus
{
	private const int WindowWidth = 5;

	internal static int EncodedLength => 1 + 2 * TField.ByteLength;

	// b in Montgomery form.
	private static readonly TField B = FromPlain(TCurve.B);

	// Holds for every point. The result may be the input.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Double(in JacobianPoint<TField> value, out JacobianPoint<TField> result)
	{
		TField.Double(in value, out result);
	}

	// Any two points, equal, opposite or at infinity: masks take the other input where one is at infinity and the double where the points are equal. The result may be either input: it is written only after the last read of the inputs.
	[SkipLocalsInit]
	internal static void Add(in JacobianPoint<TField> left, in JacobianPoint<TField> right, out JacobianPoint<TField> result)
	{
		ulong equal = AddDistinct(in left, in right, out JacobianPoint<TField> sum);
		Double(in left, out JacobianPoint<TField> twice);
		JacobianPoint<TField>.ConditionalSelect(equal, in twice, in sum, out sum);
		JacobianPoint<TField>.ConditionalSelect(TField.IsZero(in left.Z), in right, in sum, out sum);
		JacobianPoint<TField>.ConditionalSelect(TField.IsZero(in right.Z), in left, in sum, out result);
	}

	// As above, with an affine right, which cannot be the point at infinity; the left may be.
	[SkipLocalsInit]
	internal static void Add(in JacobianPoint<TField> left, in AffinePoint<TField> right, out JacobianPoint<TField> result)
	{
		ulong equal = AddDistinct(in left, in right, out JacobianPoint<TField> sum);
		Double(in left, out JacobianPoint<TField> twice);
		JacobianPoint<TField>.ConditionalSelect(equal, in twice, in sum, out sum);
		JacobianPoint<TField>.ConditionalSelect(TField.IsZero(in left.Z), in right, in sum, out result);
	}

	// The contract of IEcField.AddDistinct: for points that are not the point at infinity; equal points give (0, 0, 0) and the mask ulong.MaxValue.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static ulong AddDistinct(in JacobianPoint<TField> left, in JacobianPoint<TField> right, out JacobianPoint<TField> result)
	{
		return TField.AddDistinct(in left, in right, out result);
	}

	// As above, with an affine right.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static ulong AddDistinct(in JacobianPoint<TField> left, in AffinePoint<TField> right, out JacobianPoint<TField> result)
	{
		return TField.AddDistinct(in left, in right, out result);
	}

	// G, from the plain coordinates of TCurve.
	internal static void Generator(out AffinePoint<TField> result)
	{
		result.X = FromPlain(TCurve.GeneratorX);
		result.Y = FromPlain(TCurve.GeneratorY);
	}

	// Sets result to k·G for k below n. Neither the time nor the addresses depend on k. The Jacobian form of the result depends on k and not only on k·G, so for a secret k use MultiplyBaseToAffine, MultiplyBaseReduceX or MultiplyEncodeExportX, which clear it.
	[SkipLocalsInit]
	internal static void MultiplyBase(in FieldElement<TOrder> scalar, out JacobianPoint<TField> result)
	{
		Span<sbyte> digits = stackalloc sbyte[EcGeneratorTable<TCurve, TField, TOrder>.WindowCount];
		Recode(in scalar, TCurve.GeneratorWindowWidth, digits);
		SelectBase(0, digits[0], out AffinePoint<TField> entry);
		// A digit of 0 selects (0, 0), which is not a point: the first window then leaves the point at infinity, Z = 0, and the later ones discard the sum.
		result = default;
		JacobianPoint<TField>.ConditionalSelect(~ZeroMask((ulong)digits[0]), in entry, in result, out result);
		Unsafe.SkipInit(out JacobianPoint<TField> sum);

		// Window i adds d·2^(wi)·G, 1 ≤ |d| ≤ 2^(w − 1), to L·G with L = Σ_{j<i} d_j·2^(wj), so −2^(wi)/2 < L < 2^(wi). Opposite points give Z = 0, which is right. Equal ones need L − d·2^(wi), which is not 0, to be a multiple of n. Let t = ⌊N/w⌋ for N = TOrder.BitLength, which w does not divide. Below window t, |L − d·2^(wi)| < 2^(w(i + 1)) ≤ 2^(wt) < n. In window t, 0 < d ≤ 2^(N − wt) puts L − d·2^(wt) in (−2n, 0), so it would be −n: then k = 2d·2^(wt) − n < n and L = d·2^(wt) − n > −2^(wt)/2 put d·2^(wt) in (n − 2^(wt)/2, n), which holds no multiple of 2^(wt), as 2^N − n < 2^(wt)/2 for each curve here.
		for (int i = 1; i < digits.Length; ++i)
		{
			SelectBase(i, digits[i], out entry);
			_ = AddDistinct(in result, in entry, out sum);
			JacobianPoint<TField>.ConditionalSelect(TField.IsZero(in result.Z), in entry, in sum, out sum);
			JacobianPoint<TField>.ConditionalSelect(ZeroMask((ulong)digits[i]), in result, in sum, out result);
		}

		digits.ZeroMemory();
		entry.ZeroMemory();
		sum.ZeroMemory();
	}

	// Sets result to k·P for a point P on the curve and k below n. Neither the time nor the addresses depend on k or P. As with MultiplyBase, the Jacobian form depends on k, so for a secret k use TryMultiplyExportX or MultiplyEncodeExportX.
	[SkipLocalsInit]
	internal static void Multiply(in AffinePoint<TField> point, in FieldElement<TOrder> scalar, out JacobianPoint<TField> result)
	{
		Span<sbyte> digits = stackalloc sbyte[DigitCount(WindowWidth)];
		Span<AffinePoint<TField>> table = stackalloc AffinePoint<TField>[1 << WindowWidth - 1];
		Recode(in scalar, WindowWidth, digits);
		BuildMultiples(in point, table);
		Select(table, digits[^1], out AffinePoint<TField> entry);
		// A digit of 0 selects (0, 0), which is not a point: the top window then leaves the point at infinity, Z = 0, and the later ones discard the sum.
		result = default;
		JacobianPoint<TField>.ConditionalSelect(~ZeroMask((ulong)digits[^1]), in entry, in result, out result);
		Unsafe.SkipInit(out JacobianPoint<TField> sum);

		for (int i = digits.Length - 2; i >= 0; --i)
		{
			for (int k = 0; k < WindowWidth; ++k)
			{
				Double(in result, out result);
			}

			Select(table, digits[i], out entry);

			// The doublings leave 32a·P for the value a ≥ 0 of the digits above i, and the entry is d·P, |d| ≤ 16, or (0, 0) for d = 0. The digits from i down make more than −32^(i + 1)/2, so 32a < n/32^i + 16. Opposite points give Z = 0, which is right; equal ones need 32a ≡ d (mod n). For i ≥ 1, |32a − d| < n leaves 32a = d, so a = 0 and d = 0: the point at infinity and a digit of 0, which the masks cover. In window 0, k = 32a + d, so equal points need k ≡ 2d (mod n) with d the low digit of k. For d > 0 that is k = 2d, whose low digit is not d; for d < 0 it is k = n + 2d, whose low digit is d just if d ≡ −n (mod 32). No d in [−15, −1] does that for P-256, n ≡ 17, or P-384, n ≡ 19, but d = −9 does for P-521, n ≡ 9, at k = n − 18, so that window doubles where the points are equal.
			if (i is not 0)
			{
				_ = AddDistinct(in result, in entry, out sum);
				JacobianPoint<TField>.ConditionalSelect(TField.IsZero(in result.Z), in entry, in sum, out sum);
			}
			else
			{
				Add(in result, in entry, out sum);
			}

			JacobianPoint<TField>.ConditionalSelect(ZeroMask((ulong)digits[i]), in result, in sum, out result);
		}

		digits.ZeroMemory();
		table.ZeroMemory();
		entry.ZeroMemory();
		sum.ZeroMemory();
	}

	// Sets multiples[j − 1] to j·P for a point P on the curve. No j·P is the point at infinity, as j ≤ multiples.Length < n, so each has an affine form. Every caller of Multiply passes a public P, but the inversion takes constant time all the same and the intermediates are cleared, so that neither the time nor the addresses depend on P.
	[SkipLocalsInit]
	internal static void BuildMultiples(in AffinePoint<TField> point, Span<AffinePoint<TField>> multiples)
	{
		Debug.Assert(multiples.Length >= 2);

		// sums[j − 2] is j·P. For odd j it is (j − 1)·P + P, two points that are neither equal, opposite nor at infinity, as 2 < j < n.
		Span<JacobianPoint<TField>> sums = stackalloc JacobianPoint<TField>[multiples.Length - 1];
		JacobianPoint<TField>.FromAffine(in point, out JacobianPoint<TField> first);
		Double(in first, out sums[0]);

		for (int j = 3; j <= multiples.Length; ++j)
		{
			if (j % 2 is 0)
			{
				Double(in sums[j / 2 - 2], out sums[j - 2]);
			}
			else
			{
				_ = AddDistinct(in sums[j - 3], in point, out sums[j - 2]);
			}
		}

		multiples[0] = point;
		ToAffine(sums, multiples.Slice(1));
		sums.ZeroMemory();
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
		bool valid = TField.IsZero(in product.Z) is 0;

		if (valid)
		{
			ExportX(in product, destination);
		}

		product.ZeroMemory();
		return valid;
	}

	// For a point P on the curve and k in [1, n − 1], writes the encoding of k·G to encoded and the x-coordinate of k·P to x. Neither product is the point at infinity, as the group has prime order n, so one inversion of the product of their Z gives both Z⁻¹. Neither the time nor the addresses depend on k or P, and the intermediates are cleared.
	[SkipLocalsInit]
	internal static void MultiplyEncodeExportX(in AffinePoint<TField> point, in FieldElement<TOrder> scalar, Span<byte> encoded, Span<byte> x)
	{
		Debug.Assert(encoded.Length == EncodedLength && x.Length == TField.ByteLength);

		int length = TField.ByteLength;
		MultiplyBase(in scalar, out JacobianPoint<TField> baseProduct);
		Multiply(in point, in scalar, out JacobianPoint<TField> product);
		TField.Multiply(in baseProduct.Z, in product.Z, out TField inverse);
		TField.Invert(in inverse, out inverse);
		TField.Multiply(in inverse, in product.Z, out TField baseInverse);
		TField.Multiply(in inverse, in baseProduct.Z, out inverse);
		// As in ExportX, the powers of Z⁻¹ are taken out of Montgomery form, so that the products with X and Y come out in plain form.
		TField.Square(in baseInverse, out TField power);
		TField.FromMontgomery(in power, out power);
		TField.Multiply(in baseProduct.X, in power, out TField coordinate);
		encoded[0] = 0x04;
		TField.Export(in coordinate, encoded.Slice(1, length));
		TField.Multiply(in power, in baseInverse, out power);
		TField.Multiply(in baseProduct.Y, in power, out coordinate);
		TField.Export(in coordinate, encoded.Slice(1 + length, length));
		TField.Square(in inverse, out power);
		TField.FromMontgomery(in power, out power);
		TField.Multiply(in product.X, in power, out coordinate);
		TField.Export(in coordinate, x);
		baseProduct.ZeroMemory();
		product.ZeroMemory();
		inverse.ZeroMemory();
		baseInverse.ZeroMemory();
		power.ZeroMemory();
		coordinate.ZeroMemory();
	}

	// The point at infinity gives (0, 0), which is not on the curve.
	internal static void ToAffine(in JacobianPoint<TField> point, out AffinePoint<TField> result)
	{
		TField.Invert(in point.Z, out TField inverse);
		TField.Square(in inverse, out TField square);
		TField.Multiply(in point.X, in square, out result.X);
		TField.Multiply(in square, in inverse, out inverse);
		TField.Multiply(in point.Y, in inverse, out result.Y);
		// With the affine form, Z⁻² or Z⁻³ would give back the Jacobian one.
		square.ZeroMemory();
		inverse.ZeroMemory();
	}

	// None of the points may be the point at infinity. Neither the time nor the addresses depend on the points, and the intermediates are cleared.
	internal static void ToAffine(ReadOnlySpan<JacobianPoint<TField>> points, Span<AffinePoint<TField>> result)
	{
		ToAffine(points, result, false);
	}

	// As above for public points: the inversion may take variable time, and nothing is cleared.
	internal static void ToAffineVariableTime(ReadOnlySpan<JacobianPoint<TField>> points, Span<AffinePoint<TField>> result)
	{
		ToAffine(points, result, true);
	}

	// One inversion for all the points: result[i].X holds the product of the Z of points 0 to i until result[i] is written.
	private static void ToAffine(ReadOnlySpan<JacobianPoint<TField>> points, Span<AffinePoint<TField>> result, bool variableTime)
	{
		Debug.Assert(points.Length > 0 && result.Length == points.Length);

		result[0].X = points[0].Z;

		for (int i = 1; i < points.Length; ++i)
		{
			TField.Multiply(in result[i - 1].X, in points[i].Z, out result[i].X);
		}

		TField inverse;

		if (variableTime)
		{
			TField.InvertVariableTime(in result[^1].X, out inverse);
		}
		else
		{
			TField.Invert(in result[^1].X, out inverse);
		}

		Unsafe.SkipInit(out TField zInverse);

		for (int i = points.Length - 1; i > 0; --i)
		{
			TField.Multiply(in inverse, in result[i - 1].X, out zInverse);
			TField.Multiply(in inverse, in points[i].Z, out inverse);
			Scale(in points[i], in zInverse, out result[i]);
		}

		Scale(in points[0], in inverse, out result[0]);

		if (!variableTime)
		{
			inverse.ZeroMemory();
			zInverse.ZeroMemory();
		}
	}

	// point must not be the point at infinity.
	internal static void ExportX(in JacobianPoint<TField> point, Span<byte> destination)
	{
		TField.Invert(in point.Z, out TField inverse);
		TField.Square(in inverse, out inverse);
		// The square is Z⁻²R; with R taken off, the product with X comes out in plain form.
		TField.FromMontgomery(in inverse, out inverse);
		TField.Multiply(in point.X, in inverse, out TField x);
		TField.Export(in x, destination);
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
		TField.FromMontgomery(in point.X, out TField coordinate);
		TField.Export(in coordinate, destination.Slice(1, length));
		TField.FromMontgomery(in point.Y, out coordinate);
		TField.Export(in coordinate, destination.Slice(1 + length, length));
	}

	// The cofactor is 1, so every point on the curve is in the group of G. The input is public, so the checks may branch.
	internal static bool TryDecode(ReadOnlySpan<byte> source, out AffinePoint<TField> result)
	{
		int length = TField.ByteLength;

		if (source.Length != 1 + 2 * length
			|| source[0] is not 0x04
			|| !TField.TryImport(source.Slice(1, length), out TField x)
			|| !TField.TryImport(source.Slice(1 + length, length), out TField y))
		{
			result = default;
			return false;
		}

		TField.ToMontgomery(in x, out result.X);
		TField.ToMontgomery(in y, out result.Y);

		if (!IsOnCurve(in result))
		{
			result = default;
			return false;
		}

		return true;
	}

	private static bool IsOnCurve(in AffinePoint<TField> point)
	{
		TField.Square(in point.X, out TField right);
		TField.Multiply(in right, in point.X, out right);
		TField.Subtract(in right, in point.X, out right);
		TField.Subtract(in right, in point.X, out right);
		TField.Subtract(in right, in point.X, out right);
		TField.Add(in right, in B, out right);
		TField.Square(in point.Y, out TField left);
		return TField.AreEqual(in left, in right) is not 0;
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

	// multiples holds 1·P to multiples.Length·P. A digit of 0 gives (0, 0), which is not a point.
	internal static void Select(ReadOnlySpan<AffinePoint<TField>> multiples, int digit, out AffinePoint<TField> result)
	{
		int sign = digit >> 31;
		MaskedSelect.Lookup(in MemoryMarshal.GetReference(multiples), multiples.Length, (uint)((digit ^ sign) - sign) - 1, out result);
		ConditionalNegate((ulong)sign, ref result.Y);
	}

	// digit·B from window of EcGeneratorTable, which holds 1·B to WindowLength·B. A digit of 0 gives (0, 0), which is not a point.
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	internal static void SelectBase(int window, int digit, out AffinePoint<TField> result)
	{
		int sign = digit >> 31;
		Unsafe.SkipInit(out result);
		MaskedSelect.Lookup(in EcGeneratorTable<TCurve, TField, TOrder>.Window(window), EcGeneratorTable<TCurve, TField, TOrder>.EntryLength, EcGeneratorTable<TCurve, TField, TOrder>.WindowLength, (uint)((digit ^ sign) - sign) - 1, ref Unsafe.As<AffinePoint<TField>, ulong>(ref result));
		TField.Unpack(ref result);
		ConditionalNegate((ulong)sign, ref result.Y);
	}

	// Sets result to (X·Z⁻², Y·Z⁻³) from zInverse = Z⁻¹.
	private static void Scale(in JacobianPoint<TField> point, in TField zInverse, out AffinePoint<TField> result)
	{
		TField.Square(in zInverse, out TField power);
		TField.Multiply(in point.X, in power, out result.X);
		TField.Multiply(in power, in zInverse, out power);
		TField.Multiply(in point.Y, in power, out result.Y);
	}

	// The element of a plain value below p, in Montgomery form.
	private static TField FromPlain(ReadOnlySpan<ulong> limbs)
	{
		TField.FromLimbs(limbs, out TField value);
		TField.ToMontgomery(in value, out value);
		return value;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ConditionalNegate(ulong mask, ref TField value)
	{
		TField.Negate(in value, out TField negated);
		TField.ConditionalSelect(mask, in negated, in value, out value);
	}
}
