using static CryptoBase.EllipticCurves.LimbArithmetic;

namespace CryptoBase.EllipticCurves;

// Scalars are plain values below n. Nothing here branches on or indexes by a point or a scalar, except where a method says that its input is public.
internal static class ECGroup<TCurve, TField, TOrder>
	where TCurve : struct, IECCurve
	where TField : unmanaged, IECField<TField>
	where TOrder : unmanaged, IMontgomeryModulus
{
	private const int WindowWidth = 5;

	internal static int EncodedLength => 1 + 2 * TField.ByteLength;

	// Whether MultiplyAdd takes kernels of TCurve, which callers then prefer to a sum of public points in variable time before one product.
	internal static bool HasMultiplyAdd => TCurve.HasMultiplyAdd;

	// b in Montgomery form.
	private static readonly TField B = FromPlain(TCurve.B);

	// Holds for every point. The result may be the input.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Double(in JacobianPoint<TField> value, out JacobianPoint<TField> result)
	{
		TField.Double(in value, out result);
	}

	// Any left, equal, opposite or at infinity, and an affine right, which cannot be the point at infinity: masks take the right where the left is at infinity and the double where the points are equal. The result may be the left: it is written only after the last read of the inputs.
	[SkipLocalsInit]
	internal static void Add(in JacobianPoint<TField> left, in AffinePoint<TField> right, out JacobianPoint<TField> result)
	{
		ulong equal = AddDistinct(in left, in right, out JacobianPoint<TField> sum);
		Double(in left, out JacobianPoint<TField> twice);
		JacobianPoint<TField>.ConditionalSelect(equal, in twice, in sum, out sum);
		JacobianPoint<TField>.ConditionalSelect(TField.IsZero(in left.Z), in right, in sum, out result);
	}

	// Any points, equal, opposite or at infinity: masks take the double where they are equal and the other point where one is at infinity. The result may be either input: it is written only after the last read of them. The sums on the stack are cleared.
	[SkipLocalsInit]
	internal static void Add(in JacobianPoint<TField> left, in JacobianPoint<TField> right, out JacobianPoint<TField> result)
	{
		ulong equal = AddDistinct(in left, in right, out JacobianPoint<TField> sum);
		Double(in left, out JacobianPoint<TField> twice);
		JacobianPoint<TField>.ConditionalSelect(equal, in twice, in sum, out sum);
		JacobianPoint<TField>.ConditionalSelect(TField.IsZero(in left.Z), in right, in sum, out sum);
		JacobianPoint<TField>.ConditionalSelect(TField.IsZero(in right.Z), in left, in sum, out result);
		sum.ZeroMemory();
		twice.ZeroMemory();
	}

	// The contract of IECField.AddDistinct: for points that are not the point at infinity; equal points give (0, 0, 0) and the mask ulong.MaxValue.
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

	// Sets result to k·G for k below n, by the kernels of TCurve where it has them and MultiplyBaseWindows otherwise. Neither the time nor the addresses depend on k. The Jacobian form of the result depends on k and not only on k·G, so for a secret k use MultiplyBaseToAffine, MultiplyBaseReduceX or MultiplyEncodeExportX, which clear it.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void MultiplyBase(in FieldElement<TOrder> scalar, out JacobianPoint<TField> result)
	{
		if (!TCurve.TryMultiplyBase(in scalar, out result))
		{
			MultiplyBaseWindows(in scalar, out result);
		}
	}

	// As MultiplyBase, by the windows of ECGeneratorTable alone.
	internal static void MultiplyBaseWindows(in FieldElement<TOrder> scalar, out JacobianPoint<TField> result)
	{
		MultiplyFixedWindows(ECGeneratorTable<TCurve, TField, TOrder>.Windows, in scalar, out result);
	}

	// Sets baseResult to k·G and result to k·P for k below n from the table of a point P, by the kernels of TCurve where it has them and MultiplyBase and MultiplyFixedWindows otherwise. Neither the time nor the addresses depend on k. As with MultiplyBase, the Jacobian forms depend on k, so for a secret k use MultiplyEncode, which clears them.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void MultiplyBaseAndFixed(ECPointTable<TCurve, TField, TOrder> table, in FieldElement<TOrder> scalar, out JacobianPoint<TField> baseResult, out JacobianPoint<TField> result)
	{
		ReadOnlySpan<ulong> windows = table.Windows;

		if (!TCurve.TryMultiplyBaseAndFixed(windows, in scalar, out baseResult, out result))
		{
			MultiplyBase(in scalar, out baseResult);
			MultiplyFixedWindows(windows, in scalar, out result);
		}
	}

	// Sets result to k·P for k below n from the table of a point P, by the kernels of TCurve where it has them and MultiplyFixedWindows otherwise. Neither the time nor the addresses depend on k. As with MultiplyBase, the Jacobian form depends on k, so for a secret k use TryMultiplyAddEncode, which clears it.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void MultiplyFixed(ECPointTable<TCurve, TField, TOrder> table, in FieldElement<TOrder> scalar, out JacobianPoint<TField> result)
	{
		ReadOnlySpan<ulong> windows = table.Windows;

		if (!TCurve.TryMultiplyFixed(windows, in scalar, out result))
		{
			MultiplyFixedWindows(windows, in scalar, out result);
		}
	}

	// As MultiplyBase, k·P from the windows of P as ECGeneratorTable lays them out. The argument below deals with the scalars mod n alone, so it holds for any point of the group, which has prime order n.
	[SkipLocalsInit]
	internal static void MultiplyFixedWindows(ReadOnlySpan<ulong> windows, in FieldElement<TOrder> scalar, out JacobianPoint<TField> result)
	{
		Debug.Assert(windows.Length == ECGeneratorTable<TCurve, TField, TOrder>.Length);

		Span<sbyte> digits = stackalloc sbyte[ECGeneratorTable<TCurve, TField, TOrder>.WindowCount];

		RecodeWindows(in scalar, TCurve.GeneratorWindowWidth, digits);
		SelectWindow(windows, 0, digits[0], out AffinePoint<TField> entry);
		// A digit of 0 selects (0, 0), which is not a point: the first window then leaves the point at infinity, Z = 0, and the later ones discard the sum.
		result = default;
		JacobianPoint<TField>.ConditionalSelect(~ZeroMask((ulong)digits[0]), in entry, in result, out result);
		Unsafe.SkipInit(out JacobianPoint<TField> sum);

		// Window i adds d·2^(wi)·P, d ≠ 0, to L·P with L = Σ_{j<i} d_j·2^(wj). Opposite points give Z = 0, which is right. Equal ones need L − d·2^(wi) to be a multiple of n. Where w divides N = TOrder.BitLength, as for SM2VerificationCurve alone, L − d·2^(wi) has digits in [−2^(w − 1), 2^(w − 1)], the lowest other than 0 no multiple of 2^w, so it is not 0, and it is at most 2^(w − 1)·(2^N − 1)/(2^w − 1) < n for SM2 in absolute value. Otherwise 1 ≤ |d| ≤ 2^(w − 1) and −2^(wi)/2 < L < 2^(wi), so L − d·2^(wi) is not 0; let t = ⌊N/w⌋. Below window t, |L − d·2^(wi)| < 2^(w(i + 1)) ≤ 2^(wt) < n. In window t, 0 < d ≤ 2^(N − wt) puts L − d·2^(wt) in (−2n, 0), so it would be −n: then k = 2d·2^(wt) − n < n and L = d·2^(wt) − n > −2^(wt)/2 put d·2^(wt) in (n − 2^(wt)/2, n), which holds no multiple of 2^(wt), as 2^N − n < 2^(wt)/2 for each curve here.
		for (int i = 1; i < digits.Length; ++i)
		{
			SelectWindow(windows, i, digits[i], out entry);
			_ = AddDistinct(in result, in entry, out sum);
			JacobianPoint<TField>.ConditionalSelect(TField.IsZero(in result.Z), in entry, in sum, out sum);
			JacobianPoint<TField>.ConditionalSelect(ZeroMask((ulong)digits[i]), in result, in sum, out result);
		}

		digits.ZeroMemory();
		entry.ZeroMemory();
		sum.ZeroMemory();
	}

	// Sets result to k·P for a point P on the curve and k below n, by the kernels of TCurve where it has them and MultiplyWindows otherwise. Neither the time nor the addresses depend on k or P. As with MultiplyBase, the Jacobian form depends on k, so for a secret k use TryMultiplyExportX or MultiplyEncodeExportX.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Multiply(in AffinePoint<TField> point, in FieldElement<TOrder> scalar, out JacobianPoint<TField> result)
	{
		if (!TCurve.TryMultiply(in point, in scalar, out result))
		{
			MultiplyWindows(in point, in scalar, out result);
		}
	}

	// As Multiply, by the windows of BuildMultiples alone.
	[SkipLocalsInit]
	internal static void MultiplyWindows(in AffinePoint<TField> point, in FieldElement<TOrder> scalar, out JacobianPoint<TField> result)
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

			// The doublings leave 32a·P for the value a ≥ 0 of the digits above i, and the entry is d·P, |d| ≤ 16, or (0, 0) for d = 0. The digits from i down make more than −32^(i + 1)/2, so 32a < n/32^i + 16. Opposite points give Z = 0, which is right; equal ones need 32a ≡ d (mod n). For i ≥ 1, |32a − d| < n leaves 32a = d, so a = 0 and d = 0: the point at infinity and a digit of 0, which the masks cover. In window 0, k = 32a + d, so equal points need k ≡ 2d (mod n) with d the low digit of k. For d > 0 that is k = 2d, whose low digit is not d; for d < 0 it is k = n + 2d, whose low digit is d just if d ≡ −n (mod 32). No d in [−15, −1] does that for P-256, n ≡ 17, or P-384, n ≡ 19, but d = −9 does for P-521, n ≡ 9, at k = n − 18, and d = −3 for SM2, n ≡ 3, at k = n − 6, so that window doubles where the points are equal.
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

	// Sets result to k·P + l·Q for points P and Q on the curve and k and l below n, by the kernels of TCurve where it has them and Multiply of each and Add otherwise. Neither the time nor the addresses depend on k, l, P or Q. As with MultiplyBase, the Jacobian form depends on k and l, so for secret ones use TryMultiplyAddEncode, which clears it.
	[SkipLocalsInit]
	internal static void MultiplyAdd(in AffinePoint<TField> point, in FieldElement<TOrder> scalar, in AffinePoint<TField> otherPoint, in FieldElement<TOrder> otherScalar, out JacobianPoint<TField> result)
	{
		if (TCurve.TryMultiplyAdd(in point, in scalar, in otherPoint, in otherScalar, out result))
		{
			return;
		}

		Multiply(in point, in scalar, out JacobianPoint<TField> first);
		Multiply(in otherPoint, in otherScalar, out JacobianPoint<TField> second);
		Add(in first, in second, out result);
		first.ZeroMemory();
		second.ZeroMemory();
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
	[MethodImpl(MethodImplOptions.NoInlining)]
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

	// For a point P on the curve and k in [1, n − 1], writes the encodings of k·G and k·P, neither of which is the point at infinity, as the group has prime order n. One inversion serves both. Neither the time nor the addresses depend on k or P, and the intermediates are cleared.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static void MultiplyEncode(in AffinePoint<TField> point, in FieldElement<TOrder> scalar, Span<byte> encodedBase, Span<byte> encodedProduct)
	{
		Span<JacobianPoint<TField>> products = stackalloc JacobianPoint<TField>[2];
		MultiplyBase(in scalar, out products[0]);
		Multiply(in point, in scalar, out products[1]);
		EncodeProducts(products, encodedBase, encodedProduct);
	}

	// As above, from the table of P.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static void MultiplyEncode(ECPointTable<TCurve, TField, TOrder> table, in FieldElement<TOrder> scalar, Span<byte> encodedBase, Span<byte> encodedProduct)
	{
		Span<JacobianPoint<TField>> products = stackalloc JacobianPoint<TField>[2];
		MultiplyBaseAndFixed(table, in scalar, out products[0], out products[1]);
		EncodeProducts(products, encodedBase, encodedProduct);
	}

	// For a point P on the curve and k below n, writes the encoding of k·P. Returns false, leaving destination unchanged, if k·P is the point at infinity; the return value reveals that anyway, so it may decide a branch.
	[SkipLocalsInit]
	internal static bool TryMultiplyEncode(in AffinePoint<TField> point, in FieldElement<TOrder> scalar, Span<byte> destination)
	{
		Multiply(in point, in scalar, out JacobianPoint<TField> product);
		return TryEncode(ref product, destination);
	}

	// For the table of a point P, a point Q on the curve and k and l below n, writes the encoding of k·P + l·Q. Returns false, leaving destination unchanged, if that is the point at infinity; the return value reveals that anyway, so it may decide a branch. Neither the time nor the addresses depend on k, l, P or Q, and the intermediates are cleared.
	[SkipLocalsInit]
	internal static bool TryMultiplyAddEncode(ECPointTable<TCurve, TField, TOrder> table, in FieldElement<TOrder> scalar, in AffinePoint<TField> point, in FieldElement<TOrder> otherScalar, Span<byte> destination)
	{
		MultiplyFixed(table, in scalar, out JacobianPoint<TField> first);
		Multiply(in point, in otherScalar, out JacobianPoint<TField> second);
		Add(in first, in second, out JacobianPoint<TField> sum);
		first.ZeroMemory();
		second.ZeroMemory();
		return TryEncode(ref sum, destination);
	}

	// As above, for points P and Q on the curve.
	[SkipLocalsInit]
	internal static bool TryMultiplyAddEncode(in AffinePoint<TField> point, in FieldElement<TOrder> scalar, in AffinePoint<TField> otherPoint, in FieldElement<TOrder> otherScalar, Span<byte> destination)
	{
		MultiplyAdd(in point, in scalar, in otherPoint, in otherScalar, out JacobianPoint<TField> sum);
		return TryEncode(ref sum, destination);
	}

	// Writes the encoding of point and returns true, or returns false, leaving destination unchanged, for the point at infinity; clears point and the intermediates either way.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	[SkipLocalsInit]
	private static bool TryEncode(ref JacobianPoint<TField> point, Span<byte> destination)
	{
		bool valid = TField.IsZero(in point.Z) is 0;

		if (valid)
		{
			ToAffine(in point, out AffinePoint<TField> affine);
			Encode(in affine, destination);
			affine.ZeroMemory();
		}

		point.ZeroMemory();
		return valid;
	}

	// The encodings of the two products, neither the point at infinity, with one inversion; clears them and the intermediates.
	[SkipLocalsInit]
	private static void EncodeProducts(Span<JacobianPoint<TField>> products, Span<byte> encodedBase, Span<byte> encodedProduct)
	{
		Span<AffinePoint<TField>> affine = stackalloc AffinePoint<TField>[2];
		ToAffine(products, affine);
		Encode(in affine[0], encodedBase);
		Encode(in affine[1], encodedProduct);
		products.ZeroMemory();
		affine.ZeroMemory();
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
			Scale(in points[i], in zInverse, variableTime, out result[i]);
		}

		Scale(in points[0], in inverse, variableTime, out result[0]);

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

	// Clears the plain coordinate in its local, so that it serves secret points too.
	internal static void Encode(in AffinePoint<TField> point, Span<byte> destination)
	{
		Debug.Assert(destination.Length == EncodedLength);

		int length = TField.ByteLength;
		destination[0] = 0x04;
		TField.FromMontgomery(in point.X, out TField coordinate);
		TField.Export(in coordinate, destination.Slice(1, length));
		TField.FromMontgomery(in point.Y, out coordinate);
		TField.Export(in coordinate, destination.Slice(1 + length, length));
		coordinate.ZeroMemory();
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
		RightSide(in point.X, out TField right);
		TField.Square(in point.Y, out TField left);
		return TField.AreEqual(in left, in right) is not 0;
	}

	// x³ − 3x + b, which y² equals for a point (x, y) of the curve. The result must not be x.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void RightSide(in TField x, out TField result)
	{
		TField.Square(in x, out result);
		TField.Multiply(in result, in x, out result);
		TField.Subtract(in result, in x, out result);
		TField.Subtract(in result, in x, out result);
		TField.Subtract(in result, in x, out result);
		TField.Add(in result, in B, out result);
	}

	// ⌈N/w⌉ digits for N = TOrder.BitLength: where w does not divide N, the top one holds the top N mod w bits and the carry into them, as Recode writes them, and where it does, RecodeSpanning keeps every carry within them.
	internal static int DigitCount(int width)
	{
		return (TOrder.BitLength + width - 1) / width;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void RecodeWindows(in FieldElement<TOrder> scalar, int width, Span<sbyte> digits)
	{
		if (TOrder.BitLength % width is 0)
		{
			RecodeSpanning(in scalar, width, digits);
		}
		else
		{
			Recode(in scalar, width, digits);
		}
	}

	// The digits of LimbArithmetic.RecodeSignedWindows, for w that does not divide N, so that the top window holds at most w − 1 bits of k. The loop is repeated here, where the JIT knows the limb count of TOrder: a call to the shared one passes a span, which its loop rereads for every digit.
	internal static void Recode(in FieldElement<TOrder> scalar, int width, Span<sbyte> digits)
	{
		// Digits up to 2^(w − 1) must fit in an sbyte.
		Debug.Assert(width is > 0 and < 8 && TOrder.BitLength % width is not 0);
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

	// As Recode for w that divides 64 and N = 64·TOrder.LimbCount, the N/w digits d_i = x_i − 2^(w − 1) for the windows x_i of k + H, H holding 2^(w − 1) in every window: they lie in [−2^(w − 1), 2^(w − 1) − 1] and sum to k − c·2^N for the carry c out of k + H, which is 1 just if k + H ≥ 2^N, so just if k exceeds the largest such sum, (2^(w − 1) − 1)·(2^N − 1)/(2^w − 1). Then the windows of k + H − n, below 2^N, give the digits of k − n, so that k ≡ Σ d_i·2^(wi) (mod n) either way. n is subtracted under a mask of the carry, and only i decides which limbs are read, so neither the time nor the addresses depend on k.
	[SkipLocalsInit]
	internal static void RecodeSpanning(in FieldElement<TOrder> scalar, int width, Span<sbyte> digits)
	{
		// Digits from −2^(w − 1) must fit in an sbyte.
		Debug.Assert(width is > 0 and <= 8 && 64 % width is 0 && TOrder.BitLength == 64 * TOrder.LimbCount);
		Debug.Assert(digits.Length == DigitCount(width));

		int count = TOrder.LimbCount;
		ReadOnlySpan<ulong> n = TOrder.Modulus;
		Span<ulong> values = stackalloc ulong[2 * count];
		Span<ulong> addend = values.Slice(0, count);
		Span<ulong> sum = values.Slice(count);
		addend.Fill(ulong.MaxValue / ((1UL << width) - 1) << width - 1);
		ulong mask = 0 - AddLimbs(ref MemoryMarshal.GetReference(FieldElement<TOrder>.GetLimbs(in scalar)), ref MemoryMarshal.GetReference(addend), ulong.MaxValue, ref MemoryMarshal.GetReference(sum), count);

		for (int i = 0; i < count; ++i)
		{
			addend[i] = n[i] & mask;
		}

		_ = SubtractLimbs(ref MemoryMarshal.GetReference(sum), ref MemoryMarshal.GetReference(addend), ref MemoryMarshal.GetReference(sum), count);
		uint windowMask = (1u << width) - 1;
		uint half = 1u << width - 1;

		for (int i = 0; i < digits.Length; ++i)
		{
			int position = i * width;
			digits[i] = (sbyte)(((uint)(sum[position >> 6] >> (position & 63)) & windowMask) - half);
		}

		values.ZeroMemory();
	}

	// multiples holds 1·P to multiples.Length·P. A digit of 0 gives (0, 0), which is not a point.
	internal static void Select(ReadOnlySpan<AffinePoint<TField>> multiples, int digit, out AffinePoint<TField> result)
	{
		int sign = digit >> 31;
		MaskedSelect.Lookup(in MemoryMarshal.GetReference(multiples), multiples.Length, (uint)((digit ^ sign) - sign) - 1, out result);
		ConditionalNegate((ulong)sign, ref result.Y);
	}

	// digit·B from window window of windows, which holds 1·B to WindowLength·B as ECGeneratorTable lays them out. A digit of 0 gives (0, 0), which is not a point.
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	internal static void SelectWindow(ReadOnlySpan<ulong> windows, int window, int digit, out AffinePoint<TField> result)
	{
		int sign = digit >> 31;
		int windowLength = ECGeneratorTable<TCurve, TField, TOrder>.WindowLength;
		int entryLength = ECGeneratorTable<TCurve, TField, TOrder>.EntryLength;
		Unsafe.SkipInit(out result);
		MaskedSelect.Lookup(in Unsafe.Add(ref MemoryMarshal.GetReference(windows), window * windowLength * entryLength), entryLength, windowLength, (uint)((digit ^ sign) - sign) - 1, ref Unsafe.As<AffinePoint<TField>, ulong>(ref result));
		TField.Unpack(ref result);
		ConditionalNegate((ulong)sign, ref result.Y);
	}

	// Sets result to (X·Z⁻², Y·Z⁻³) from zInverse = Z⁻¹, clearing the powers of Z⁻¹ unless variableTime is set.
	private static void Scale(in JacobianPoint<TField> point, in TField zInverse, bool variableTime, out AffinePoint<TField> result)
	{
		TField.Square(in zInverse, out TField power);
		TField.Multiply(in point.X, in power, out result.X);
		TField.Multiply(in power, in zInverse, out power);
		TField.Multiply(in point.Y, in power, out result.Y);

		if (!variableTime)
		{
			power.ZeroMemory();
		}
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
