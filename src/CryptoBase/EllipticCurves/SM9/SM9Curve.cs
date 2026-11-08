namespace CryptoBase.EllipticCurves.SM9;

// The group law of y² = x³ + b over TField by the complete formulas of Renes, Costello and Batina ("Complete addition formulas for prime order elliptic curves", 2016, Algorithms 7 to 9 for a = 0). They hold for every pair of points, the point at infinity included, on a curve with no point of order 2, as E(Fp), of prime order N, and E'(Fp2), of odd order N·(2p − N), both are; the mixed addition takes any left and an affine right, which cannot be the point at infinity. Every output of TField's arithmetic is reduced, so each product here takes reduced inputs. The point at infinity has X = 0 and Y ≠ 0 in every form these formulas give.
// Nothing here branches on or indexes by a point, except where a method says that its input is public. The results may be the same variables as the inputs.
internal static class SM9Curve<TField> where TField : unmanaged, ISM9Field<TField>
{
	[SkipLocalsInit]
	internal static void Infinity(out SM9Point<TField> result)
	{
		result = default;
		result.Y = TField.One;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void FromAffine(in SM9AffinePoint<TField> point, out SM9Point<TField> result)
	{
		result.X = point.X;
		result.Y = point.Y;
		result.Z = TField.One;
	}

	// Algorithm 7, 12 products and 2 by 3b, with 2t0 + t0 taken as 3·t0.
	[SkipLocalsInit]
	internal static void Add(in SM9Point<TField> left, in SM9Point<TField> right, out SM9Point<TField> result)
	{
		TField.Multiply(in left.X, in right.X, out TField t0);
		TField.Multiply(in left.Y, in right.Y, out TField t1);
		TField.Multiply(in left.Z, in right.Z, out TField t2);
		TField.Add(in left.X, in left.Y, out TField t3);
		TField.Add(in right.X, in right.Y, out TField t4);
		TField.Multiply(in t3, in t4, out t3);
		TField.Add(in t0, in t1, out t4);
		TField.Subtract(in t3, in t4, out t3);
		TField.Add(in left.Y, in left.Z, out t4);
		TField.Add(in right.Y, in right.Z, out TField x3);
		TField.Multiply(in t4, in x3, out t4);
		TField.Add(in t1, in t2, out x3);
		TField.Subtract(in t4, in x3, out t4);
		TField.Add(in left.X, in left.Z, out x3);
		TField.Add(in right.X, in right.Z, out TField y3);
		TField.Multiply(in x3, in y3, out x3);
		TField.Add(in t0, in t2, out y3);
		TField.Subtract(in x3, in y3, out y3);
		TField.MultiplySmall(in t0, 3, out t0);
		TField.MultiplyByThreeB(in t2, out t2);
		TField.Add(in t1, in t2, out TField z3);
		TField.Subtract(in t1, in t2, out t1);
		TField.MultiplyByThreeB(in y3, out y3);
		TField.Multiply(in t4, in y3, out x3);
		TField.Multiply(in t3, in t1, out t2);
		TField.Subtract(in t2, in x3, out x3);
		TField.Multiply(in y3, in t0, out y3);
		TField.Multiply(in t1, in z3, out t1);
		TField.Add(in t1, in y3, out y3);
		TField.Multiply(in t0, in t3, out t0);
		TField.Multiply(in z3, in t4, out z3);
		TField.Add(in z3, in t0, out z3);
		result.X = x3;
		result.Y = y3;
		result.Z = z3;
	}

	// Algorithm 8, for Z2 = 1: 11 products and 2 by 3b, with 3·t0 as above.
	[SkipLocalsInit]
	internal static void Add(in SM9Point<TField> left, in SM9AffinePoint<TField> right, out SM9Point<TField> result)
	{
		TField.Multiply(in left.X, in right.X, out TField t0);
		TField.Multiply(in left.Y, in right.Y, out TField t1);
		TField.Add(in right.X, in right.Y, out TField t3);
		TField.Add(in left.X, in left.Y, out TField t4);
		TField.Multiply(in t3, in t4, out t3);
		TField.Add(in t0, in t1, out t4);
		TField.Subtract(in t3, in t4, out t3);
		TField.Multiply(in right.Y, in left.Z, out t4);
		TField.Add(in t4, in left.Y, out t4);
		TField.Multiply(in right.X, in left.Z, out TField y3);
		TField.Add(in y3, in left.X, out y3);
		TField.MultiplySmall(in t0, 3, out t0);
		TField.MultiplyByThreeB(in left.Z, out TField t2);
		TField.Add(in t1, in t2, out TField z3);
		TField.Subtract(in t1, in t2, out t1);
		TField.MultiplyByThreeB(in y3, out y3);
		TField.Multiply(in t4, in y3, out TField x3);
		TField.Multiply(in t3, in t1, out t2);
		TField.Subtract(in t2, in x3, out x3);
		TField.Multiply(in y3, in t0, out y3);
		TField.Multiply(in t1, in z3, out t1);
		TField.Add(in t1, in y3, out y3);
		TField.Multiply(in t0, in t3, out t0);
		TField.Multiply(in z3, in t4, out z3);
		TField.Add(in z3, in t0, out z3);
		result.X = x3;
		result.Y = y3;
		result.Z = z3;
	}

	// Algorithm 9, 6 products, 2 squares and 1 by 3b, with the repeated sums taken as 8·t0 and 3·t2.
	[SkipLocalsInit]
	internal static void Double(in SM9Point<TField> value, out SM9Point<TField> result)
	{
		TField.Square(in value.Y, out TField t0);
		TField.MultiplySmall(in t0, 8, out TField z3);
		TField.Multiply(in value.Y, in value.Z, out TField t1);
		TField.Square(in value.Z, out TField t2);
		TField.MultiplyByThreeB(in t2, out t2);
		TField.Multiply(in t2, in z3, out TField x3);
		TField.Add(in t0, in t2, out TField y3);
		TField.Multiply(in t1, in z3, out z3);
		TField.MultiplySmall(in t2, 3, out t2);
		TField.Subtract(in t0, in t2, out t0);
		TField.Multiply(in t0, in y3, out y3);
		TField.Add(in x3, in y3, out y3);
		TField.Multiply(in value.X, in value.Y, out t1);
		TField.Multiply(in t0, in t1, out x3);
		TField.Add(in x3, in x3, out x3);
		result.X = x3;
		result.Y = y3;
		result.Z = z3;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Negate(in SM9Point<TField> value, out SM9Point<TField> result)
	{
		result.X = value.X;
		TField.Negate(in value.Y, out result.Y);
		result.Z = value.Z;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Negate(in SM9AffinePoint<TField> value, out SM9AffinePoint<TField> result)
	{
		result.X = value.X;
		TField.Negate(in value.Y, out result.Y);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void ConditionalNegate(ulong mask, ref SM9Point<TField> value)
	{
		TField.Negate(in value.Y, out TField negated);
		TField.ConditionalSelect(mask, in negated, in value.Y, out value.Y);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void ConditionalNegate(ulong mask, ref SM9AffinePoint<TField> value)
	{
		TField.Negate(in value.Y, out TField negated);
		TField.ConditionalSelect(mask, in negated, in value.Y, out value.Y);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void ConditionalSelect(ulong mask, in SM9Point<TField> whenSet, in SM9Point<TField> whenClear, out SM9Point<TField> result)
	{
		TField.ConditionalSelect(mask, in whenSet.X, in whenClear.X, out result.X);
		TField.ConditionalSelect(mask, in whenSet.Y, in whenClear.Y, out result.Y);
		TField.ConditionalSelect(mask, in whenSet.Z, in whenClear.Z, out result.Z);
	}

	// ulong.MaxValue if the points are the same, as X1·Z2 = X2·Z1 and Y1·Z2 = Y2·Z1; with X = 0 and Y ≠ 0 at infinity, that holds for two points at infinity and fails for one.
	[SkipLocalsInit]
	internal static ulong AreEqual(in SM9Point<TField> left, in SM9Point<TField> right)
	{
		TField.Multiply(in left.X, in right.Z, out TField x1);
		TField.Multiply(in right.X, in left.Z, out TField x2);
		TField.Multiply(in left.Y, in right.Z, out TField y1);
		TField.Multiply(in right.Y, in left.Z, out TField y2);
		return TField.AreEqual(in x1, in x2) & TField.AreEqual(in y1, in y2);
	}

	// Returns ulong.MaxValue for the point at infinity, which gives (0, 0), not on the curve, and 0 otherwise. The inversion takes constant time, and Z⁻¹ is erased.
	[SkipLocalsInit]
	internal static ulong ToAffine(in SM9Point<TField> value, out SM9AffinePoint<TField> result)
	{
		ulong infinity = TField.IsZero(in value.Z);
		TField.Invert(in value.Z, out TField inverse);
		TField.Multiply(in value.X, in inverse, out result.X);
		TField.Multiply(in value.Y, in inverse, out result.Y);
		inverse.ZeroMemory();
		return infinity;
	}

	// As above for a public point: returns false for the point at infinity, leaving result 0.
	[SkipLocalsInit]
	internal static bool ToAffineVariableTime(in SM9Point<TField> value, out SM9AffinePoint<TField> result)
	{
		if (TField.IsZero(in value.Z) is not 0)
		{
			result = default;
			return false;
		}

		TField.InvertVariableTime(in value.Z, out TField inverse);
		TField.Multiply(in value.X, in inverse, out result.X);
		TField.Multiply(in value.Y, in inverse, out result.Y);
		return true;
	}

	// None of the points may be the point at infinity. One inversion for all of them, which takes constant time unless variableTime is set, for public points: result[i].X holds the product of the Z of points 0 to i until result[i] is written.
	[SkipLocalsInit]
	internal static void ToAffine(ReadOnlySpan<SM9Point<TField>> points, Span<SM9AffinePoint<TField>> result, bool variableTime)
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
			TField.Multiply(in points[i].X, in zInverse, out result[i].X);
			TField.Multiply(in points[i].Y, in zInverse, out result[i].Y);
		}

		TField.Multiply(in points[0].X, in inverse, out result[0].X);
		TField.Multiply(in points[0].Y, in inverse, out result[0].Y);

		if (!variableTime)
		{
			inverse.ZeroMemory();
			zInverse.ZeroMemory();
		}
	}

	// y² = x³ + b in constant time, for a point that may be a private key, whose squares are erased.
	[SkipLocalsInit]
	internal static bool IsOnCurve(in SM9AffinePoint<TField> point)
	{
		TField.Square(in point.X, out TField right);
		TField.Multiply(in right, in point.X, out right);
		TField.Add(in right, in TField.B, out right);
		TField.Square(in point.Y, out TField left);
		bool onCurve = TField.AreEqual(in left, in right) is not 0;
		left.ZeroMemory();
		right.ZeroMemory();
		return onCurve;
	}

	// Sets result to k·P for a scalar of up to four 64-bit limbs, least significant first, by its NAF of width 4. The time depends on the scalar, which must be public, but not on the point, as the formulas are complete: the point may be a private key, and the multiples in its locals are erased.
	[SkipLocalsInit]
	internal static void MultiplyVariableTime(in SM9Point<TField> point, ReadOnlySpan<ulong> scalar, out SM9Point<TField> result)
	{
		const int nafWidth = 4;
		Debug.Assert(scalar.Length <= 4);

		int length = 64 * scalar.Length;
		Span<sbyte> digits = stackalloc sbyte[length + 1];
		int top = NonAdjacentForm.Recode(scalar, 0, length, nafWidth, digits);
		Span<SM9Point<TField>> multiples = stackalloc SM9Point<TField>[1 << nafWidth - 2];
		multiples[0] = point;
		Double(in point, out SM9Point<TField> twice);

		for (int j = 1; j < multiples.Length; ++j)
		{
			Add(in multiples[j - 1], in twice, out multiples[j]);
		}

		Infinity(out result);
		Unsafe.SkipInit(out SM9Point<TField> negated);

		for (int i = top; i >= 0; --i)
		{
			Double(in result, out result);
			int digit = digits[i];

			if (digit > 0)
			{
				Add(in result, in multiples[digit >> 1], out result);
			}
			else if (digit < 0)
			{
				Negate(in multiples[-digit >> 1], out negated);
				Add(in result, in negated, out result);
			}
		}

		multiples.ZeroMemory();
		twice.ZeroMemory();
		negated.ZeroMemory();
	}
}
