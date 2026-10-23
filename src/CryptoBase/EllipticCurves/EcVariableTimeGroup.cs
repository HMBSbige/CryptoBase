using static CryptoBase.EllipticCurves.LimbArithmetic;

namespace CryptoBase.EllipticCurves;

// For a = −3. The time, the branches and the table indices depend on the scalars and the points, so every input must be public: nothing
// that holds a secret may call it.
internal static class EcVariableTimeGroup<TCurve, TField, TOrder>
	where TCurve : struct, IEcCurve
	where TField : unmanaged, IMontgomeryModulus
	where TOrder : unmanaged, IMontgomeryModulus
{
	private const int PointWidth = 5;

	internal static int DigitCount => TOrder.BitLength + 1;

	// Sets result to u1·G + u2·Q for u1 and u2 below n and a point Q on the curve.
	[SkipLocalsInit]
	internal static void MultiplyAdd(in FieldElement<TOrder> u1, in AffinePoint<TField> point, in FieldElement<TOrder> u2, out JacobianPoint<TField> result)
	{
		Span<sbyte> baseDigits = stackalloc sbyte[DigitCount];
		Span<sbyte> pointDigits = stackalloc sbyte[DigitCount];
		int top = Math.Max(Recode(in u1, EcVariableTimeGeneratorTable<TCurve, TField, TOrder>.Width, baseDigits), Recode(in u2, PointWidth, pointDigits));
		ReadOnlySpan<AffinePoint<TField>> baseMultiples = EcVariableTimeGeneratorTable<TCurve, TField, TOrder>.Entries;
		Span<JacobianPoint<TField>> pointMultiples = stackalloc JacobianPoint<TField>[1 << PointWidth - 2];
		JacobianPoint<TField>.FromAffine(in point, out pointMultiples[0]);
		Double(in pointMultiples[0], out JacobianPoint<TField> twice);

		for (int j = 1; j < pointMultiples.Length; ++j)
		{
			Add(in pointMultiples[j - 1], in twice, out pointMultiples[j]);
		}

		// Z = 0, the point at infinity.
		result = default;

		for (int i = top; i >= 0; --i)
		{
			Double(in result, out result);
			int digit = baseDigits[i];

			if (digit is not 0)
			{
				AffinePoint<TField> entry = baseMultiples[Math.Abs(digit) >> 1];

				if (digit < 0)
				{
					FieldElement<TField>.Negate(in entry.Y, out entry.Y);
				}

				Add(in result, in entry, out result);
			}

			digit = pointDigits[i];

			if (digit is not 0)
			{
				JacobianPoint<TField> entry = pointMultiples[Math.Abs(digit) >> 1];

				if (digit < 0)
				{
					FieldElement<TField>.Negate(in entry.Y, out entry.Y);
				}

				Add(in result, in entry, out result);
			}
		}
	}

	// For r in [1, n − 1]. As n < p < 2n, x mod n = r means x = r, or x = r + n where r + n < p, and x = t means X = t·Z².
	[SkipLocalsInit]
	internal static bool XModOrderEquals(in JacobianPoint<TField> point, in FieldElement<TOrder> r)
	{
		Debug.Assert(TField.LimbCount == TOrder.LimbCount);

		if (point.IsInfinity)
		{
			return false;
		}

		// The Montgomery Z² times a plain t is the plain t·Z², to compare with the plain X.
		FieldElement<TField>.Square(in point.Z, out FieldElement<TField> zz);
		FieldElement<TField>.FromMontgomery(in point.X, out FieldElement<TField> x);
		ReadOnlySpan<ulong> candidate = FieldElement<TOrder>.GetLimbs(in r);
		FieldElement<TField>.Multiply(in zz, in FieldElement<TField>.FromLimbs(candidate), out FieldElement<TField> product);

		if (FieldElement<TField>.AreEqual(in x, in product) is not 0)
		{
			return true;
		}

		int count = TField.LimbCount;
		Span<ulong> sum = stackalloc ulong[count];
		Span<ulong> difference = stackalloc ulong[count];
		ulong carry = AddLimbs(ref MemoryMarshal.GetReference(candidate), ref MemoryMarshal.GetReference(TOrder.Modulus), ulong.MaxValue, ref MemoryMarshal.GetReference(sum), count);

		if (carry is not 0 || SubtractLimbs(ref MemoryMarshal.GetReference(sum), ref MemoryMarshal.GetReference(TField.Modulus), ref MemoryMarshal.GetReference(difference), count) is 0)
		{
			return false;
		}

		FieldElement<TField>.Multiply(in zz, in FieldElement<TField>.FromLimbs(sum), out product);
		return FieldElement<TField>.AreEqual(in x, in product) is not 0;
	}

	// Holds for every point: Z = 0 gives Z3 = 0, and no other point has Y = 0, as a curve of odd order has no point of order 2. The result
	// may be the input.
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

	// The result may be left.
	internal static void Add(in JacobianPoint<TField> left, in AffinePoint<TField> right, out JacobianPoint<TField> result)
	{
		if (left.IsInfinity)
		{
			JacobianPoint<TField>.FromAffine(in right, out result);
			return;
		}

		FieldElement<TField>.Square(in left.Z, out FieldElement<TField> zz);
		FieldElement<TField>.Multiply(in right.X, in zz, out FieldElement<TField> h);
		FieldElement<TField>.Subtract(in h, in left.X, out h);
		FieldElement<TField>.Multiply(in zz, in left.Z, out zz);
		FieldElement<TField>.Multiply(in right.Y, in zz, out FieldElement<TField> r);
		FieldElement<TField>.Subtract(in r, in left.Y, out r);
		FieldElement<TField>.Add(in r, in r, out r);

		if (FieldElement<TField>.IsZero(in h) is not 0)
		{
			AddSameX(in left, in r, out result);
			return;
		}

		FieldElement<TField>.Square(in h, out FieldElement<TField> i);
		FieldElement<TField>.Add(in i, in i, out i);
		FieldElement<TField>.Add(in i, in i, out i);
		FieldElement<TField>.Multiply(in h, in i, out FieldElement<TField> j);
		FieldElement<TField>.Multiply(in left.X, in i, out FieldElement<TField> v);
		FieldElement<TField>.Multiply(in left.Y, in j, out FieldElement<TField> yj);
		FieldElement<TField>.Multiply(in left.Z, in h, out h);
		FieldElement<TField>.Add(in h, in h, out result.Z);
		Combine(in r, in j, in v, in yj, out result.X, out result.Y);
	}

	// The result may be either input.
	internal static void Add(in JacobianPoint<TField> left, in JacobianPoint<TField> right, out JacobianPoint<TField> result)
	{
		if (left.IsInfinity)
		{
			result = right;
			return;
		}

		if (right.IsInfinity)
		{
			result = left;
			return;
		}

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

		if (FieldElement<TField>.IsZero(in h) is not 0)
		{
			AddSameX(in left, in r, out result);
			return;
		}

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
	}

	// Writes the NAF of width w of k and returns the index of its top nonzero digit, or −1 for k = 0. A nonzero digit at i carries out only
	// if the w bits of k from i plus the carry in exceed 2^(w − 1), which needs a bit of k at or above i + w − 1, so i + w ≤ N for
	// N = TOrder.BitLength: digit N takes the last carry.
	internal static int Recode(in FieldElement<TOrder> scalar, int width, Span<sbyte> digits)
	{
		// Digits up to 2^(w − 1) − 1 must fit in an sbyte.
		Debug.Assert(width is >= 2 and <= 8);
		Debug.Assert(digits.Length == DigitCount);

		ReadOnlySpan<ulong> limbs = FieldElement<TOrder>.GetLimbs(in scalar);
		uint mask = (1u << width) - 1;
		uint carry = 0;
		int top = -1;
		digits.Clear();

		for (int i = 0; i < digits.Length;)
		{
			uint window = (uint)ReadBits(limbs, i) & mask;

			if ((window & 1) == carry)
			{
				++i;
				continue;
			}

			uint value = window + carry;
			carry = value >> width - 1;
			digits[i] = (sbyte)(value - (carry << width));
			top = i;
			i += width;
		}

		Debug.Assert(carry is 0);

		return top;
	}

	// The result may be left.
	private static void AddSameX(in JacobianPoint<TField> left, in FieldElement<TField> r, out JacobianPoint<TField> result)
	{
		if (FieldElement<TField>.IsZero(in r) is not 0)
		{
			Double(in left, out result);
		}
		else
		{
			result = default;
		}
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
}
