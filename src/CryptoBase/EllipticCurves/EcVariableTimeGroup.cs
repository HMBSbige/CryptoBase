using static CryptoBase.EllipticCurves.LimbArithmetic;

namespace CryptoBase.EllipticCurves;

// For a = −3. The time, the branches and the table indices depend on the scalars and the points, so every input must be public: nothing that holds a secret may call it.
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
		EcGroup<TCurve, TField, TOrder>.Double(in pointMultiples[0], out JacobianPoint<TField> twice);

		for (int j = 1; j < pointMultiples.Length; ++j)
		{
			Add(in pointMultiples[j - 1], in twice, out pointMultiples[j]);
		}

		// Z = 0, the point at infinity.
		result = default;

		for (int i = top; i >= 0; --i)
		{
			EcGroup<TCurve, TField, TOrder>.Double(in result, out result);
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

	// As above, with the table that EcVariableTimePointTable builds for Q. Each part of u2 has a NAF of its own, which needs only the doublings of one part; u1·G follows from the windows of EcGeneratorTable, which need none.
	[SkipLocalsInit]
	internal static void MultiplyAdd(in FieldElement<TOrder> u1, ReadOnlySpan<AffinePoint<TField>> pointTable, in FieldElement<TOrder> u2, out JacobianPoint<TField> result)
	{
		Debug.Assert(pointTable.Length == EcVariableTimePointTable<TCurve, TField, TOrder>.Length);

		const int parts = EcVariableTimePointTable<TCurve, TField, TOrder>.PartCount;
		int partLength = EcVariableTimePointTable<TCurve, TField, TOrder>.PartLength;
		int partEntries = EcVariableTimePointTable<TCurve, TField, TOrder>.PartEntryCount;
		int stride = partLength + 1;
		Span<sbyte> pointDigits = stackalloc sbyte[parts * stride];
		int top = -1;

		for (int c = 0; c < parts; ++c)
		{
			top = Math.Max(top, Recode(in u2, c * partLength, partLength, EcVariableTimePointTable<TCurve, TField, TOrder>.Width, pointDigits.Slice(c * stride, stride)));
		}

		// Z = 0, the point at infinity.
		result = default;

		for (int i = top; i >= 0; --i)
		{
			if (i < top)
			{
				EcGroup<TCurve, TField, TOrder>.Double(in result, out result);
			}

			for (int c = 0; c < parts; ++c)
			{
				int digit = pointDigits[c * stride + i];

				if (digit is not 0)
				{
					AffinePoint<TField> entry = pointTable[c * partEntries + (Math.Abs(digit) >> 1)];

					if (digit < 0)
					{
						FieldElement<TField>.Negate(in entry.Y, out entry.Y);
					}

					Add(in result, in entry, out result);
				}
			}
		}

		int width = TCurve.GeneratorWindowWidth;
		int windowCount = EcGeneratorTable<TCurve, TField, TOrder>.WindowCount;
		int windowLength = EcGeneratorTable<TCurve, TField, TOrder>.WindowLength;
		ReadOnlySpan<AffinePoint<TField>> windows = EcGeneratorTable<TCurve, TField, TOrder>.Entries;
		ReadOnlySpan<ulong> limbs = FieldElement<TOrder>.GetLimbs(in u1);
		uint mask = (1u << width) - 1;
		uint carry = 0;

		// The digits of EcGroup.MultiplyBase, from [−2^(w − 1) + 1, 2^(w − 1)].
		for (int i = 0; i < windowCount; ++i)
		{
			uint value = ((uint)ReadBits(limbs, i * width) & mask) + carry;
			carry = value > (uint)windowLength ? 1u : 0u;
			int digit = (int)(value - (carry << width));

			if (digit is not 0)
			{
				AffinePoint<TField> entry = windows[i * windowLength + Math.Abs(digit) - 1];

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

	// The result may be left.
	internal static void Add(in JacobianPoint<TField> left, in AffinePoint<TField> right, out JacobianPoint<TField> result)
	{
		if (left.IsInfinity)
		{
			JacobianPoint<TField>.FromAffine(in right, out result);
			return;
		}

		// Opposite points give Z = 0 by themselves. Equal ones need the double, of right, as result may already hold the sum over left.
		if (EcGroup<TCurve, TField, TOrder>.AddDistinct(in left, in right, out result) is not 0)
		{
			JacobianPoint<TField>.FromAffine(in right, out result);
			EcGroup<TCurve, TField, TOrder>.Double(in result, out result);
		}
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

		// Opposite points give Z = 0 by themselves; equal ones need the double.
		if (EcGroup<TCurve, TField, TOrder>.AddDistinct(in left, in right, out JacobianPoint<TField> sum) is not 0)
		{
			EcGroup<TCurve, TField, TOrder>.Double(in left, out result);
			return;
		}

		result = sum;
	}

	// Writes the NAF of width w of k and returns the index of its top nonzero digit, or −1 for k = 0.
	internal static int Recode(in FieldElement<TOrder> scalar, int width, Span<sbyte> digits)
	{
		return Recode(in scalar, 0, TOrder.BitLength, width, digits);
	}

	// As above for the value of the bits of k from start to start + length − 1, with length + 1 digits. A nonzero digit at i carries out only if the w bits from i plus the carry in exceed 2^(w − 1), which needs a bit at or above i + w − 1, so i + w ≤ length: digit length takes the last carry.
	internal static int Recode(in FieldElement<TOrder> scalar, int start, int length, int width, Span<sbyte> digits)
	{
		// Digits up to 2^(w − 1) − 1 must fit in an sbyte.
		Debug.Assert(width is >= 2 and <= 8);
		Debug.Assert(digits.Length == length + 1);

		ReadOnlySpan<ulong> limbs = FieldElement<TOrder>.GetLimbs(in scalar);
		uint mask = (1u << width) - 1;
		uint carry = 0;
		int top = -1;
		digits.Clear();

		for (int i = 0; i < digits.Length;)
		{
			// The mask leaves out the bits from start + length on.
			uint window = (uint)ReadBits(limbs, start + i) & mask >> Math.Max(width - (length - i), 0);

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
}
