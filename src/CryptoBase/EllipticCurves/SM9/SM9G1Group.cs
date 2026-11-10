using static CryptoBase.EllipticCurves.LimbArithmetic;

namespace CryptoBase.EllipticCurves.SM9;

// The scalar arithmetic of G1 = E(Fp), E: y² = x³ + 5, of prime order N with the generator P1 of GM/T 0044.5 §3.1. Scalars are plain values below N. The products give projective points whose coordinates depend on the scalar and not only on the product, so a caller makes them affine or erases them.
internal static class SM9G1Group
{
	// The windows of the product with a variable point: the two parts of GLV, below 2^127 in magnitude, take 26 digits each.
	internal const int PointWidth = 5;

	internal const int PointDigitCount = 127 / PointWidth + 1;

	internal const int PointTableLength = (1 << PointWidth - 1) + 1;

	// Plain coordinates of P1.
	private static ReadOnlySpan<ulong> GeneratorX => [0xE8C4E4817C66DDDD, 0xE1E4086909DC3280, 0xF5ED0704487D01D6, 0x93DE051D62BF718F];

	private static ReadOnlySpan<ulong> GeneratorY => [0x0C464CD70A3EA616, 0x1C1C00CBFA602435, 0x631065125C395BBC, 0x21FE8DDA4F21E607];

	// β = 0xF300000002A3A6F2780272354F8B78F4D5FC11967BE65333 in Montgomery form, the cube root of unity in Fp for which φ(x, y) = (βx, y) is [λ]P on G1, λ = 0x1E600000005474DE26804E46A9A65C91E2BF5F68BCD8990E5, a root of λ² + λ + 1 mod N.
	private static ReadOnlySpan<ulong> BetaLimbs => [0x0009B6FAA6CCDA64, 0x00033906AC1994F1, 0x00083CA407298A35, 0x000A40E7F4F3D6F0, 0x00000453E74894E5];

	internal static readonly SM9AffinePoint<SM9Fp> Generator = FromPlain(GeneratorX, GeneratorY);

	// Windows of width 6, 43 of 32 entries.
	internal static readonly SM9BaseTable<SM9Fp> BaseTable = new(in Generator, 6);

	// k·P for a point P of G1, by GLV: k = k1 + k2·λ with |k1|, |k2| < 2^127, and k1·P + k2·φ(P) by windows of width 5 over both, from tables of 0·P to 16·P and their images under φ, with the point at infinity as entry 0, which the complete formulas add. Neither the time nor the addresses depend on k or P.
	[SkipLocalsInit]
	internal static void Multiply(in SM9AffinePoint<SM9Fp> point, in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp> result)
	{
		Span<sbyte> digits1 = stackalloc sbyte[PointDigitCount];
		Span<sbyte> digits2 = stackalloc sbyte[PointDigitCount];
		Digits(in scalar, digits1, digits2, out ulong sign1, out ulong sign2);
		Span<SM9Point<SM9Fp>> multiples = stackalloc SM9Point<SM9Fp>[PointTableLength];
		Span<SM9Point<SM9Fp>> images = stackalloc SM9Point<SM9Fp>[PointTableLength];
		SM9Curve<SM9Fp>.Infinity(out multiples[0]);
		SM9Curve<SM9Fp>.FromAffine(in point, out multiples[1]);

		for (int j = 2; j < PointTableLength; ++j)
		{
			SM9Curve<SM9Fp>.Add(in multiples[j - 1], in point, out multiples[j]);
		}

		for (int j = 0; j < PointTableLength; ++j)
		{
			Endomorphism(in multiples[j], out images[j]);
		}

		SM9Curve<SM9Fp>.Infinity(out result);

		for (int i = PointDigitCount - 1; i >= 0; --i)
		{
			if (i < PointDigitCount - 1)
			{
				for (int k = 0; k < PointWidth; ++k)
				{
					SM9Curve<SM9Fp>.Double(in result, out result);
				}
			}

			AddDigit(ref result, multiples, digits1[i], sign1);
			AddDigit(ref result, images, digits2[i], sign2);
		}

		digits1.ZeroMemory();
		digits2.ZeroMemory();
		multiples.ZeroMemory();
		images.ZeroMemory();
	}

	// The digits of the two parts of GLV for windows of width 5, and the sign masks of the parts.
	[SkipLocalsInit]
	internal static void Digits(in FieldElement<SM9Order> scalar, Span<sbyte> digits1, Span<sbyte> digits2, out ulong sign1, out ulong sign2)
	{
		SM9Decomposition.DecomposeG1(in scalar, out UInt128 k1, out UInt128 k2);
		Span<ulong> magnitude = stackalloc ulong[2];
		sign1 = Magnitude(k1, magnitude);
		RecodeSignedWindows(magnitude, PointWidth, digits1);
		sign2 = Magnitude(k2, magnitude);
		RecodeSignedWindows(magnitude, PointWidth, digits2);
		magnitude.ZeroMemory();
	}

	// k·P1 + addend for a public k and addend.
	[SkipLocalsInit]
	internal static void MultiplyBaseAddVariableTime(in FieldElement<SM9Order> scalar, in SM9Point<SM9Fp> addend, out SM9Point<SM9Fp> result)
	{
		BaseTable.MultiplyAddVariableTime(in scalar, in addend, out result);
	}

	// The NAF of the parts of GLV in the variable-time product: width 5 over the 127 bits of each, with the odd multiples P to 15P.
	internal const int VariableTimeWidth = 5;

	internal const int VariableTimeBits = 127;

	internal const int VariableTimeTableLength = 1 << VariableTimeWidth - 2;

	// k·P for a public P of G1 and a public k, by GLV: k = k1 + k2·λ, and k1·P + k2·φ(P) by the NAF of width 5 of |k1| and |k2|, which share the doublings, from the odd multiples of ±P and their images under φ. The time depends on k.
	[SkipLocalsInit]
	internal static void MultiplyVariableTime(in SM9AffinePoint<SM9Fp> point, in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp> result)
	{
		Span<sbyte> digits1 = stackalloc sbyte[VariableTimeBits + 1];
		Span<sbyte> digits2 = stackalloc sbyte[VariableTimeBits + 1];
		int top = VariableTimeDigits(in scalar, digits1, digits2, out bool negative1, out bool negative2);
		Span<SM9Point<SM9Fp>> multiples = stackalloc SM9Point<SM9Fp>[VariableTimeTableLength];
		Span<SM9Point<SM9Fp>> images = stackalloc SM9Point<SM9Fp>[VariableTimeTableLength];
		SM9Curve<SM9Fp>.FromAffine(in point, out multiples[0]);
		SM9Curve<SM9Fp>.Double(in multiples[0], out SM9Point<SM9Fp> twice);

		for (int j = 1; j < multiples.Length; ++j)
		{
			SM9Curve<SM9Fp>.Add(in multiples[j - 1], in twice, out multiples[j]);
		}

		VariableTimeImages(multiples, images, negative1, negative2);
		SM9Curve<SM9Fp>.Infinity(out result);

		for (int i = top; i >= 0; --i)
		{
			SM9Curve<SM9Fp>.Double(in result, out result);
			AddVariableTime(ref result, multiples, digits1[i]);
			AddVariableTime(ref result, images, digits2[i]);
		}
	}

	// The NAF of |k1| and |k2| for k = k1 + k2·λ and whether each part is negative, and the index of the top nonzero digit of either.
	[SkipLocalsInit]
	internal static int VariableTimeDigits(in FieldElement<SM9Order> scalar, Span<sbyte> digits1, Span<sbyte> digits2, out bool negative1, out bool negative2)
	{
		SM9Decomposition.DecomposeG1(in scalar, out UInt128 k1, out UInt128 k2);
		Span<ulong> magnitude = stackalloc ulong[2];
		negative1 = Magnitude(k1, magnitude) is not 0;
		int top = NonAdjacentForm.Recode(magnitude, 0, VariableTimeBits, VariableTimeWidth, digits1);
		negative2 = Magnitude(k2, magnitude) is not 0;
		return Math.Max(top, NonAdjacentForm.Recode(magnitude, 0, VariableTimeBits, VariableTimeWidth, digits2));
	}

	// The images under φ of the odd multiples, and both tables negated where their part is negative.
	internal static void VariableTimeImages(Span<SM9Point<SM9Fp>> multiples, Span<SM9Point<SM9Fp>> images, bool negative1, bool negative2)
	{
		for (int j = 0; j < multiples.Length; ++j)
		{
			Endomorphism(in multiples[j], out images[j]);

			if (negative2)
			{
				SM9Fp.Negate(in images[j].Y, out images[j].Y);
			}

			if (negative1)
			{
				SM9Fp.Negate(in multiples[j].Y, out multiples[j].Y);
			}
		}
	}

	// φ(X : Y : Z) = (βX : Y : Z).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Endomorphism(in SM9Point<SM9Fp> point, out SM9Point<SM9Fp> result)
	{
		SM9Fp.Multiply(in point.X, in SM9Fp.FromConstant(BetaLimbs), out result.X);
		result.Y = point.Y;
		result.Z = point.Z;
	}

	// Adds digit·(±P) from multiples, negated where the digit and the sign of the part differ. Every entry is read.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void AddDigit(ref SM9Point<SM9Fp> result, ReadOnlySpan<SM9Point<SM9Fp>> multiples, int digit, ulong partSign)
	{
		int sign = digit >> 31;
		MaskedSelect.Lookup(in MemoryMarshal.GetReference(multiples), multiples.Length, (uint)((digit ^ sign) - sign), out SM9Point<SM9Fp> entry);
		SM9Curve<SM9Fp>.ConditionalNegate((ulong)sign ^ partSign, ref entry);
		SM9Curve<SM9Fp>.Add(in result, in entry, out result);
		entry.ZeroMemory();
	}

	// Adds digit·P from the odd multiples for an odd digit, negated for a negative one, or nothing for 0.
	[SkipLocalsInit]
	private static void AddVariableTime(ref SM9Point<SM9Fp> result, ReadOnlySpan<SM9Point<SM9Fp>> multiples, int digit)
	{
		if (digit > 0)
		{
			SM9Curve<SM9Fp>.Add(in result, in multiples[digit >> 1], out result);
		}
		else if (digit < 0)
		{
			SM9Point<SM9Fp> entry = multiples[-digit >> 1];
			SM9Fp.Negate(in entry.Y, out entry.Y);
			SM9Curve<SM9Fp>.Add(in result, in entry, out result);
		}
	}

	// Writes |part| in two limbs and returns its sign mask, for a part in two's complement.
	[SkipLocalsInit]
	private static ulong Magnitude(UInt128 part, Span<ulong> destination)
	{
		ulong low = (ulong)part;
		ulong high = (ulong)(part >> 64);
		ulong sign = (ulong)((long)high >> 63);
		ulong carry = 0;
		destination[0] = AddWithCarry(low ^ sign, sign & 1, ref carry);
		destination[1] = AddWithCarry(high ^ sign, 0, ref carry);
		return sign;
	}

	[SkipLocalsInit]
	private static SM9AffinePoint<SM9Fp> FromPlain(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y)
	{
		SM9AffinePoint<SM9Fp> point;
		SM9Fp.FromLimbs(x, out point.X);
		SM9Fp.ToMontgomery(in point.X, out point.X);
		SM9Fp.FromLimbs(y, out point.Y);
		SM9Fp.ToMontgomery(in point.Y, out point.Y);
		return point;
	}
}
