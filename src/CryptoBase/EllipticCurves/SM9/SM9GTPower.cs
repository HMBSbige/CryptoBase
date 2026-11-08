namespace CryptoBase.EllipticCurves.SM9;

// Exponentiation in GT, the subgroup of order N of Fp12* that the pairing maps onto. Its elements lie in the cyclotomic subgroup, where SM9Fp12.CyclotomicSquare holds and inverses are conjugates, and the p-power Frobenius acts on it as the power p. A plain exponent k below N splits by SM9Decomposition.DecomposeFrobenius into k = Σ k_i·p^i (mod N) with non-negative parts of at most 67 bits, and SM9FrobeniusRecoding turns those into 67 signed digits of one table of the eight products x·Π_(j≥1) (x^(p^j))^(u_j). k0 must be odd for the recoding, so an even k0 takes 1 more, which one multiplication by x⁻¹ = x̄ takes back.
// The tables of a fixed base hold the eight entries for each of Teeth combs, raised to 2^(c·Spacing) for comb c: position i of the digits is tooth i/Spacing of offset i mod Spacing, so a product takes Spacing − 1 squares rather than 66.
internal static class SM9GTPower
{
	internal const int Teeth = 17;

	internal const int Spacing = (SM9FrobeniusRecoding.Length + Teeth - 1) / Teeth;

	internal const int FixedTableLength = Teeth * SM9FrobeniusRecoding.TableLength;

	// value^k for value in GT. Neither the time nor the addresses depend on value or k, and the intermediates are erased.
	[SkipLocalsInit]
	internal static void Power(in SM9Fp12 value, in FieldElement<SM9Order> exponent, out SM9Fp12 result)
	{
		Span<SM9Fp12> table = stackalloc SM9Fp12[SM9FrobeniusRecoding.TableLength];
		Span<byte> digits = stackalloc byte[SM9FrobeniusRecoding.Length];
		BuildTable(in value, table);
		ulong even = Recode(in exponent, digits);
		Select(table, digits[^1], out SM9Fp12 power);
		Unsafe.SkipInit(out SM9Fp12 entry);

		for (int i = digits.Length - 2; i >= 0; --i)
		{
			SM9Fp12.CyclotomicSquare(in power, out power);
			Select(table, digits[i], out entry);
			SM9Fp12.Multiply(in power, in entry, out power);
		}

		Correct(ref power, even, in value);
		result = power;
		table.ZeroMemory();
		digits.ZeroMemory();
		power.ZeroMemory();
		entry.ZeroMemory();
	}

	// The FixedTableLength entries of the combs of value in GT, and value⁻¹ for the correction. The time and the addresses do not depend on value, which may be secret.
	[SkipLocalsInit]
	internal static void BuildFixedTable(in SM9Fp12 value, Span<SM9Fp12> table, out SM9Fp12 inverse)
	{
		Debug.Assert(table.Length is FixedTableLength);

		SM9Fp12 toothBase = value;

		for (int c = 0; c < Teeth; ++c)
		{
			if (c > 0)
			{
				for (int k = 0; k < Spacing; ++k)
				{
					SM9Fp12.CyclotomicSquare(in toothBase, out toothBase);
				}
			}

			BuildTable(in toothBase, table.Slice(c * SM9FrobeniusRecoding.TableLength, SM9FrobeniusRecoding.TableLength));
		}

		SM9Fp12.Conjugate(in value, out inverse);
		toothBase.ZeroMemory();
	}

	// value^k from the table of BuildFixedTable and value⁻¹. Neither the time nor the addresses depend on the base or k.
	[SkipLocalsInit]
	internal static void Power(ReadOnlySpan<SM9Fp12> table, in SM9Fp12 inverse, in FieldElement<SM9Order> exponent, out SM9Fp12 result)
	{
		Debug.Assert(table.Length is FixedTableLength);

		Span<byte> digits = stackalloc byte[SM9FrobeniusRecoding.Length];
		ulong even = Recode(in exponent, digits);
		Unsafe.SkipInit(out SM9Fp12 power);
		Unsafe.SkipInit(out SM9Fp12 entry);
		bool first = true;

		for (int offset = Spacing - 1; offset >= 0; --offset)
		{
			if (!first)
			{
				SM9Fp12.CyclotomicSquare(in power, out power);
			}

			for (int c = 0; c < Teeth; ++c)
			{
				int i = c * Spacing + offset;

				// Which positions exist depends on the lengths alone.
				if (i >= digits.Length)
				{
					continue;
				}

				Select(table.Slice(c * SM9FrobeniusRecoding.TableLength, SM9FrobeniusRecoding.TableLength), digits[i], out entry);

				if (first)
				{
					power = entry;
					first = false;
				}
				else
				{
					SM9Fp12.Multiply(in power, in entry, out power);
				}
			}
		}

		Correct(ref power, even, in inverse, true);
		result = power;
		digits.ZeroMemory();
		power.ZeroMemory();
		entry.ZeroMemory();
	}

	// The eight products x·Π_(j≥1) (x^(p^j))^(u_j), u_j bit j − 1 of the index.
	[SkipLocalsInit]
	private static void BuildTable(in SM9Fp12 value, Span<SM9Fp12> table)
	{
		SM9Fp12.Frobenius(in value, out SM9Fp12 b1);
		SM9Fp12.FrobeniusSquared(in value, out SM9Fp12 b2);
		SM9Fp12.FrobeniusCubed(in value, out SM9Fp12 b3);
		table[0] = value;
		SM9Fp12.Multiply(in value, in b1, out table[1]);
		SM9Fp12.Multiply(in value, in b2, out table[2]);
		SM9Fp12.Multiply(in table[1], in b2, out table[3]);

		for (int u = 0; u < 4; ++u)
		{
			SM9Fp12.Multiply(in table[u], in b3, out table[u + 4]);
		}

		b1.ZeroMemory();
		b2.ZeroMemory();
		b3.ZeroMemory();
	}

	// Recodes the parts of k, with k0 made odd, and returns ulong.MaxValue if it was even.
	[SkipLocalsInit]
	internal static ulong Recode(in FieldElement<SM9Order> exponent, Span<byte> digits)
	{
		SM9Decomposition.DecomposeFrobenius(in exponent, out UInt128 k0, out UInt128 k1, out UInt128 k2, out UInt128 k3);
		ulong even = ((ulong)k0 & 1) - 1;
		SM9FrobeniusRecoding.Recode(k0 | 1, k1, k2, k3, digits);
		return even;
	}

	// The entry of digit, conjugated if the digit is negative. Every entry is read, so neither the time nor the addresses depend on the digit.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Select(ReadOnlySpan<SM9Fp12> table, byte digit, out SM9Fp12 result)
	{
		MaskedSelect.Lookup(in MemoryMarshal.GetReference(table), table.Length, (uint)(digit & 7), out result);
		ulong negative = 0 - (ulong)(digit >> 3);
		SM9Fp6.Negate(in result.C1, out SM9Fp6 negated);
		SM9Fp6.ConditionalSelect(negative, in negated, in result.C1, out result.C1);
		negated.ZeroMemory();
	}

	// Multiplies power by x⁻¹ where even is set: x⁻¹ is the conjugate of value, or value itself if it already is the inverse.
	[SkipLocalsInit]
	private static void Correct(ref SM9Fp12 power, ulong even, in SM9Fp12 value, bool isInverse = false)
	{
		SM9Fp12 inverse;

		if (isInverse)
		{
			inverse = value;
		}
		else
		{
			SM9Fp12.Conjugate(in value, out inverse);
		}

		SM9Fp12.Multiply(in power, in inverse, out SM9Fp12 corrected);
		SM9Fp12.ConditionalSelect(even, in corrected, in power, out power);
		inverse.ZeroMemory();
		corrected.ZeroMemory();
	}
}
