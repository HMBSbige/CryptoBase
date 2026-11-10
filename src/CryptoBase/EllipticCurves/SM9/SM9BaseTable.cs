using static CryptoBase.EllipticCurves.LimbArithmetic;

namespace CryptoBase.EllipticCurves.SM9;

// The fixed-base table of a point G of prime order N: window i holds j·2^(wi)·G for j from 1 to 2^(w − 1), affine, for the digits of LimbArithmetic.RecodeSignedWindows, so that a product takes one mixed addition per window and no doubling. G is a generator or a point that many products take, as a key may be.
internal sealed class SM9BaseTable<TField> where TField : unmanaged, ISM9Field<TField>
{
	private readonly SM9AffinePoint<TField>[] _entries;

	// The entries come from the kernel of SM9KernelDispatch. A secret G gives a table as secret as it is.
	internal SM9BaseTable(in SM9AffinePoint<TField> generator, int width, bool secret = false)
	{
		Width = width;
		WindowCount = SM9Windows.DigitCount(SM9Order.BitLength, width);
		_entries = new SM9AffinePoint<TField>[WindowCount * WindowLength];

		if (typeof(TField) == typeof(SM9Fp))
		{
			SM9KernelDispatch.BuildBaseTable(in Unsafe.As<SM9AffinePoint<TField>, SM9AffinePoint<SM9Fp>>(ref Unsafe.AsRef(in generator)), width, secret, MemoryMarshal.Cast<SM9AffinePoint<TField>, SM9AffinePoint<SM9Fp>>(_entries.AsSpan()));
		}
		else
		{
			SM9KernelDispatch.BuildBaseTable(in Unsafe.As<SM9AffinePoint<TField>, SM9AffinePoint<SM9Fp2>>(ref Unsafe.AsRef(in generator)), width, secret, MemoryMarshal.Cast<SM9AffinePoint<TField>, SM9AffinePoint<SM9Fp2>>(_entries.AsSpan()));
		}
	}

	// The entries for G and the width, window after window, as the scalar kernel builds them: the base of each window doubles into 2B, and each later entry j·B is (j − 1)·B + B; the last entry, 2^(w − 1)·B, doubles into the base of the next window. A public G takes the inversion in variable time; a secret one takes it in constant time, and its projective multiples are erased. The formulas are complete, so nothing else depends on G.
	internal static void BuildEntries(in SM9AffinePoint<TField> generator, int width, bool secret, Span<SM9AffinePoint<TField>> entries)
	{
		int windowLength = 1 << width - 1;
		SM9Point<TField>[] multiples = new SM9Point<TField>[entries.Length];
		SM9Curve<TField>.FromAffine(in generator, out SM9Point<TField> windowBase);

		for (int i = 0; i < multiples.Length; i += windowLength)
		{
			multiples[i] = windowBase;
			SM9Curve<TField>.Double(in windowBase, out multiples[i + 1]);

			for (int j = 2; j < windowLength; ++j)
			{
				SM9Curve<TField>.Add(in multiples[i + j - 1], in windowBase, out multiples[i + j]);
			}

			SM9Curve<TField>.Double(in multiples[i + windowLength - 1], out windowBase);
		}

		SM9Curve<TField>.ToAffine(multiples, entries, !secret);

		if (secret)
		{
			multiples.AsSpan().ZeroMemory();
			windowBase.ZeroMemory();
		}
	}

	internal int Width { get; }

	internal int WindowCount { get; }

	internal int WindowLength => 1 << Width - 1;

	// The entries, window after window.
	internal ReadOnlySpan<SM9AffinePoint<TField>> Entries => _entries;

	// k·G for a plain k below N. Neither the time nor the addresses depend on k or G: each window reads all of its entries, takes the negation where the digit is negative, and keeps the sum only where the digit is not 0, whose lookup gives (0, 0), not a point. The complete formulas take every sum, the point at infinity included. The projective form of the result depends on k and not only on k·G, so a caller makes it affine or erases it.
	[SkipLocalsInit]
	internal void Multiply(in FieldElement<SM9Order> scalar, out SM9Point<TField> result)
	{
		Span<sbyte> digits = stackalloc sbyte[WindowCount];
		RecodeSignedWindows(FieldElement<SM9Order>.GetLimbs(in scalar), Width, digits);
		SM9Curve<TField>.Infinity(out result);
		ref SM9AffinePoint<TField> entries = ref MemoryMarshal.GetArrayDataReference(_entries);
		Unsafe.SkipInit(out SM9AffinePoint<TField> entry);
		Unsafe.SkipInit(out SM9Point<TField> sum);

		for (int i = 0; i < digits.Length; ++i)
		{
			int digit = digits[i];
			int sign = digit >> 31;
			MaskedSelect.Lookup(in Unsafe.Add(ref entries, i * WindowLength), WindowLength, (uint)((digit ^ sign) - sign) - 1, out entry);
			SM9Curve<TField>.ConditionalNegate((ulong)sign, ref entry);
			SM9Curve<TField>.Add(in result, in entry, out sum);
			SM9Curve<TField>.ConditionalSelect(ZeroMask((ulong)digit), in result, in sum, out result);
		}

		digits.ZeroMemory();
		entry.ZeroMemory();
		sum.ZeroMemory();
	}

	// k·G + addend for a public k, G and addend: the windows of digit 0 are skipped and the others read by index.
	[SkipLocalsInit]
	internal void MultiplyAddVariableTime(in FieldElement<SM9Order> scalar, in SM9Point<TField> addend, out SM9Point<TField> result)
	{
		Span<sbyte> digits = stackalloc sbyte[WindowCount];
		RecodeSignedWindows(FieldElement<SM9Order>.GetLimbs(in scalar), Width, digits);
		result = addend;

		for (int i = 0; i < digits.Length; ++i)
		{
			int digit = digits[i];

			if (digit is 0)
			{
				continue;
			}

			SM9AffinePoint<TField> entry = _entries[i * WindowLength + Math.Abs(digit) - 1];

			if (digit < 0)
			{
				SM9Curve<TField>.Negate(in entry, out entry);
			}

			SM9Curve<TField>.Add(in result, in entry, out result);
		}
	}

	// Erases the entries, for the table of a secret point once it is no longer needed.
	internal void Clear()
	{
		_entries.AsSpan().ZeroMemory();
	}
}
