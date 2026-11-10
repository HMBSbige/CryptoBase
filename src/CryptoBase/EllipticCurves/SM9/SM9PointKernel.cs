namespace CryptoBase.EllipticCurves.SM9;

// The product of G1 with a variable point on the formulas of SM9PointLanes for one point: the algorithm of SM9G1Group.Multiply, with the same digits, tables and sums, each doubling and addition taking its products in two rows. The tables stay in SM9Point form, so that a masked scan reads as many bytes as there, and each entry goes into lanes after its selection. Neither the time nor the addresses depend on the scalar or the point, and the intermediates are cleared.
internal static class SM9PointKernel<TVector> where TVector : unmanaged, ISM9Vector<TVector>
{
	// k·P for P of G1, as SM9G1Group.Multiply.
	[SkipLocalsInit]
	internal static void MultiplyG1(in SM9AffinePoint<SM9Fp> point, in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp> result)
	{
		Span<sbyte> digits1 = stackalloc sbyte[SM9G1Group.PointDigitCount];
		Span<sbyte> digits2 = stackalloc sbyte[SM9G1Group.PointDigitCount];
		SM9G1Group.Digits(in scalar, digits1, digits2, out ulong sign1, out ulong sign2);
		Span<SM9Point<SM9Fp>> multiples = stackalloc SM9Point<SM9Fp>[SM9G1Group.PointTableLength];
		Span<SM9Point<SM9Fp>> images = stackalloc SM9Point<SM9Fp>[SM9G1Group.PointTableLength];
		int e = SM9Lanes<TVector>.FpLanes.ElementLength;
		Span<byte> storage = stackalloc byte[AlignedScratch.StorageLength<ulong>(2 * e + SM9PointLanes<TVector, SM9Lanes<TVector>.FpLanes, SM9Fp>.SingleWorkLength)];
		ref ulong sum = ref Workspace(storage);
		ref ulong entry = ref Unsafe.Add(ref sum, e);
		ref ulong work = ref Unsafe.Add(ref entry, e);
		BuildTablesG1(in point, multiples, images, ref sum, ref entry, ref work);
		SM9PointLanes<TVector, SM9Lanes<TVector>.FpLanes, SM9Fp>.InfinitySingle(ref sum);

		for (int i = SM9G1Group.PointDigitCount - 1; i >= 0; --i)
		{
			if (i < SM9G1Group.PointDigitCount - 1)
			{
				for (int k = 0; k < SM9G1Group.PointWidth; ++k)
				{
					SM9PointLanes<TVector, SM9Lanes<TVector>.FpLanes, SM9Fp>.DoubleSingle(ref sum, ref sum, ref work);
				}
			}

			AddDigit(ref sum, multiples, digits1[i], sign1, ref entry, ref work);
			AddDigit(ref sum, images, digits2[i], sign2, ref entry, ref work);
		}

		SM9PointLanes<TVector, SM9Lanes<TVector>.FpLanes, SM9Fp>.JoinSingle(ref sum, out result);
		digits1.ZeroMemory();
		digits2.ZeroMemory();
		multiples.ZeroMemory();
		images.ZeroMemory();
		storage.ZeroMemory();
	}

	// k·P for a public P of G1 and a public k, as SM9G1Group.MultiplyVariableTime: the odd multiples come from AddSingle with 2P, and each digit adds its entry, negated where it is negative.
	[SkipLocalsInit]
	internal static void MultiplyG1VariableTime(in SM9AffinePoint<SM9Fp> point, in FieldElement<SM9Order> scalar, out SM9Point<SM9Fp> result)
	{
		Span<sbyte> digits1 = stackalloc sbyte[SM9G1Group.VariableTimeBits + 1];
		Span<sbyte> digits2 = stackalloc sbyte[SM9G1Group.VariableTimeBits + 1];
		int top = SM9G1Group.VariableTimeDigits(in scalar, digits1, digits2, out bool negative1, out bool negative2);
		Span<SM9Point<SM9Fp>> multiples = stackalloc SM9Point<SM9Fp>[SM9G1Group.VariableTimeTableLength];
		Span<SM9Point<SM9Fp>> images = stackalloc SM9Point<SM9Fp>[SM9G1Group.VariableTimeTableLength];
		int e = SM9Lanes<TVector>.FpLanes.ElementLength;
		Span<byte> storage = stackalloc byte[AlignedScratch.StorageLength<ulong>(2 * e + SM9PointLanes<TVector, SM9Lanes<TVector>.FpLanes, SM9Fp>.SingleWorkLength)];
		ref ulong sum = ref Workspace(storage);
		ref ulong entry = ref Unsafe.Add(ref sum, e);
		ref ulong work = ref Unsafe.Add(ref entry, e);
		SM9Curve<SM9Fp>.FromAffine(in point, out multiples[0]);
		SM9PointLanes<TVector, SM9Lanes<TVector>.FpLanes, SM9Fp>.SplitSingle(in multiples[0], ref sum);
		SM9PointLanes<TVector, SM9Lanes<TVector>.FpLanes, SM9Fp>.DoubleSingle(ref sum, ref sum, ref work);
		SM9PointLanes<TVector, SM9Lanes<TVector>.FpLanes, SM9Fp>.JoinSingle(ref sum, out SM9Point<SM9Fp> twice);
		SM9PointLanes<TVector, SM9Lanes<TVector>.FpLanes, SM9Fp>.SplitEntry(in twice, ref entry);
		SM9PointLanes<TVector, SM9Lanes<TVector>.FpLanes, SM9Fp>.SplitSingle(in multiples[0], ref sum);

		for (int j = 1; j < multiples.Length; ++j)
		{
			SM9PointLanes<TVector, SM9Lanes<TVector>.FpLanes, SM9Fp>.AddSingle(ref sum, ref entry, ref sum, ref work);
			SM9PointLanes<TVector, SM9Lanes<TVector>.FpLanes, SM9Fp>.JoinSingle(ref sum, out multiples[j]);
		}

		SM9G1Group.VariableTimeImages(multiples, images, negative1, negative2);
		SM9PointLanes<TVector, SM9Lanes<TVector>.FpLanes, SM9Fp>.InfinitySingle(ref sum);

		for (int i = top; i >= 0; --i)
		{
			SM9PointLanes<TVector, SM9Lanes<TVector>.FpLanes, SM9Fp>.DoubleSingle(ref sum, ref sum, ref work);
			AddVariableTime(ref sum, multiples, digits1[i], ref entry, ref work);
			AddVariableTime(ref sum, images, digits2[i], ref entry, ref work);
		}

		SM9PointLanes<TVector, SM9Lanes<TVector>.FpLanes, SM9Fp>.JoinSingle(ref sum, out result);
	}

	// [a]Q for a = 6t + 2 and Q of E'(Fp2) with reduced coordinates, by the NAF of a, SM9MillerLoop.Digits, on the formulas for one point: Q for the top digit, then a doubling for each digit below it and an addition of Q or −Q for each nonzero one, the complete formulas taking every sum. The time depends on a alone, so Q may be a private key, and the workspace and −Q are erased.
	[SkipLocalsInit]
	internal static void MultiplyByLoopScalarG2(in SM9Point<SM9Fp2> point, out SM9Point<SM9Fp2> result)
	{
		int e = SM9Lanes<TVector>.Fp2Lanes.ElementLength;
		Span<byte> storage = stackalloc byte[AlignedScratch.StorageLength<ulong>(3 * e + SM9PointLanes<TVector, SM9Lanes<TVector>.Fp2Lanes, SM9Fp2>.SingleWorkLength)];
		ref ulong sum = ref Workspace(storage);
		ref ulong entry = ref Unsafe.Add(ref sum, e);
		ref ulong negated = ref Unsafe.Add(ref entry, e);
		ref ulong work = ref Unsafe.Add(ref negated, e);
		SM9Curve<SM9Fp2>.Negate(in point, out SM9Point<SM9Fp2> opposite);
		SM9PointLanes<TVector, SM9Lanes<TVector>.Fp2Lanes, SM9Fp2>.SplitSingle(in point, ref sum);
		SM9PointLanes<TVector, SM9Lanes<TVector>.Fp2Lanes, SM9Fp2>.SplitEntry(in point, ref entry);
		SM9PointLanes<TVector, SM9Lanes<TVector>.Fp2Lanes, SM9Fp2>.SplitEntry(in opposite, ref negated);
		ReadOnlySpan<sbyte> digits = SM9MillerLoop.Digits;
		Debug.Assert(digits[^1] is 1);

		for (int i = digits.Length - 2; i >= 0; --i)
		{
			SM9PointLanes<TVector, SM9Lanes<TVector>.Fp2Lanes, SM9Fp2>.DoubleSingle(ref sum, ref sum, ref work);

			if (digits[i] > 0)
			{
				SM9PointLanes<TVector, SM9Lanes<TVector>.Fp2Lanes, SM9Fp2>.AddSingle(ref sum, ref entry, ref sum, ref work);
			}
			else if (digits[i] < 0)
			{
				SM9PointLanes<TVector, SM9Lanes<TVector>.Fp2Lanes, SM9Fp2>.AddSingle(ref sum, ref negated, ref sum, ref work);
			}
		}

		SM9PointLanes<TVector, SM9Lanes<TVector>.Fp2Lanes, SM9Fp2>.JoinSingle(ref sum, out result);
		storage.ZeroMemory();
		opposite.ZeroMemory();
	}

	// Adds digit·P from the odd multiples for an odd digit, negated for a negative one, or nothing for 0.
	[SkipLocalsInit]
	private static void AddVariableTime(ref ulong sum, ReadOnlySpan<SM9Point<SM9Fp>> multiples, int digit, ref ulong entry, ref ulong work)
	{
		if (digit is 0)
		{
			return;
		}

		SM9Point<SM9Fp> selected = multiples[Math.Abs(digit) >> 1];

		if (digit < 0)
		{
			SM9Fp.Negate(in selected.Y, out selected.Y);
		}

		SM9PointLanes<TVector, SM9Lanes<TVector>.FpLanes, SM9Fp>.SplitEntry(in selected, ref entry);
		SM9PointLanes<TVector, SM9Lanes<TVector>.FpLanes, SM9Fp>.AddSingle(ref sum, ref entry, ref sum, ref work);
	}

	// The tables of SM9G1Group.Multiply, 0·P to 16·P and their images under φ, each multiple from the one before by AddSingle with P.
	[SkipLocalsInit]
	private static void BuildTablesG1(in SM9AffinePoint<SM9Fp> point, Span<SM9Point<SM9Fp>> multiples, Span<SM9Point<SM9Fp>> images, ref ulong sum, ref ulong entry, ref ulong work)
	{
		SM9Curve<SM9Fp>.Infinity(out multiples[0]);
		SM9Curve<SM9Fp>.FromAffine(in point, out multiples[1]);
		SM9PointLanes<TVector, SM9Lanes<TVector>.FpLanes, SM9Fp>.SplitSingle(in multiples[1], ref sum);
		SM9PointLanes<TVector, SM9Lanes<TVector>.FpLanes, SM9Fp>.SplitEntry(in multiples[1], ref entry);

		for (int j = 2; j < multiples.Length; ++j)
		{
			SM9PointLanes<TVector, SM9Lanes<TVector>.FpLanes, SM9Fp>.AddSingle(ref sum, ref entry, ref sum, ref work);
			SM9PointLanes<TVector, SM9Lanes<TVector>.FpLanes, SM9Fp>.JoinSingle(ref sum, out multiples[j]);
		}

		for (int j = 0; j < multiples.Length; ++j)
		{
			SM9G1Group.Endomorphism(in multiples[j], out images[j]);
		}
	}

	// Adds the entry of digit, negated where the digit and the sign of the part differ, as SM9G1Group.AddDigit. Every entry is read.
	[SkipLocalsInit]
	private static void AddDigit(ref ulong sum, ReadOnlySpan<SM9Point<SM9Fp>> table, int digit, ulong partSign, ref ulong entry, ref ulong work)
	{
		int sign = digit >> 31;
		MaskedSelect.Lookup(in MemoryMarshal.GetReference(table), table.Length, (uint)((digit ^ sign) - sign), out SM9Point<SM9Fp> selected);
		SM9Curve<SM9Fp>.ConditionalNegate((ulong)sign ^ partSign, ref selected);
		SM9PointLanes<TVector, SM9Lanes<TVector>.FpLanes, SM9Fp>.SplitEntry(in selected, ref entry);
		SM9PointLanes<TVector, SM9Lanes<TVector>.FpLanes, SM9Fp>.AddSingle(ref sum, ref entry, ref sum, ref work);
		selected.ZeroMemory();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ref ulong Workspace(Span<byte> storage)
	{
		return ref Unsafe.As<byte, ulong>(ref storage[AlignedScratch.Offset(storage)]);
	}
}
