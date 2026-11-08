using static CryptoBase.EllipticCurves.LimbArithmetic;

namespace CryptoBase.EllipticCurves.SM9;

// The products of G1 and G2 with fixed bases, on one point in each lane of vector 0 of TLanes: the formulas of SM9Curve in every lane at once, with the products of each round in a row and their sums reduced once, so that the fixed-base products of SM9BaseTable take their windows TVector.Count at a time.
// A point in lanes is X, Y and Z, one element after the other, with components below 1.0001p in limbs 0 to 8 below 2^26, as Reduce leaves them; an entry, x and y of a point of a table, has x reduced, below 2.25p, and y reduced or negated as 3p − y, at most 3p in limbs below 2^27. The formulas keep these bounds, and the point at infinity is (0 : 1 : 0) in every lane, as in SM9Curve.
internal static class SM9PointLanes<TVector, TLanes, TField> where TVector : unmanaged, ISM9Vector<TVector> where TLanes : struct, ISM9FieldLanes<TField> where TField : unmanaged, ISM9Field<TField>
{
	private const int Alignment = 64;

	// The temporaries of the formulas.
	private const int SlotCount = 8;

	// The ulongs of the workspace of a product: the sum, the other point and the entry, the rows of the lane masks and of the signs, the slots, three sets of columns and the scratch of Multiply.
	internal static int WorkspaceLength => (3 + 3 + 3 + SlotCount) * TLanes.ElementLength + 2 * SM9Lanes<TVector>.RowLength + 3 * TLanes.ColumnsLength + TLanes.ScratchLength;

	// The ulongs of the formulas' part of the workspace, from the slots on.
	private static int FormulaOffset => 9 * TLanes.ElementLength + 2 * SM9Lanes<TVector>.RowLength;

	// k·G for the table of G, as SM9BaseTable.Multiply gives it: window w goes to lane w mod L in round ⌊w/L⌋, L = TVector.Count, and each lane sums its windows by the mixed addition, keeping its sum where the digit is 0, as there; Fold then adds up the lanes. The complete formulas take every sum, the point at infinity included. Neither the time nor the addresses depend on k or G, and the workspace is cleared.
	[SkipLocalsInit]
	internal static void MultiplyBase(SM9BaseTable<TField> table, in FieldElement<SM9Order> scalar, out SM9Point<TField> result)
	{
		Span<sbyte> digits = stackalloc sbyte[table.WindowCount];
		SM9Windows.Recode(FieldElement<SM9Order>.GetLimbs(in scalar), table.Width, digits);
		MultiplyBase(table, null, digits, out result);
		digits.ZeroMemory();
	}

	// a·G + b·H for the tables of G and H, as the sum of what MultiplyBase gives for each: the windows of H follow those of G, so that both share the rounds and one fold. Neither the time nor the addresses depend on a, b, G or H.
	[SkipLocalsInit]
	internal static void MultiplyBase(SM9BaseTable<TField> first, in FieldElement<SM9Order> firstScalar, SM9BaseTable<TField> second, in FieldElement<SM9Order> secondScalar, out SM9Point<TField> result)
	{
		int split = first.WindowCount;
		Span<sbyte> digits = stackalloc sbyte[split + second.WindowCount];
		SM9Windows.Recode(FieldElement<SM9Order>.GetLimbs(in firstScalar), first.Width, digits.Slice(0, split));
		SM9Windows.Recode(FieldElement<SM9Order>.GetLimbs(in secondScalar), second.Width, digits.Slice(split));
		MultiplyBase(first, second, digits, out result);
		digits.ZeroMemory();
	}

	// The windows of the digits, those of first and then those of second, if any. The tables are read before the rounds, and each lane negates its entry where its digit is negative.
	[SkipLocalsInit]
	private static void MultiplyBase(SM9BaseTable<TField> first, SM9BaseTable<TField>? second, ReadOnlySpan<sbyte> digits, out SM9Point<TField> result)
	{
		int windows = digits.Length;
		int split = first.WindowCount;
		int lanes = TVector.Count;
		SM9BaseTable<TField> last = second ?? first;
		ref SM9AffinePoint<TField> firstEntries = ref MemoryMarshal.GetReference(first.Entries);
		ref SM9AffinePoint<TField> lastEntries = ref MemoryMarshal.GetReference(last.Entries);
		int firstLength = first.WindowLength;
		int lastLength = last.WindowLength;
		Span<byte> storage = stackalloc byte[StorageLength()];
		ref ulong sum = ref Workspace(storage);
		ref ulong acc = ref Unsafe.Add(ref sum, 3 * TLanes.ElementLength);
		ref ulong entry = ref Unsafe.Add(ref acc, 3 * TLanes.ElementLength);
		ref ulong masks = ref Unsafe.Add(ref entry, 3 * TLanes.ElementLength);
		ref ulong signs = ref Unsafe.Add(ref masks, SM9Lanes<TVector>.RowLength);
		ref ulong formula = ref Unsafe.Add(ref sum, FormulaOffset);
		Infinity(ref acc);
		Unsafe.SkipInit(out SM9AffinePoint<TField> selected);

		for (int start = 0; start < windows; start += lanes)
		{
			for (int lane = 0; lane < lanes; ++lane)
			{
				int window = start + lane;
				ulong keep = ulong.MaxValue;
				ulong negative = 0;

				// Which lanes have a window, and of which table, depends on the round alone; the digits fill the tables' windows, so every window lies in its table.
				if (window < windows)
				{
					bool inFirst = window < split;
					int length = inFirst ? firstLength : lastLength;
					ref SM9AffinePoint<TField> windowEntries = ref inFirst ? ref Unsafe.Add(ref firstEntries, window * firstLength) : ref Unsafe.Add(ref lastEntries, (window - split) * lastLength);
					int digit = digits[window];
					int sign = digit >> 31;
					MaskedSelect.Lookup(in windowEntries, length, (uint)((digit ^ sign) - sign) - 1, out selected);
					keep = ZeroMask((ulong)digit);
					negative = (ulong)sign;
				}
				else
				{
					selected = default;
				}

				TLanes.Split(in selected.X, ref entry, lane);
				TLanes.Split(in selected.Y, ref Unsafe.Add(ref entry, TLanes.ElementLength), lane);
				Unsafe.Add(ref masks, lane) = keep;
				Unsafe.Add(ref signs, lane) = negative;
			}

			TLanes.ConditionalNegate(ref signs, ref Unsafe.Add(ref entry, TLanes.ElementLength));
			MixedAdd(ref acc, ref entry, ref sum, ref formula);
			SelectPoint(ref masks, ref acc, ref sum, ref acc);
		}

		Fold(ref acc, ref entry, ref sum, ref formula, out result);
		storage.ZeroMemory();
		selected.ZeroMemory();
	}

	// k·G + addend for a public k and addend, as SM9BaseTable.MultiplyAddVariableTime gives it: as MultiplyBase, with lane 0 starting from the addend and the entries read by index.
	[SkipLocalsInit]
	internal static void MultiplyBaseAddVariableTime(SM9BaseTable<TField> table, in FieldElement<SM9Order> scalar, in SM9Point<TField> addend, out SM9Point<TField> result)
	{
		int windows = table.WindowCount;
		int windowLength = table.WindowLength;
		int lanes = TVector.Count;
		Span<sbyte> digits = stackalloc sbyte[windows];
		SM9Windows.Recode(FieldElement<SM9Order>.GetLimbs(in scalar), table.Width, digits);
		Span<byte> storage = stackalloc byte[StorageLength()];
		ref ulong sum = ref Workspace(storage);
		ref ulong acc = ref Unsafe.Add(ref sum, 3 * TLanes.ElementLength);
		ref ulong entry = ref Unsafe.Add(ref acc, 3 * TLanes.ElementLength);
		ref ulong masks = ref Unsafe.Add(ref entry, 3 * TLanes.ElementLength);
		ref ulong formula = ref Unsafe.Add(ref sum, FormulaOffset);
		Infinity(ref acc);
		// The addend is reduced, below 2.25p; the formulas take its coordinates below 1.0001p.
		SplitPoint(in addend, ref acc, 0);
		WeakReducePoint(ref acc);
		ReadOnlySpan<SM9AffinePoint<TField>> entries = table.Entries;

		for (int start = 0; start < windows; start += lanes)
		{
			for (int lane = 0; lane < lanes; ++lane)
			{
				int window = start + lane;
				int digit = window < windows ? digits[window] : 0;
				SM9AffinePoint<TField> selected = default;

				if (digit is not 0)
				{
					selected = entries[window * windowLength + Math.Abs(digit) - 1];

					if (digit < 0)
					{
						SM9Curve<TField>.Negate(in selected, out selected);
					}
				}

				TLanes.Split(in selected.X, ref entry, lane);
				TLanes.Split(in selected.Y, ref Unsafe.Add(ref entry, TLanes.ElementLength), lane);
				Unsafe.Add(ref masks, lane) = digit is 0 ? ulong.MaxValue : 0;
			}

			MixedAdd(ref acc, ref entry, ref sum, ref formula);
			SelectPoint(ref masks, ref acc, ref sum, ref acc);
		}

		Fold(ref acc, ref entry, ref sum, ref formula, out result);
	}

	// The entries of SM9BaseTable for G and the width, window after window: the bases B_w = 2^(width·w)·G of the windows by DoubleSingle, their multiples by BuildMultiples and their affine forms by ToAffine. G may be secret, as the entries then are: the inversion takes constant time, and the projective points are erased.
	internal static void BuildTable(in SM9AffinePoint<TField> generator, int width, bool secret, Span<SM9AffinePoint<TField>> entries)
	{
		int windowLength = 1 << width - 1;
		SM9Point<TField>[] bases = new SM9Point<TField>[entries.Length / windowLength];
		SM9Point<TField>[] multiples = new SM9Point<TField>[entries.Length];
		ulong[] single = new ulong[TLanes.ElementLength + SingleWorkLength];
		ref ulong point = ref single[0];
		ref ulong work = ref single[TLanes.ElementLength];
		SM9Curve<TField>.FromAffine(in generator, out bases[0]);
		SplitSingle(in bases[0], ref point);

		for (int w = 1; w < bases.Length; ++w)
		{
			for (int k = 0; k < width; ++k)
			{
				DoubleSingle(ref point, ref point, ref work);
			}

			JoinSingle(ref point, out bases[w]);
		}

		BuildMultiples(bases, windowLength, multiples);
		ToAffine(multiples, entries, !secret);
		single.AsSpan().Clear();

		if (secret)
		{
			bases.AsSpan().ZeroMemory();
			multiples.AsSpan().ZeroMemory();
		}
	}

	// SM9Curve.ToAffine on the lanes, a row of eight points at a time: lane l takes points l, l + 8, …, the products of their Z go down the rows, and Montgomery's trick in TField over the eight totals inverts them all with one inversion, in constant time unless variableTime is set, for public points. None of the points may be the point at infinity; the lanes past the last point take 1. The workspace is cleared.
	[SkipLocalsInit]
	internal static void ToAffine(ReadOnlySpan<SM9Point<TField>> points, Span<SM9AffinePoint<TField>> result, bool variableTime)
	{
		Debug.Assert(points.Length > 0 && result.Length == points.Length);

		const int lanes = SM9Lanes<TVector>.RowLength;
		int rows = (points.Length + lanes - 1) / lanes;
		int vectors = lanes / TVector.Count;
		int e = TLanes.ElementLength;
		// The products of Z down the rows, then the inverse of the products so far, the inverse of the Z of a row, a row of X, Y or Z, and a product.
		ulong[] work = new ulong[(rows + 4) * e + TLanes.ColumnsLength + TLanes.ScratchLength];
		ref ulong prefix = ref work[0];
		ref ulong inverse = ref work[rows * e];
		ref ulong zInverse = ref Unsafe.Add(ref inverse, e);
		ref ulong row = ref Unsafe.Add(ref inverse, 2 * e);
		ref ulong product = ref Unsafe.Add(ref inverse, 3 * e);
		ref ulong columns = ref Unsafe.Add(ref inverse, 4 * e);
		ref ulong scratch = ref Unsafe.Add(ref columns, TLanes.ColumnsLength);
		SplitRow(points, 0, 2, ref prefix);

		for (int m = 1; m < rows; ++m)
		{
			SplitRow(points, m, 2, ref row);
			TLanes.MultiplyReduce(ref Unsafe.Add(ref prefix, (m - 1) * e), ref row, ref Unsafe.Add(ref prefix, m * e), ref columns, ref scratch, vectors);
		}

		Span<TField> totals = stackalloc TField[lanes];
		Span<TField> inverses = stackalloc TField[lanes];
		ref ulong last = ref Unsafe.Add(ref prefix, (rows - 1) * e);

		for (int l = 0; l < lanes; ++l)
		{
			TLanes.Join(ref last, l, out totals[l]);
		}

		inverses[0] = totals[0];

		for (int l = 1; l < lanes; ++l)
		{
			TField.Multiply(in inverses[l - 1], in totals[l], out inverses[l]);
		}

		Unsafe.SkipInit(out TField t);

		if (variableTime)
		{
			TField.InvertVariableTime(in inverses[lanes - 1], out t);
		}
		else
		{
			TField.Invert(in inverses[lanes - 1], out t);
		}

		for (int l = lanes - 1; l > 0; --l)
		{
			TField.Multiply(in t, in inverses[l - 1], out inverses[l]);
			TField.Multiply(in t, in totals[l], out t);
		}

		inverses[0] = t;

		for (int l = 0; l < lanes; ++l)
		{
			TLanes.Split(in inverses[l], ref inverse, l);
		}

		for (int m = rows - 1; m >= 0; --m)
		{
			ref ulong factor = ref inverse;

			if (m > 0)
			{
				TLanes.MultiplyReduce(ref inverse, ref Unsafe.Add(ref prefix, (m - 1) * e), ref zInverse, ref columns, ref scratch, vectors);
				SplitRow(points, m, 2, ref row);
				TLanes.MultiplyReduce(ref inverse, ref row, ref inverse, ref columns, ref scratch, vectors);
				factor = ref zInverse;
			}

			SplitRow(points, m, 0, ref row);
			TLanes.MultiplyReduce(ref row, ref factor, ref product, ref columns, ref scratch, vectors);
			JoinRow(ref product, m, 0, result);
			SplitRow(points, m, 1, ref row);
			TLanes.MultiplyReduce(ref row, ref factor, ref product, ref columns, ref scratch, vectors);
			JoinRow(ref product, m, 1, result);
		}

		work.AsSpan().Clear();
		totals.ZeroMemory();
		inverses.ZeroMemory();
		t.ZeroMemory();
	}

	// Lane l of rows takes coordinate c, 0 for X, 1 for Y and 2 for Z, of point 8m + l, and the lanes past the last point take 1.
	private static void SplitRow(ReadOnlySpan<SM9Point<TField>> points, int m, int c, ref ulong rows)
	{
		for (int l = 0; l < SM9Lanes<TVector>.RowLength; ++l)
		{
			TLanes.Split(in Coordinate(points, SM9Lanes<TVector>.RowLength * m + l, c), ref rows, l);
		}
	}

	private static ref readonly TField Coordinate(ReadOnlySpan<SM9Point<TField>> points, int i, int c)
	{
		if (i >= points.Length)
		{
			return ref TField.One;
		}

		ref readonly SM9Point<TField> point = ref points[i];

		if (c is 0)
		{
			return ref point.X;
		}

		return ref c is 1 ? ref point.Y : ref point.Z;
	}

	// Coordinate c, 0 for x and 1 for y, of point 8m + l of result from lane l of rows, for the points that there are.
	private static void JoinRow(ref ulong rows, int m, int c, Span<SM9AffinePoint<TField>> result)
	{
		for (int l = 0; l < SM9Lanes<TVector>.RowLength && SM9Lanes<TVector>.RowLength * m + l < result.Length; ++l)
		{
			ref SM9AffinePoint<TField> point = ref result[SM9Lanes<TVector>.RowLength * m + l];

			if (c is 0)
			{
				TLanes.Join(ref rows, l, out point.X);
			}
			else
			{
				TLanes.Join(ref rows, l, out point.Y);
			}
		}
	}

	// The multiples of the windows of SM9BaseTable from their bases B_w = 2^(width·w)·G, window w in lane w mod L in round ⌊w/L⌋: each lane adds its base to its last multiple, B, 2B, … up to windowLength·B, by Add, whose complete formulas double where the two are equal. Lanes past the last window take the first base of the round. The bases may be secret, and the workspace is cleared.
	[SkipLocalsInit]
	internal static void BuildMultiples(ReadOnlySpan<SM9Point<TField>> bases, int windowLength, Span<SM9Point<TField>> multiples)
	{
		int windows = bases.Length;
		int lanes = TVector.Count;
		Span<byte> storage = stackalloc byte[StorageLength()];
		ref ulong sum = ref Workspace(storage);
		ref ulong acc = ref Unsafe.Add(ref sum, 3 * TLanes.ElementLength);
		ref ulong windowBase = ref Unsafe.Add(ref acc, 3 * TLanes.ElementLength);
		ref ulong formula = ref Unsafe.Add(ref sum, FormulaOffset);

		for (int start = 0; start < windows; start += lanes)
		{
			int count = Math.Min(lanes, windows - start);

			for (int lane = 0; lane < lanes; ++lane)
			{
				int window = start + (lane < count ? lane : 0);
				multiples[window * windowLength] = bases[window];
				SplitPoint(in bases[window], ref windowBase, lane);
			}

			// The bases are reduced, below 2.25p; the formulas take coordinates below 1.0001p.
			WeakReducePoint(ref windowBase);
			Unsafe.CopyBlockUnaligned(ref Unsafe.As<ulong, byte>(ref acc), ref Unsafe.As<ulong, byte>(ref windowBase), (uint)(3 * TLanes.ElementLength * sizeof(ulong)));

			for (int j = 1; j < windowLength; ++j)
			{
				Add(ref acc, ref windowBase, ref sum, ref formula);
				Unsafe.CopyBlockUnaligned(ref Unsafe.As<ulong, byte>(ref acc), ref Unsafe.As<ulong, byte>(ref sum), (uint)(3 * TLanes.ElementLength * sizeof(ulong)));

				for (int lane = 0; lane < count; ++lane)
				{
					JoinPoint(ref sum, lane, out multiples[(start + lane) * windowLength + j]);
				}
			}
		}

		storage.ZeroMemory();
	}

	// The sum of the lanes. Vectors of a whole row add lanes 1 to 7 to lane 0 by AddSingle on one point, in place of the three additions of eight lanes of a fold; narrower ones fold in halves, lane i adding lane i + d for d = L/2 down to 1, so that lane 0 ends with the sum of every lane. other and sum are points of scratch.
	private static void Fold(ref ulong acc, ref ulong other, ref ulong sum, ref ulong formula, out SM9Point<TField> result)
	{
		if (TVector.Count == SM9Lanes<TVector>.RowLength)
		{
			ref ulong single = ref sum;
			ref ulong entry = ref Unsafe.Add(ref sum, TLanes.ElementLength);
			JoinPoint(ref acc, 0, out result);
			SplitSingle(in result, ref single);

			for (int lane = 1; lane < TVector.Count; ++lane)
			{
				JoinPoint(ref acc, lane, out result);
				SplitEntry(in result, ref entry);
				AddSingle(ref single, ref entry, ref single, ref formula);
			}

			JoinSingle(ref single, out result);
			return;
		}

		for (int distance = TVector.Count / 2; distance > 0; distance /= 2)
		{
			for (int c = 0; c < 3; ++c)
			{
				TLanes.MoveDown(ref Unsafe.Add(ref acc, c * TLanes.ElementLength), distance, ref Unsafe.Add(ref other, c * TLanes.ElementLength));
			}

			Add(ref acc, ref other, ref sum, ref formula);
			Unsafe.CopyBlockUnaligned(ref Unsafe.As<ulong, byte>(ref acc), ref Unsafe.As<ulong, byte>(ref sum), (uint)(3 * TLanes.ElementLength * sizeof(ulong)));
		}

		JoinPoint(ref acc, 0, out result);
	}

	// left + (x, y) by SM9Curve.Add with an affine right, Algorithm 8, in every lane. Round 1 takes X1·X2, Y1·Y2, (X1 + Y1)(X2 + Y2), Y2·Z1 + Y1 and X2·Z1 + X1, the last two with the addends folded into their reductions, and t3 = (X1 + Y1)(X2 + Y2) − X1·X2 − Y1·Y2 from the reduced three; round 2 is that of Add. The inputs bound every product of round 1 below 10.51p² in Fp, and the components of a product of Fp2 within (−21.01p², 10.51p²) and [0, 21.01p²).
	// The result must be neither input.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	internal static void MixedAdd(ref ulong left, ref ulong right, ref ulong result, ref ulong formula)
	{
		int e = TLanes.ElementLength;
		ref ulong x1 = ref left;
		ref ulong y1 = ref Unsafe.Add(ref left, e);
		ref ulong z1 = ref Unsafe.Add(ref left, 2 * e);
		ref ulong x2 = ref right;
		ref ulong y2 = ref Unsafe.Add(ref right, e);
		ref ulong a = ref formula;
		ref ulong b = ref Unsafe.Add(ref formula, e);
		ref ulong t0 = ref Unsafe.Add(ref formula, 2 * e);
		ref ulong t1 = ref Unsafe.Add(ref formula, 3 * e);
		ref ulong t3 = ref Unsafe.Add(ref formula, 5 * e);
		ref ulong t4 = ref Unsafe.Add(ref formula, 6 * e);
		ref ulong y3 = ref Unsafe.Add(ref formula, 7 * e);
		ref ulong columns = ref Unsafe.Add(ref formula, SlotCount * e);
		ref ulong other = ref Unsafe.Add(ref columns, TLanes.ColumnsLength);
		ref ulong scratch = ref Unsafe.Add(ref columns, 3 * TLanes.ColumnsLength);
		TLanes.Multiply(ref x1, ref x2, ref columns, ref scratch, 1);
		TLanes.Multiply(ref y1, ref y2, ref other, ref scratch, 1);
		TLanes.Reduce2(ref columns, ref other, ref t0, ref t1);
		TLanes.Add(ref x1, ref y1, ref a);
		TLanes.Add(ref x2, ref y2, ref b);
		TLanes.Multiply(ref a, ref b, ref columns, ref scratch, 1);
		TLanes.Multiply(ref y2, ref z1, ref other, ref scratch, 1);
		TLanes.AddShifted(ref other, ref y1);
		TLanes.Reduce2(ref columns, ref other, ref t3, ref t4);
		TLanes.Multiply(ref x2, ref z1, ref columns, ref scratch, 1);
		TLanes.AddShifted(ref columns, ref x1);
		TLanes.Reduce(ref columns, ref y3, 1);
		TLanes.SubtractTwo(ref t3, ref t0, ref t1, ref t3);
		// t2 = 3b·Z1 in a and 3b·y3 in b.
		TLanes.MultiplyByThreeB(ref z1, ref a, 1);
		TLanes.MultiplyByThreeB(ref y3, ref b, 1);
		SecondRound(ref formula, ref result);
	}

	// left + right by SM9Curve.Add, Algorithm 7, in every lane. Round 1 takes the six products of the inputs and their sums, of reduced inputs, so each product of Fp lies below 4.0008p² and each component of one of Fp2 within (−8.0016p², 4.0008p²) or [0, 8.0016p²); t3, t4 and y3 come from the reduced products. Round 2 then takes the six products of SecondRound from t0 = 3·X1·X2, t1 = Y1·Y2 − 3b·Z1·Z2 and z3 = Y1·Y2 + 3b·Z1·Z2.
	// The result must be neither input.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	internal static void Add(ref ulong left, ref ulong right, ref ulong result, ref ulong formula)
	{
		int e = TLanes.ElementLength;
		ref ulong x1 = ref left;
		ref ulong y1 = ref Unsafe.Add(ref left, e);
		ref ulong z1 = ref Unsafe.Add(ref left, 2 * e);
		ref ulong x2 = ref right;
		ref ulong y2 = ref Unsafe.Add(ref right, e);
		ref ulong z2 = ref Unsafe.Add(ref right, 2 * e);
		ref ulong a = ref formula;
		ref ulong b = ref Unsafe.Add(ref formula, e);
		ref ulong t0 = ref Unsafe.Add(ref formula, 2 * e);
		ref ulong t1 = ref Unsafe.Add(ref formula, 3 * e);
		ref ulong t2 = ref Unsafe.Add(ref formula, 4 * e);
		ref ulong t3 = ref Unsafe.Add(ref formula, 5 * e);
		ref ulong t4 = ref Unsafe.Add(ref formula, 6 * e);
		ref ulong y3 = ref Unsafe.Add(ref formula, 7 * e);
		ref ulong columns = ref Unsafe.Add(ref formula, SlotCount * e);
		ref ulong other = ref Unsafe.Add(ref columns, TLanes.ColumnsLength);
		ref ulong scratch = ref Unsafe.Add(ref columns, 3 * TLanes.ColumnsLength);
		TLanes.Multiply(ref x1, ref x2, ref columns, ref scratch, 1);
		TLanes.Multiply(ref y1, ref y2, ref other, ref scratch, 1);
		TLanes.Reduce2(ref columns, ref other, ref t0, ref t1);
		TLanes.Add(ref x1, ref y1, ref a);
		TLanes.Add(ref x2, ref y2, ref b);
		TLanes.Multiply(ref a, ref b, ref columns, ref scratch, 1);
		TLanes.Multiply(ref z1, ref z2, ref other, ref scratch, 1);
		TLanes.Reduce2(ref columns, ref other, ref t3, ref t2);
		TLanes.Add(ref y1, ref z1, ref a);
		TLanes.Add(ref y2, ref z2, ref b);
		TLanes.Multiply(ref a, ref b, ref columns, ref scratch, 1);
		TLanes.Add(ref x1, ref z1, ref a);
		TLanes.Add(ref x2, ref z2, ref b);
		TLanes.Multiply(ref a, ref b, ref other, ref scratch, 1);
		TLanes.Reduce2(ref columns, ref other, ref t4, ref y3);
		TLanes.SubtractTwo(ref t3, ref t0, ref t1, ref t3);
		TLanes.SubtractTwo(ref t4, ref t1, ref t2, ref t4);
		TLanes.SubtractTwo(ref y3, ref t0, ref t2, ref y3);
		TLanes.MultiplyByThreeB(ref t2, ref a, 1);
		TLanes.MultiplyByThreeB(ref y3, ref b, 1);
		SecondRound(ref formula, ref result);
	}

	// Round 2 of Algorithms 7 and 8, from t0, t1, t3, t4, 3b·Z (t2) in slot a and 3b·y3 in slot b, all reduced: t0 = 3·t0, z3 = t1 + t2 and t1 = t1 + 3p − t2, below 3.0003p, 2.0002p and 4.0001p in limbs below 2^27.6; then X3 = t3·t1 − t4·y3, Y3 = t1·z3 + y3·t0 and Z3 = z3·t4 + t0·t3, each sum of two products reduced once. In Fp, X3 lies in (−1.0002p², 4.0005p²), Y3 in [0, 11.002p²) and Z3 in [0, 5.001p²), X3 with the 64p² of SubtractColumns; in Fp2 the components of X3 lie within (−9.002p², 8.002p²), with 64p² from SubtractColumns, and those of Y3 and Z3 within (−22.004p², 22.004p²), the real parts with the 128p² of each product, so every reduction takes a value in [0, 268p²).
	private static void SecondRound(ref ulong formula, ref ulong result)
	{
		int e = TLanes.ElementLength;
		ref ulong t2 = ref formula;
		ref ulong y3 = ref Unsafe.Add(ref formula, e);
		ref ulong t0 = ref Unsafe.Add(ref formula, 2 * e);
		ref ulong t1 = ref Unsafe.Add(ref formula, 3 * e);
		ref ulong z3 = ref Unsafe.Add(ref formula, 4 * e);
		ref ulong t3 = ref Unsafe.Add(ref formula, 5 * e);
		ref ulong t4 = ref Unsafe.Add(ref formula, 6 * e);
		ref ulong columns = ref Unsafe.Add(ref formula, SlotCount * e);
		ref ulong other = ref Unsafe.Add(ref columns, TLanes.ColumnsLength);
		ref ulong third = ref Unsafe.Add(ref columns, 2 * TLanes.ColumnsLength);
		ref ulong scratch = ref Unsafe.Add(ref columns, 3 * TLanes.ColumnsLength);
		TLanes.Triple(ref t0, ref t0);
		TLanes.Add(ref t1, ref t2, ref z3);
		TLanes.SubtractFromCover(ref t1, ref t2, ref t1);
		TLanes.Multiply(ref t3, ref t1, ref columns, ref scratch, 1);
		TLanes.Multiply(ref t4, ref y3, ref other, ref scratch, 1);
		TLanes.SubtractColumns(ref columns, ref other);
		TLanes.Multiply(ref t1, ref z3, ref other, ref scratch, 1);
		TLanes.Multiply(ref y3, ref t0, ref third, ref scratch, 1);
		TLanes.AddColumns(ref other, ref third);
		TLanes.Reduce2(ref columns, ref other, ref result, ref Unsafe.Add(ref result, e));
		TLanes.Multiply(ref z3, ref t4, ref columns, ref scratch, 1);
		TLanes.Multiply(ref t0, ref t3, ref other, ref scratch, 1);
		TLanes.AddColumns(ref columns, ref other);
		TLanes.Reduce(ref columns, ref Unsafe.Add(ref result, 2 * e), 1);
	}

	// The ulongs of the workspace of the formulas on one point: three elements, the columns, the scratch of Multiply and the rows of the shuffles.
	internal static int SingleWorkLength => 3 * TLanes.ElementLength + TLanes.ColumnsLength + TLanes.ScratchLength + SM9Lanes<TVector>.PermutedRows * SM9Lanes<TVector>.RowLength;

	// The vectors of a row that hold lanes 0 to lanes − 1.
	private static int Vectors(int lanes)
	{
		return (lanes + TVector.Count - 1) / TVector.Count;
	}

	// 2·P by SM9Curve.Double, Algorithm 9, on one point, X, Y and Z in lanes 0 to 2 of an element, round 1 takes (Y², YZ, t2, XY) in one row, t2 = 3b·Z², and round 2 (t2·8Y², YZ·8Y², t0·(Y² + t2), t0·XY) for t0 = Y² − 3t2, which give X3 = 2·t0·XY, Y3 = t2·8Y² + t0·(Y² + t2) and Z3 = YZ·8Y². For P below 2.25p in limbs below 2^27, as SplitSingle and DoubleSingle leave it, the products of round 1 are below 75.94p² in Fp, with the factor 15 in lane 2 and its limbs below 2^30.9, and within (−10.13p², 5.07p²) or [0, 10.13p²) in Fp2; those of round 2, of t0 below 10.0001p in limbs below 2^28.3 by Y² + t2 below 2.0002p and of reduced terms by 8Y² below 8.0008p in limbs below 2^29, below 20.01p² and within (−40.01p², 20.01p²) or [0, 40.01p²). The columns stay below 2^61.2 in magnitude. The result is below 2.0002p in limbs below 2^27, and the other lanes hold values of no meaning, bounded as these. The result may be the point.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	internal static void DoubleSingle(ref ulong point, ref ulong result, ref ulong work)
	{
		int e = TLanes.ElementLength;
		int rows = e / SM9Lanes<TVector>.RowLength;
		int vectors = Vectors(4);
		ref ulong left = ref work;
		ref ulong right = ref Unsafe.Add(ref work, e);
		ref ulong q = ref Unsafe.Add(ref work, 2 * e);
		ref ulong columns = ref Unsafe.Add(ref work, 3 * e);
		ref ulong scratch = ref Unsafe.Add(ref columns, TLanes.ColumnsLength);
		ref ulong permuted = ref Unsafe.Add(ref scratch, TLanes.ScratchLength);
		TLanes.DoublingOperands(ref point, ref left, ref right, vectors);
		TLanes.MultiplyReduce(ref left, ref right, ref q, ref columns, ref scratch, vectors);
		TLanes.ThreeBLaneTwo(ref q, ref left, vectors);
		SM9Lanes<TVector>.DoublingMiddle(ref q, ref left, ref right, rows, ref permuted, vectors);
		TLanes.MultiplyReduce(ref left, ref right, ref q, ref columns, ref scratch, vectors);
		SM9Lanes<TVector>.DoublingResult(ref q, ref result, rows, ref permuted, vectors);
	}

	// left + right by SM9Curve.Add, Algorithm 7, on one point each: right holds (X2, Y2, 3b·Z2, X2 + Y2, Z2, Y2, 3b·Z2, 3b·X2) in lanes 0 to 7, from reduced coordinates, so round 1 takes the eight products (X1X2, Y1Y2, 3b·Z1Z2, (X1 + Y1)(X2 + Y2), Y1Z2, Z1Y2, 3b·X1Z2, 3b·Z1X2) in one row, which give t3, t4 = Y1Z2 + Z1Y2 and 3b·y3 = 3b·(X1Z2 + Z1X2) with no factor 3b in lanes, and round 2 the six of Add. For a left point below 2.25p in limbs below 2^27, as SplitSingle and DoubleSingle leave it, the products of round 1, with X1 + Y1 below 4.5p in limbs below 2^28, are below 10.13p² in Fp and within (−20.25p², 10.13p²) or [0, 20.25p²) in Fp2, and those of round 2, of operands below 10.0001p and 4.0001p in limbs below 2^28.3 and 2^27.6, below 40.01p² and within (−80.02p², 40.01p²) or [0, 80.02p²), the columns below 2^61.2 in magnitude. The result is weakly reduced, below 1.0001p. The result may be left.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	internal static void AddSingle(ref ulong left, ref ulong right, ref ulong result, ref ulong work)
	{
		int e = TLanes.ElementLength;
		int rows = e / SM9Lanes<TVector>.RowLength;
		int all = Vectors(8);
		int vectors = Vectors(6);
		ref ulong first = ref work;
		ref ulong second = ref Unsafe.Add(ref work, e);
		ref ulong q = ref Unsafe.Add(ref work, 2 * e);
		ref ulong columns = ref Unsafe.Add(ref work, 3 * e);
		ref ulong scratch = ref Unsafe.Add(ref columns, TLanes.ColumnsLength);
		ref ulong permuted = ref Unsafe.Add(ref scratch, TLanes.ScratchLength);
		SM9Lanes<TVector>.AdditionOperands(ref left, ref first, rows, ref permuted, all);
		TLanes.MultiplyReduce(ref first, ref right, ref q, ref columns, ref scratch, all);
		SM9Lanes<TVector>.AdditionSecondOperands(ref q, ref first, ref second, rows, ref permuted, vectors);
		TLanes.MultiplyReduce(ref first, ref second, ref q, ref columns, ref scratch, vectors);
		SM9Lanes<TVector>.AdditionResult(ref q, ref result, rows, ref permuted, vectors);
		TLanes.WeakReduce(ref result, Vectors(3));
	}

	// The point at infinity, (0 : 1 : 0), in lanes 0 to 2 of an element, the other lanes 0.
	internal static void InfinitySingle(ref ulong point)
	{
		TLanes.Clear(ref point);
		TLanes.Split(in TField.One, ref point, 1);
	}

	// A point in lanes 0 to 2, whose coordinates must be reduced.
	internal static void SplitSingle(in SM9Point<TField> point, ref ulong rows)
	{
		TLanes.Split(in point.X, ref rows, 0);
		TLanes.Split(in point.Y, ref rows, 1);
		TLanes.Split(in point.Z, ref rows, 2);
	}

	// The right operand of AddSingle, (X, Y, 3b·Z, X + Y, Z, Y, 3b·Z, 3b·X), from a point with reduced coordinates, the sums and products reduced as TField gives them.
	[SkipLocalsInit]
	internal static void SplitEntry(in SM9Point<TField> point, ref ulong rows)
	{
		TLanes.Split(in point.X, ref rows, 0);
		TLanes.Split(in point.Y, ref rows, 1);
		TLanes.Split(in point.Z, ref rows, 4);
		TLanes.Split(in point.Y, ref rows, 5);
		TField.MultiplyByThreeB(in point.Z, out TField value);
		TLanes.Split(in value, ref rows, 2);
		TLanes.Split(in value, ref rows, 6);
		TField.Add(in point.X, in point.Y, out value);
		TLanes.Split(in value, ref rows, 3);
		TField.MultiplyByThreeB(in point.X, out value);
		TLanes.Split(in value, ref rows, 7);
		value.ZeroMemory();
	}

	// The point in lanes 0 to 2, reduced as TField has it: below 2.25p in limbs below 2^27 from the formulas, so WeakReduce takes it first, in place.
	internal static void JoinSingle(ref ulong rows, out SM9Point<TField> result)
	{
		TLanes.WeakReduce(ref rows, Vectors(3));
		Unsafe.SkipInit(out result);
		TLanes.Join(ref rows, 0, out result.X);
		TLanes.Join(ref rows, 1, out result.Y);
		TLanes.Join(ref rows, 2, out result.Z);
	}

	// The point at infinity in every lane.
	private static void Infinity(ref ulong point)
	{
		int e = TLanes.ElementLength;
		TLanes.Clear(ref point);
		TLanes.One(ref Unsafe.Add(ref point, e));
		TLanes.Clear(ref Unsafe.Add(ref point, 2 * e));
	}

	private static void SelectPoint(ref ulong masks, ref ulong whenSet, ref ulong whenClear, ref ulong result)
	{
		int e = TLanes.ElementLength;

		for (int c = 0; c < 3; ++c)
		{
			TLanes.ConditionalSelect(ref masks, ref Unsafe.Add(ref whenSet, c * e), ref Unsafe.Add(ref whenClear, c * e), ref Unsafe.Add(ref result, c * e), 1);
		}
	}

	internal static void WeakReducePoint(ref ulong point)
	{
		int e = TLanes.ElementLength;

		for (int c = 0; c < 3; ++c)
		{
			TLanes.WeakReduce(ref Unsafe.Add(ref point, c * e), 1);
		}
	}

	internal static void SplitPoint(in SM9Point<TField> point, ref ulong rows, int lane)
	{
		int e = TLanes.ElementLength;
		TLanes.Split(in point.X, ref rows, lane);
		TLanes.Split(in point.Y, ref Unsafe.Add(ref rows, e), lane);
		TLanes.Split(in point.Z, ref Unsafe.Add(ref rows, 2 * e), lane);
	}

	// Lane lane, whose components Reduce leaves below 1.0001p, reduced as TField has them.
	internal static void JoinPoint(ref ulong rows, int lane, out SM9Point<TField> result)
	{
		int e = TLanes.ElementLength;
		Unsafe.SkipInit(out result);
		TLanes.Join(ref rows, lane, out result.X);
		TLanes.Join(ref Unsafe.Add(ref rows, e), lane, out result.Y);
		TLanes.Join(ref Unsafe.Add(ref rows, 2 * e), lane, out result.Z);
	}

	// The bytes for the workspace with room to start it on a 64-byte line.
	private static int StorageLength()
	{
		return WorkspaceLength * sizeof(ulong) + Alignment - 1;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static unsafe ref ulong Workspace(Span<byte> storage)
	{
		nint address = (nint)Unsafe.AsPointer(ref MemoryMarshal.GetReference(storage));
		int offset = (int)(-address & Alignment - 1);
		return ref Unsafe.As<byte, ulong>(ref storage[offset]);
	}
}
