namespace CryptoBase.EllipticCurves.SM9;

// The pairing and the powers of GT on SM9Lanes, by the algorithms of SM9MillerLoop, SM9FinalExponentiation and SM9GTPower, with the same steps on the same values. The elements of Fp12 stay in lanes from the first operation to the last; only the steps of T that the Miller loop takes out of the lanes, the inversion of Fp6 of the final exponentiation and the entries of a fixed table come from SM9Fp2, SM9Fp6 and SM9Fp12. Each operation works in an aligned workspace on the stack, erased at its end, and neither its time nor its addresses depend on its inputs.
internal static class SM9LaneKernel<TVector> where TVector : unmanaged, ISM9Vector<TVector>
{
	private const int Alignment = 64;

	private const int TableLength = SM9FrobeniusRecoding.TableLength;

	// T doubles in lanes by SM9Lanes.DoublingStep, which gives the line at P as it goes; the additions, one for each nonzero digit and the two of the end, take SM9MillerLoop's step on T taken out of the lanes. Vectors narrower than a row, which DoublingStep does not take, take MillerLoopScalarSteps.
	[SkipLocalsInit]
	internal static void MillerLoop(in SM9AffinePoint<SM9Fp> p, in SM9AffinePoint<SM9Fp2> q, out SM9Fp12 result)
	{
		if (TVector.Count < SM9Lanes<TVector>.RowLength)
		{
			MillerLoopScalarSteps(in p, in q, out result);
			return;
		}

		Span<byte> storage = stackalloc byte[StorageLength(4)];
		ref SM9Fp12Lanes f = ref Workspace(storage);
		ref SM9Fp12Lanes line = ref Unsafe.Add(ref f, 1);
		ref SM9Fp12Lanes point = ref Unsafe.Add(ref f, 2);
		ref SM9Fp12Lanes factors = ref Unsafe.Add(ref f, 3);
		ref SM9LaneScratch scratch = ref Scratch(ref f, 4);
		SM9Fp.Negate(in p.X, out SM9Fp negatedX);
		SM9Fp y = p.Y;
		SM9AffinePoint<SM9Fp2> negatedQ;
		negatedQ.X = q.X;
		SM9Fp2.Negate(in q.Y, out negatedQ.Y);
		SM9Point<SM9Fp2> t;
		t.X = q.X;
		t.Y = q.Y;
		t.Z = SM9Fp2.One;
		SM9Lanes<TVector>.FromPoint(in t, ref point);
		SM9Lanes<TVector>.FromFactors(in negatedX, in y, ref factors);
		ReadOnlySpan<sbyte> digits = SM9MillerLoop.Digits;
		Debug.Assert(digits[^2] is 0);

		// f starts at 1, so the first step, whose digit is 0, leaves f = l, which must be reduced.
		SM9Lanes<TVector>.DoublingStep(ref point, ref factors, ref f, ref scratch);
		SM9Lanes<TVector>.WeakReduce(ref f);

		for (int i = digits.Length - 3; i >= 0; --i)
		{
			SM9Lanes<TVector>.Square(ref f, ref f, ref scratch);
			SM9Lanes<TVector>.DoublingStep(ref point, ref factors, ref line, ref scratch);
			SM9Lanes<TVector>.MultiplyByLine(ref f, ref line, ref f, ref scratch);

			if (digits[i] > 0)
			{
				AdditionStep(ref point, in q, in negatedX, in y, ref line);
				SM9Lanes<TVector>.MultiplyByLine(ref f, ref line, ref f, ref scratch);
			}
			else if (digits[i] < 0)
			{
				AdditionStep(ref point, in negatedQ, in negatedX, in y, ref line);
				SM9Lanes<TVector>.MultiplyByLine(ref f, ref line, ref f, ref scratch);
			}
		}

		SM9G2Group.Frobenius(in q, out SM9AffinePoint<SM9Fp2> q1);
		AdditionStep(ref point, in q1, in negatedX, in y, ref line);
		SM9Lanes<TVector>.MultiplyByLine(ref f, ref line, ref f, ref scratch);
		SM9G2Group.NegatedFrobeniusSquared(in q, out SM9AffinePoint<SM9Fp2> q2);
		AdditionStep(ref point, in q2, in negatedX, in y, ref line);
		SM9Lanes<TVector>.MultiplyByLine(ref f, ref line, ref f, ref scratch);
		SM9Lanes<TVector>.ToFp12(ref f, out result);
		storage.ZeroMemory();
		negatedX.ZeroMemory();
		y.ZeroMemory();
		negatedQ.ZeroMemory();
		t.ZeroMemory();
		q1.ZeroMemory();
		q2.ZeroMemory();
	}

	// As MillerLoop with the steps of T by SM9MillerLoop, out of the lanes: only f is in lanes, and each line goes into lanes at P for its product.
	[SkipLocalsInit]
	private static void MillerLoopScalarSteps(in SM9AffinePoint<SM9Fp> p, in SM9AffinePoint<SM9Fp2> q, out SM9Fp12 result)
	{
		Span<byte> storage = stackalloc byte[StorageLength(2)];
		ref SM9Fp12Lanes f = ref Workspace(storage);
		ref SM9Fp12Lanes lanes = ref Unsafe.Add(ref f, 1);
		ref SM9LaneScratch scratch = ref Scratch(ref f, 2);
		SM9Fp.Negate(in p.X, out SM9Fp negatedX);
		SM9Fp y = p.Y;
		SM9AffinePoint<SM9Fp2> negatedQ;
		negatedQ.X = q.X;
		SM9Fp2.Negate(in q.Y, out negatedQ.Y);
		SM9Point<SM9Fp2> t;
		t.X = q.X;
		t.Y = q.Y;
		t.Z = SM9Fp2.One;
		ReadOnlySpan<sbyte> digits = SM9MillerLoop.Digits;
		Debug.Assert(digits[^2] is 0);

		// f starts at 1, so the first step, whose digit is 0, leaves f = l.
		SM9MillerLoop.DoublingStep(ref t, out SM9Line line);
		Evaluate(in line, in negatedX, in y, ref f);

		for (int i = digits.Length - 3; i >= 0; --i)
		{
			SM9Lanes<TVector>.Square(ref f, ref f, ref scratch);
			SM9MillerLoop.DoublingStep(ref t, out line);
			Evaluate(in line, in negatedX, in y, ref lanes);
			SM9Lanes<TVector>.MultiplyByLine(ref f, ref lanes, ref f, ref scratch);

			if (digits[i] > 0)
			{
				SM9MillerLoop.AdditionStep(ref t, in q, out line);
				Evaluate(in line, in negatedX, in y, ref lanes);
				SM9Lanes<TVector>.MultiplyByLine(ref f, ref lanes, ref f, ref scratch);
			}
			else if (digits[i] < 0)
			{
				SM9MillerLoop.AdditionStep(ref t, in negatedQ, out line);
				Evaluate(in line, in negatedX, in y, ref lanes);
				SM9Lanes<TVector>.MultiplyByLine(ref f, ref lanes, ref f, ref scratch);
			}
		}

		SM9G2Group.Frobenius(in q, out SM9AffinePoint<SM9Fp2> q1);
		SM9MillerLoop.AdditionStep(ref t, in q1, out line);
		Evaluate(in line, in negatedX, in y, ref lanes);
		SM9Lanes<TVector>.MultiplyByLine(ref f, ref lanes, ref f, ref scratch);
		SM9G2Group.NegatedFrobeniusSquared(in q, out SM9AffinePoint<SM9Fp2> q2);
		SM9MillerLoop.AdditionStep(ref t, in q2, out line);
		Evaluate(in line, in negatedX, in y, ref lanes);
		SM9Lanes<TVector>.MultiplyByLine(ref f, ref lanes, ref f, ref scratch);
		SM9Lanes<TVector>.ToFp12(ref f, out result);
		storage.ZeroMemory();
		negatedX.ZeroMemory();
		y.ZeroMemory();
		negatedQ.ZeroMemory();
		t.ZeroMemory();
		line.ZeroMemory();
		q1.ZeroMemory();
		q2.ZeroMemory();
	}

	// T = T + Q by SM9MillerLoop's step on T out of the lanes, and the line at P.
	[SkipLocalsInit]
	private static void AdditionStep(ref SM9Fp12Lanes point, in SM9AffinePoint<SM9Fp2> q, in SM9Fp negatedX, in SM9Fp y, ref SM9Fp12Lanes line)
	{
		SM9Lanes<TVector>.ToPoint(ref point, out SM9Point<SM9Fp2> t);
		SM9MillerLoop.AdditionStep(ref t, in q, out SM9Line l);
		SM9Lanes<TVector>.FromPoint(in t, ref point);
		Evaluate(in l, in negatedX, in y, ref line);
		t.ZeroMemory();
		l.ZeroMemory();
	}

	// As SM9MillerLoop.Run with the lines of Precompute and the factors of P: SM9Lanes.EvaluateLines takes them a batch at a time, each line into a lane, and each product by a line takes it from its lane of the batch.
	[SkipLocalsInit]
	internal static void MillerLoop(in SM9Fp alpha, in SM9Fp beta, ReadOnlySpan<SM9PrecomputedLine> lines, out SM9Fp12 result)
	{
		Debug.Assert(lines.Length is SM9MillerLoop.LineCount);

		Span<byte> storage = stackalloc byte[StorageLength(1) + SM9Lanes<TVector>.LineBatchLength * sizeof(ulong)];
		ref SM9Fp12Lanes f = ref Workspace(storage);
		ref SM9LaneScratch scratch = ref Scratch(ref f, 1);
		ref ulong batch = ref Unsafe.As<SM9LaneScratch, ulong>(ref Unsafe.Add(ref scratch, 1));
		SM9Lanes<TVector>.SplitFactors(in alpha, in beta, ref batch);
		ReadOnlySpan<sbyte> digits = SM9MillerLoop.Digits;
		Debug.Assert(digits[^2] is 0);

		// f starts at 1, so the first step, whose digit is 0, leaves f = l, the first line.
		EvaluateBatch(lines, 0, ref batch, ref scratch);
		SM9Lanes<TVector>.FromNormalizedLine(ref batch, 0, ref f);
		int k = 1;

		for (int i = digits.Length - 3; i >= 0; --i)
		{
			SM9Lanes<TVector>.Square(ref f, ref f, ref scratch);
			MultiplyByLine(ref f, lines, k++, ref batch, ref scratch);

			if (digits[i] is not 0)
			{
				MultiplyByLine(ref f, lines, k++, ref batch, ref scratch);
			}
		}

		MultiplyByLine(ref f, lines, k++, ref batch, ref scratch);
		MultiplyByLine(ref f, lines, k, ref batch, ref scratch);
		SM9Lanes<TVector>.ToFp12(ref f, out result);
		storage.ZeroMemory();
	}

	// As SM9MillerLoop.Run for the factors of two points with their lines, each step multiplying f by the product of its two lines: the lines go into a batch for each point and their products into a batch of pairs by SM9Lanes.EvaluateLinePairs, a batch at a time, and each product of f takes its pair from its lane of the batch. The first pair is f itself.
	[SkipLocalsInit]
	internal static void MillerLoop(in SM9Fp alpha, in SM9Fp beta, ReadOnlySpan<SM9PrecomputedLine> lines, in SM9Fp otherAlpha, in SM9Fp otherBeta, ReadOnlySpan<SM9PrecomputedLine> otherLines, out SM9Fp12 result)
	{
		Debug.Assert(lines.Length is SM9MillerLoop.LineCount && otherLines.Length is SM9MillerLoop.LineCount);

		Span<byte> storage = stackalloc byte[StorageLength(1) + (2 * SM9Lanes<TVector>.LineBatchLength + SM9Lanes<TVector>.PairBatchLength) * sizeof(ulong)];
		ref SM9Fp12Lanes f = ref Workspace(storage);
		ref SM9LaneScratch scratch = ref Scratch(ref f, 1);
		ref ulong batch = ref Unsafe.As<SM9LaneScratch, ulong>(ref Unsafe.Add(ref scratch, 1));
		ref ulong otherBatch = ref Unsafe.Add(ref batch, SM9Lanes<TVector>.LineBatchLength);
		ref ulong pairs = ref Unsafe.Add(ref otherBatch, SM9Lanes<TVector>.LineBatchLength);
		SM9Lanes<TVector>.SplitFactors(in alpha, in beta, ref batch);
		SM9Lanes<TVector>.SplitFactors(in otherAlpha, in otherBeta, ref otherBatch);
		ReadOnlySpan<sbyte> digits = SM9MillerLoop.Digits;
		Debug.Assert(digits[^2] is 0);

		EvaluatePairs(lines, otherLines, 0, ref batch, ref otherBatch, ref pairs, ref scratch);
		SM9Lanes<TVector>.FromLinePair(ref pairs, 0, ref f);
		int k = 1;

		for (int i = digits.Length - 3; i >= 0; --i)
		{
			SM9Lanes<TVector>.Square(ref f, ref f, ref scratch);
			MultiplyByLinePair(ref f, lines, otherLines, k++, ref batch, ref otherBatch, ref pairs, ref scratch);

			if (digits[i] is not 0)
			{
				MultiplyByLinePair(ref f, lines, otherLines, k++, ref batch, ref otherBatch, ref pairs, ref scratch);
			}
		}

		for (; k < SM9MillerLoop.LineCount; ++k)
		{
			MultiplyByLinePair(ref f, lines, otherLines, k, ref batch, ref otherBatch, ref pairs, ref scratch);
		}

		SM9Lanes<TVector>.ToFp12(ref f, out result);
		storage.ZeroMemory();
	}

	// f = f·l·l′ for line k of each point, evaluating the batches that start at k first. Which lines a batch holds depends on k alone.
	private static void MultiplyByLinePair(ref SM9Fp12Lanes f, ReadOnlySpan<SM9PrecomputedLine> lines, ReadOnlySpan<SM9PrecomputedLine> otherLines, int k, ref ulong batch, ref ulong otherBatch, ref ulong pairs, ref SM9LaneScratch scratch)
	{
		int lane = k % SM9Lanes<TVector>.BatchLines;

		if (lane is 0)
		{
			EvaluatePairs(lines, otherLines, k, ref batch, ref otherBatch, ref pairs, ref scratch);
		}

		SM9Lanes<TVector>.MultiplyByLinePair(ref f, ref pairs, lane, ref f, ref scratch);
	}

	// The lines of each point from start on into its batch and their products into pairs.
	private static void EvaluatePairs(ReadOnlySpan<SM9PrecomputedLine> lines, ReadOnlySpan<SM9PrecomputedLine> otherLines, int start, ref ulong batch, ref ulong otherBatch, ref ulong pairs, ref SM9LaneScratch scratch)
	{
		EvaluateBatch(lines, start, ref batch, ref scratch);
		EvaluateBatch(otherLines, start, ref otherBatch, ref scratch);
		SM9Lanes<TVector>.EvaluateLinePairs(ref batch, ref otherBatch, ref pairs, ref scratch);
	}

	// f = f·l for line k, evaluating the batch that starts at k first. Which lines a batch holds depends on k alone.
	private static void MultiplyByLine(ref SM9Fp12Lanes f, ReadOnlySpan<SM9PrecomputedLine> lines, int k, ref ulong batch, ref SM9LaneScratch scratch)
	{
		int lane = k % SM9Lanes<TVector>.BatchLines;

		if (lane is 0)
		{
			EvaluateBatch(lines, k, ref batch, ref scratch);
		}

		SM9Lanes<TVector>.MultiplyByNormalizedLine(ref f, ref batch, lane, ref f, ref scratch);
	}

	// The lines from start on, a batch of them or the rest, into the batch.
	private static void EvaluateBatch(ReadOnlySpan<SM9PrecomputedLine> lines, int start, ref ulong batch, ref SM9LaneScratch scratch)
	{
		int count = Math.Min(SM9Lanes<TVector>.BatchLines, lines.Length - start);
		SM9Lanes<TVector>.EvaluateLines(lines.Slice(start, count), ref batch, ref scratch);
	}

	// Nine elements hold the steps: each y_i takes the place of a power that no later step reads, as soon as its last reader is done.
	[SkipLocalsInit]
	internal static void FinalExponentiation(in SM9Fp12 value, out SM9Fp12 result)
	{
		Span<byte> storage = stackalloc byte[StorageLength(9)];
		ref SM9Fp12Lanes f = ref Workspace(storage);
		ref SM9Fp12Lanes t0 = ref Unsafe.Add(ref f, 1);
		ref SM9Fp12Lanes t1 = ref Unsafe.Add(ref f, 2);
		ref SM9Fp12Lanes ft = ref Unsafe.Add(ref f, 3);
		ref SM9Fp12Lanes ft2 = ref Unsafe.Add(ref f, 4);
		ref SM9Fp12Lanes ft3 = ref Unsafe.Add(ref f, 5);
		ref SM9Fp12Lanes inverse = ref Unsafe.Add(ref f, 6);
		ref SM9Fp12Lanes y4 = ref Unsafe.Add(ref f, 7);
		ref SM9Fp12Lanes y2 = ref Unsafe.Add(ref f, 8);
		ref SM9LaneScratch scratch = ref Scratch(ref f, 9);
		// f^(p⁶ − 1) = f̄/f = f̄²/N for N = f·f̄ = C0² − v·C1² of Fp6, so that it takes an inversion of Fp6 rather than of Fp12; MultiplyByFp6 reads the even lanes alone, so the odd ones of N, which are 0 mod p, go along.
		SM9Lanes<TVector>.FromFp12(in value, ref t0);
		SM9Lanes<TVector>.Conjugate(ulong.MaxValue, ref t0, ref t1);
		SM9Lanes<TVector>.Multiply(ref t0, ref t1, ref f, ref scratch);
		SM9Lanes<TVector>.ToFp12(ref f, out SM9Fp12 norm);
		SM9Fp6.Invert(in norm.C0, out norm.C0);
		SM9Lanes<TVector>.FromFp12(in norm, ref t0);
		norm.ZeroMemory();
		SM9Lanes<TVector>.Square(ref t1, ref t1, ref scratch);
		SM9Lanes<TVector>.MultiplyByFp6(ref t0, ref t1, ref f, ref scratch);
		SM9Lanes<TVector>.FrobeniusSquared(ref f, ref t0, ref scratch);
		SM9Lanes<TVector>.Multiply(ref t0, ref f, ref f, ref scratch);
		PowerT(ref f, ref ft, ref inverse, ref scratch);
		PowerT(ref ft, ref ft2, ref inverse, ref scratch);
		PowerT(ref ft2, ref ft3, ref inverse, ref scratch);
		// y0 = f^p·f^(p²)·f^(p³) in the place of the inverse of PowerT.
		ref SM9Fp12Lanes y0 = ref inverse;
		SM9Lanes<TVector>.Frobenius(ref f, ref y0, ref scratch);
		SM9Lanes<TVector>.FrobeniusSquared(ref f, ref t0, ref scratch);
		SM9Lanes<TVector>.Multiply(ref y0, ref t0, ref y0, ref scratch);
		SM9Lanes<TVector>.FrobeniusCubed(ref f, ref t0, ref scratch);
		SM9Lanes<TVector>.Multiply(ref y0, ref t0, ref y0, ref scratch);
		// y6 = conj(f^(t³)·(f^(t³))^p), y4 = conj(f^t·(f^(t²))^p), y3 = conj((f^t)^p), y2 = (f^(t²))^(p²), y5 = conj(f^(t²)) and y1 = conj(f), y6, y3, y5 and y1 in the places of f^(t³), f^t, f^(t²) and f.
		ref SM9Fp12Lanes y6 = ref ft3;
		SM9Lanes<TVector>.Frobenius(ref ft3, ref t0, ref scratch);
		SM9Lanes<TVector>.Multiply(ref t0, ref ft3, ref y6, ref scratch);
		SM9Lanes<TVector>.Conjugate(ulong.MaxValue, ref y6, ref y6);
		SM9Lanes<TVector>.Frobenius(ref ft2, ref y4, ref scratch);
		SM9Lanes<TVector>.Multiply(ref y4, ref ft, ref y4, ref scratch);
		SM9Lanes<TVector>.Conjugate(ulong.MaxValue, ref y4, ref y4);
		ref SM9Fp12Lanes y3 = ref ft;
		SM9Lanes<TVector>.Frobenius(ref ft, ref y3, ref scratch);
		SM9Lanes<TVector>.Conjugate(ulong.MaxValue, ref y3, ref y3);
		SM9Lanes<TVector>.FrobeniusSquared(ref ft2, ref y2, ref scratch);
		ref SM9Fp12Lanes y5 = ref ft2;
		SM9Lanes<TVector>.Conjugate(ulong.MaxValue, ref ft2, ref y5);
		ref SM9Fp12Lanes y1 = ref f;
		SM9Lanes<TVector>.Conjugate(ulong.MaxValue, ref f, ref y1);
		// The vectorial addition chain: T0 = y6²·y4·y5, T1 = y3·y5·T0, T0 = T0·y2, T1 = (T1²·T0)², and the result (T1·y0)·(T1·y1)².
		SM9Lanes<TVector>.CyclotomicSquare(ref y6, ref t0, ref scratch);
		SM9Lanes<TVector>.Multiply(ref t0, ref y4, ref t0, ref scratch);
		SM9Lanes<TVector>.Multiply(ref t0, ref y5, ref t0, ref scratch);
		SM9Lanes<TVector>.Multiply(ref y3, ref y5, ref t1, ref scratch);
		SM9Lanes<TVector>.Multiply(ref t1, ref t0, ref t1, ref scratch);
		SM9Lanes<TVector>.Multiply(ref t0, ref y2, ref t0, ref scratch);
		SM9Lanes<TVector>.CyclotomicSquare(ref t1, ref t1, ref scratch);
		SM9Lanes<TVector>.Multiply(ref t1, ref t0, ref t1, ref scratch);
		SM9Lanes<TVector>.CyclotomicSquare(ref t1, ref t1, ref scratch);
		SM9Lanes<TVector>.Multiply(ref t1, ref y1, ref t0, ref scratch);
		SM9Lanes<TVector>.Multiply(ref t1, ref y0, ref t1, ref scratch);
		SM9Lanes<TVector>.CyclotomicSquare(ref t0, ref t0, ref scratch);
		SM9Lanes<TVector>.Multiply(ref t1, ref t0, ref t1, ref scratch);
		SM9Lanes<TVector>.ToFp12(ref t1, out result);
		storage.ZeroMemory();
	}

	// value^k for value in GT, as SM9GTPower.Power: a table of eight entries in lanes, read in full for each digit.
	[SkipLocalsInit]
	internal static void Power(in SM9Fp12 value, in FieldElement<SM9Order> exponent, out SM9Fp12 result)
	{
		Span<byte> storage = stackalloc byte[StorageLength(TableLength + 2)];
		Span<byte> digits = stackalloc byte[SM9FrobeniusRecoding.Length];
		ref SM9Fp12Lanes table = ref Workspace(storage);
		ref SM9Fp12Lanes power = ref Unsafe.Add(ref table, TableLength);
		ref SM9Fp12Lanes entry = ref Unsafe.Add(ref table, TableLength + 1);
		ref SM9LaneScratch scratch = ref Scratch(ref table, TableLength + 2);
		// x is entry 0 of the table, which BuildTable leaves as it is.
		ref SM9Fp12Lanes x = ref table;
		SM9Lanes<TVector>.FromFp12(in value, ref x);
		BuildTable(ref x, ref table, ref entry, ref scratch);
		ulong even = SM9GTPower.Recode(in exponent, digits);
		Select(ref table, digits[^1], ref power);

		for (int i = digits.Length - 2; i >= 0; --i)
		{
			SM9Lanes<TVector>.CyclotomicSquare(ref power, ref power, ref scratch);
			Select(ref table, digits[i], ref entry);
			SM9Lanes<TVector>.Multiply(ref power, ref entry, ref power, ref scratch);
		}

		// Where k0 was even, power takes x⁻¹ = x̄.
		SM9Lanes<TVector>.Conjugate(ulong.MaxValue, ref x, ref entry);
		SM9Lanes<TVector>.Multiply(ref power, ref entry, ref entry, ref scratch);
		SM9Lanes<TVector>.ConditionalSelect(even, ref entry, ref power, ref power);
		SM9Lanes<TVector>.ToFp12(ref power, out result);
		storage.ZeroMemory();
		digits.ZeroMemory();
	}

	// value^k from the table of SM9GTPower.BuildFixedTable and value⁻¹, as SM9GTPower.Power with the fixed table: each entry is selected as SM9Fp12, from all of its comb, and goes into lanes.
	[SkipLocalsInit]
	internal static void Power(ReadOnlySpan<SM9Fp12> table, in SM9Fp12 inverse, in FieldElement<SM9Order> exponent, out SM9Fp12 result)
	{
		Debug.Assert(table.Length is SM9GTPower.FixedTableLength);

		Span<byte> storage = stackalloc byte[StorageLength(2)];
		Span<byte> digits = stackalloc byte[SM9FrobeniusRecoding.Length];
		ref SM9Fp12Lanes power = ref Workspace(storage);
		ref SM9Fp12Lanes entry = ref Unsafe.Add(ref power, 1);
		ref SM9LaneScratch scratch = ref Scratch(ref power, 2);
		ulong even = SM9GTPower.Recode(in exponent, digits);
		Unsafe.SkipInit(out SM9Fp12 selected);
		bool first = true;

		for (int offset = SM9GTPower.Spacing - 1; offset >= 0; --offset)
		{
			if (!first)
			{
				SM9Lanes<TVector>.CyclotomicSquare(ref power, ref power, ref scratch);
			}

			for (int c = 0; c < SM9GTPower.Teeth; ++c)
			{
				int i = c * SM9GTPower.Spacing + offset;

				// Which positions exist depends on the lengths alone.
				if (i >= digits.Length)
				{
					continue;
				}

				byte digit = digits[i];
				MaskedSelect.Lookup(in table[c * TableLength], TableLength, (uint)(digit & 7), out selected);
				SM9Lanes<TVector>.FromFp12(in selected, ref entry);
				SM9Lanes<TVector>.Conjugate(0 - (ulong)(digit >> 3), ref entry, ref entry);

				if (first)
				{
					power = entry;
					first = false;
				}
				else
				{
					SM9Lanes<TVector>.Multiply(ref power, ref entry, ref power, ref scratch);
				}
			}
		}

		SM9Lanes<TVector>.FromFp12(in inverse, ref entry);
		SM9Lanes<TVector>.Multiply(ref power, ref entry, ref entry, ref scratch);
		SM9Lanes<TVector>.ConditionalSelect(even, ref entry, ref power, ref power);
		SM9Lanes<TVector>.ToFp12(ref power, out result);
		storage.ZeroMemory();
		digits.ZeroMemory();
		selected.ZeroMemory();
	}

	// The table of SM9GTPower.BuildFixedTable for value in GT, which may be secret, and value⁻¹ = value̅: the base of each comb from the one before by Spacing cyclotomic squares, its eight products by BuildTable, all in lanes, and each entry back as SM9Fp12.
	[SkipLocalsInit]
	internal static void BuildFixedTable(in SM9Fp12 value, Span<SM9Fp12> table, out SM9Fp12 inverse)
	{
		Debug.Assert(table.Length is SM9GTPower.FixedTableLength);

		Span<byte> storage = stackalloc byte[StorageLength(TableLength + 2)];
		ref SM9Fp12Lanes entries = ref Workspace(storage);
		ref SM9Fp12Lanes toothBase = ref Unsafe.Add(ref entries, TableLength);
		ref SM9Fp12Lanes frobenius = ref Unsafe.Add(ref entries, TableLength + 1);
		ref SM9LaneScratch scratch = ref Scratch(ref entries, TableLength + 2);
		SM9Lanes<TVector>.FromFp12(in value, ref toothBase);

		for (int c = 0; c < SM9GTPower.Teeth; ++c)
		{
			if (c > 0)
			{
				for (int k = 0; k < SM9GTPower.Spacing; ++k)
				{
					SM9Lanes<TVector>.CyclotomicSquare(ref toothBase, ref toothBase, ref scratch);
				}
			}

			BuildTable(ref toothBase, ref entries, ref frobenius, ref scratch);

			for (int j = 0; j < TableLength; ++j)
			{
				SM9Lanes<TVector>.ToFp12(ref Unsafe.Add(ref entries, j), out table[c * TableLength + j]);
			}
		}

		SM9Fp12.Conjugate(in value, out inverse);
		storage.ZeroMemory();
	}

	// value^t for value in the cyclotomic subgroup, by the NAF of t, which is public; inverse is overwritten.
	// ReSharper disable once RedundantAssignment
	private static void PowerT(ref SM9Fp12Lanes value, ref SM9Fp12Lanes result, ref SM9Fp12Lanes inverse, ref SM9LaneScratch scratch)
	{
		SM9Lanes<TVector>.Conjugate(ulong.MaxValue, ref value, ref inverse);
		result = value;

		for (int i = 62; i >= 0; --i)
		{
			SM9Lanes<TVector>.CyclotomicSquare(ref result, ref result, ref scratch);

			if ((SM9FinalExponentiation.TPlus >> i & 1) is not 0)
			{
				SM9Lanes<TVector>.Multiply(ref result, ref value, ref result, ref scratch);
			}
			else if ((SM9FinalExponentiation.TMinus >> i & 1) is not 0)
			{
				SM9Lanes<TVector>.Multiply(ref result, ref inverse, ref result, ref scratch);
			}
		}
	}

	// The eight products x·Π_(j≥1) (x^(p^j))^(u_j) of SM9GTPower, u_j bit j − 1 of the index; x may be entry 0 of table, and frobenius is overwritten.
	// ReSharper disable once RedundantAssignment
	private static void BuildTable(ref SM9Fp12Lanes x, ref SM9Fp12Lanes table, ref SM9Fp12Lanes frobenius, ref SM9LaneScratch scratch)
	{
		table = x;
		SM9Lanes<TVector>.Frobenius(ref x, ref frobenius, ref scratch);
		SM9Lanes<TVector>.Multiply(ref x, ref frobenius, ref Unsafe.Add(ref table, 1), ref scratch);
		SM9Lanes<TVector>.FrobeniusSquared(ref x, ref frobenius, ref scratch);
		SM9Lanes<TVector>.Multiply(ref x, ref frobenius, ref Unsafe.Add(ref table, 2), ref scratch);
		SM9Lanes<TVector>.Multiply(ref Unsafe.Add(ref table, 1), ref frobenius, ref Unsafe.Add(ref table, 3), ref scratch);
		SM9Lanes<TVector>.FrobeniusCubed(ref x, ref frobenius, ref scratch);

		for (int u = 0; u < 4; ++u)
		{
			SM9Lanes<TVector>.Multiply(ref Unsafe.Add(ref table, u), ref frobenius, ref Unsafe.Add(ref table, u + 4), ref scratch);
		}
	}

	// The entry of digit, conjugated if the digit is negative. Every entry is read, so neither the time nor the addresses depend on the digit.
	// ReSharper disable once RedundantAssignment
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Select(ref SM9Fp12Lanes table, byte digit, ref SM9Fp12Lanes result)
	{
		MaskedSelect.Lookup(in table, TableLength, (uint)(digit & 7), out result);
		SM9Lanes<TVector>.Conjugate(0 - (ulong)(digit >> 3), ref result, ref result);
	}

	// The line at P: l0, l2·(−xP) and l3·yP in lanes 0, 2 and 3.
	[SkipLocalsInit]
	private static void Evaluate(in SM9Line line, in SM9Fp negatedX, in SM9Fp y, ref SM9Fp12Lanes result)
	{
		SM9Fp2.MultiplyByFp(in line.L2, in negatedX, out SM9Fp2 l2);
		SM9Fp2.MultiplyByFp(in line.L3, in y, out SM9Fp2 l3);
		SM9Lanes<TVector>.FromLine(in line.L0, in l2, in l3, ref result);
		l2.ZeroMemory();
		l3.ZeroMemory();
	}

	// The bytes for count elements and a scratch, with room to start them on a 64-byte line: the writes of a vector that straddles a line do not forward to the reads of the next product.
	private static int StorageLength(int count)
	{
		return count * Unsafe.SizeOf<SM9Fp12Lanes>() + Unsafe.SizeOf<SM9LaneScratch>() + Alignment - 1;
	}

	// The first element of storage from StorageLength, on its first 64-byte line.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static unsafe ref SM9Fp12Lanes Workspace(Span<byte> storage)
	{
		nint address = (nint)Unsafe.AsPointer(ref MemoryMarshal.GetReference(storage));
		int offset = (int)(-address & Alignment - 1);
		return ref Unsafe.As<byte, SM9Fp12Lanes>(ref storage[offset]);
	}

	// The scratch after count elements of a workspace.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ref SM9LaneScratch Scratch(ref SM9Fp12Lanes elements, int count)
	{
		return ref Unsafe.As<SM9Fp12Lanes, SM9LaneScratch>(ref Unsafe.Add(ref elements, count));
	}
}
