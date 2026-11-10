using static CryptoBase.EllipticCurves.LimbArithmetic;

namespace CryptoBase.EllipticCurves;

// The products of ISM2Kernel that lanes speed up, on the lanes of TField, with the point formulas of ECFormulas, which take and give the bounds of SM2Field29, for u = 2^29: Multiply and Square take limbs whose bounds X and Y have 9·X·Y ≤ 2^64 − 2^54, every subtrahend is a product or comes from Reduce or LoadEntries, with limbs no larger than those of 4p, and every input of Reduce has limbs below 2^32. Each formula keeps X and Y below 2p in limbs below u, limb 8 below 2^25, and Z, 1 or a doubled product, below 2.3p in limbs below 2u + 130, so that each product takes limbs below 2u + 130 on both sides, or below 4u + 260 against limbs below u + 65.
internal static class SM2Vector<TField> where TField : unmanaged, ISM2Field29Lanes<TField>
{
	private const int Alignment = 64;

	private const int EntryLength = 8;

	// The values of MultiplyBase: two points and the scratch of the formulas. The rounds keep the coordinates of the entries and 1 in scratch 9 to 11, which MixedAdd does not touch; the folds, which come after the rounds and take the whole scratch, put their sums in scratch 0 to 2.
	private const int ValueCount = 2 * 3 + ScratchLength;

	private const int ScratchLength = 12;

	// The values of FillRound: the coordinates of both entries, the terms of λ, λ, the inverse, the sum and 1, and two of scratch.
	private const int FillValueCount = 13;

	// Sets result to k·G for k below n, from the windows of ECGroup.MultiplyBase in ECGeneratorTable: W windows of w = GeneratorWindowWidth bits, W = t + 1 = 43 of 6 for t = ⌊256/w⌋, so that wt = 252, or W = 32 of 8, whose digits ECGroup.RecodeSpanning takes from k or k − n. They split into LaneCount blocks of consecutive windows, the first W mod LaneCount blocks one window longer, and lane l sums the block whose index is l with its bits reversed: each round adds the entry of the next window of every lane at once, by a masked scan of its window, and then the lanes fold in halves, lane l adding lane l + LaneCount/2, then l + LaneCount/4 and so on down to lane 1, so that each fold adds the sums of two adjacent blocks. Neither the time nor the addresses depend on k, and the intermediates are cleared.
	// A digit of 0 selects (0, 0) and keeps the sum of its lane, as in ECGroup.MultiplyBase. A lane holds the point at infinity just while the digits of its block so far are all 0, which the masks track from the digits instead of testing Z: no sum S = Σ_{a≤i<c} d_i·2^(wi) of a block with a digit other than 0 is 0 mod n, as below, and no addition meets equal or opposite points, which the formulas would not give right. As |d_i| ≤ 2^(w − 1), |S| < 2^(wc)/1.9, and S = 0 only if every digit is 0, as a lowest digit other than 0 is no multiple of 2^w. Of 8 bits, every digit lies in [−128, 127], so each sum below of digits d_i or −d_i over windows below 32, below 2^256·128/255 < n in absolute value and with a lowest digit no multiple of 2^w, is 0 mod n only if its digits are all 0. Of 6 bits, for c ≤ t, |S| < 2^252 < n; for c = W and a ≥ 1, S = 2^(wa)·(⌊k/2^(wa)⌋ + c_a) for the carry c_a into window a, below n + 2^(wa) and even, so not n; and for c = W and a = 0, S = k.
	// Adding the entry d·2^(wi)·G of window i to the sum S of the windows a to i − 1 of a lane meets equal or opposite points just if S ∓ d·2^(wi) ≡ 0 (mod n), which d ≠ 0 rules out for windows of 8 bits. Of 6 bits, for i < t that is below 2^(w(i + 1)) ≤ 2^252 in absolute value, so 0, which |S| < 2^(wi) rules out for d ≠ 0. For i = t, where 0 ≤ d ≤ 16, and a ≥ 1, S ∓ d·2^252 is even and below 2n in absolute value, so 0, ruled out as before, or ±n, which is odd. For i = t and a = 0, a block of every window, S + d·2^252 = k, and S − d·2^252 is no multiple of n, as ECGroup.MultiplyFixedWindows shows for its window t.
	// A fold adds the sums S1 of the windows a to b − 1 and S2 of b to c − 1. S1 + S2 is the sum of a block, so 0 mod n just if its digits are all 0. S1 − S2 ≡ 0 needs S1 = S2, so both 0, if |S1 − S2| < n, which holds for windows of 8 bits and, of 6, for c ≤ t, and also if it is even and below 2n, as for c = W and a ≥ 1. Of 6 bits, the last fold takes a = 0, c = W and b = 23 for eight blocks and 22 for four or two: there S1 = (k mod 2^(wb)) − c_b·2^(wb), so −2^(wb)/2 < S1 < 2^(wb), and S2 − S1 = k − 2S1 lies in (−n, 2n), so it is 0, or n with S1 = (k − n)/2 < 0 and S2 = S1 + n a multiple of 2^(wb): then S1 = −(n mod 2^(wb)), which needs bit wb − 1 of n to be 0, and bits 131 and 137 of n are 1.
	internal static void MultiplyBase(in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> result)
	{
		SumWindows<MaskedScan, SM2Curve>(ECGeneratorTable<SM2Curve, SM2Field52, SM2Order>.Windows, default, in scalar, in scalar, out result, out _);
	}

	// Sets baseResult to k·G and result to k·P for k below n from the windows of P that ECPointTable holds, in one pass: lanes 0 to B − 1 sum the windows of G and lanes B to 2B − 1 those of P for B = LaneCount/2, each half as MultiplyBase sums the windows of G on B lanes, and the two share the rounds and the digits. The arguments there deal with the scalars mod n alone, so they hold for any point of the group, which has prime order n, in place of G.
	internal static void MultiplyBaseAndFixed(ReadOnlySpan<ulong> windows, in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> baseResult, out JacobianPoint<SM2Field52> result)
	{
		SumWindows<MaskedScan, SM2Curve>(ECGeneratorTable<SM2Curve, SM2Field52, SM2Order>.Windows, windows, in scalar, in scalar, out baseResult, out result);
	}

	// Sets result to u1·G + u2·Q with the table that ECVariableTimePointTable builds for Q: u2·Q by ECVariableTimeGroup.MultiplyAddWindows with u1 = 0, whose windows then add nothing, and u1·G on the lanes as MultiplyBase sums it, from the entries of the windows of SM2VerificationCurve read at the digits. Every input is public, so the time and the addresses read depend on them.
	internal static void MultiplyAdd(in FieldElement<SM2Order> u1, ReadOnlySpan<AffinePoint<SM2Field52>> pointTable, in FieldElement<SM2Order> u2, out JacobianPoint<SM2Field52> result)
	{
		FieldElement<SM2Order> zero = default;
		ECVariableTimeGroup<SM2Curve, SM2Field52, SM2Order>.MultiplyAddWindows(in zero, pointTable, in u2, out result);

		if (FieldElement<SM2Order>.IsZero(in u1) is not 0)
		{
			return;
		}

		SumWindows<DirectRead, SM2VerificationCurve>(ECGeneratorTable<SM2VerificationCurve, SM2Field52, SM2Order>.Windows, default, in u1, in u1, out JacobianPoint<SM2Field52> product, out _);
		ECVariableTimeGroup<SM2Curve, SM2Field52, SM2Order>.Add(ref result, in product);
	}

	// As MultiplyBase for a public k, from the entries of the windows of SM2VerificationCurve read at the digits. The time and the addresses read depend on k.
	internal static void MultiplyBaseVariableTime(in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> result)
	{
		SumWindows<DirectRead, SM2VerificationCurve>(ECGeneratorTable<SM2VerificationCurve, SM2Field52, SM2Order>.Windows, default, in scalar, in scalar, out result, out _);
	}

	// Sets result to k·P for k below n from the windows of P that ECPointTable holds, as MultiplyBase sums those of G: its arguments deal with the scalars mod n alone, so they hold for any point of the group, which has prime order n, in place of G.
	internal static void MultiplyFixed(ReadOnlySpan<ulong> windows, in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> result)
	{
		SumWindows<MaskedScan, SM2Curve>(windows, default, in scalar, in scalar, out result, out _);
	}

	// Sets result to u1·G + u2·P for u1 and u2 below n from the windows of P that ECPointTable holds for SM2VerificationCurve: the sums of MultiplyBaseAndFixed with u1 for G and u2 for P over the windows of that curve, from entries read at the digits, and their sum. Every input is public, so the time and the addresses read depend on them.
	internal static void MultiplyAddFixed(ReadOnlySpan<ulong> windows, in FieldElement<SM2Order> u1, in FieldElement<SM2Order> u2, out JacobianPoint<SM2Field52> result)
	{
		SumWindows<DirectRead, SM2VerificationCurve>(ECGeneratorTable<SM2VerificationCurve, SM2Field52, SM2Order>.Windows, windows, in u1, in u2, out JacobianPoint<SM2Field52> product, out result);
		ECVariableTimeGroup<SM2Curve, SM2Field52, SM2Order>.Add(ref result, in product);
	}

	// The sums of MultiplyBase over the windows of first and, unless second is empty, of second, both laid out for TCurve, with the entries that TSelector selects: one table takes the blocks of every lane, and two take those of half of the lanes each, lane l + B reading the window of lane l in the second table for B = LaneCount/2. One table leaves secondResult unset. One copy of the code serves both counts, so that the first product with two tables does not compile one of its own.
	[SkipLocalsInit]
	private static void SumWindows<TSelector, TCurve>(ReadOnlySpan<ulong> first, ReadOnlySpan<ulong> second, in FieldElement<SM2Order> scalar, in FieldElement<SM2Order> secondScalar, out JacobianPoint<SM2Field52> firstResult, out JacobianPoint<SM2Field52> secondResult) where TSelector : struct, ISelector where TCurve : struct, IECCurve
	{
		Debug.Assert(first.Length == ECGeneratorTable<TCurve, SM2Field52, SM2Order>.Length && (second.IsEmpty || second.Length == first.Length));

		int tables = second.IsEmpty ? 1 : 2;
		int lanes = TField.LaneCount;
		// The lanes of a table, one for each of its blocks.
		int blocks = tables is 2 ? lanes / 2 : lanes;
		int windowCount = ECGeneratorTable<TCurve, SM2Field52, SM2Order>.WindowCount;
		// The digits of secondScalar, where TSelector takes it, follow those of scalar.
		Span<sbyte> digits = stackalloc sbyte[TSelector.TakesSecondScalar ? 2 * windowCount : windowCount];
		// The entries and the masks, which vectors load after the stores of the lanes, start on a 64-byte line too, for the reason Align gives.
		Span<byte> entryStorage = stackalloc byte[StorageLength<ulong>(EntryLength * lanes)];
		Span<ulong> entries = Align<ulong>(entryStorage, EntryLength * lanes);
		Span<byte> maskStorage = stackalloc byte[StorageLength<ulong>(4 * lanes)];
		Span<ulong> masks = Align<ulong>(maskStorage, 4 * lanes);
		Span<byte> storage = stackalloc byte[StorageLength<TField>(ValueCount)];
		Span<TField> values = Align<TField>(storage, ValueCount);
		ref SM2JacobianLanes<TField> point = ref AsPoint(ref values[0]);
		ref SM2JacobianLanes<TField> sum = ref AsPoint(ref values[3]);
		ref TField scratch = ref values[6];
		ref TField x = ref Unsafe.Add(ref scratch, 9);
		ref TField y = ref Unsafe.Add(ref scratch, 10);
		ref TField one = ref Unsafe.Add(ref scratch, 11);
		ref SM2JacobianLanes<TField> total = ref AsPoint(ref scratch);
		Span<ulong> zero = masks.Slice(0, lanes);
		Span<ulong> negative = masks.Slice(lanes, lanes);
		Span<ulong> infinity = masks.Slice(2 * lanes, lanes);
		Span<ulong> otherInfinity = masks.Slice(3 * lanes, lanes);
		ReadOnlySpan<byte> starts = BlockStarts(windowCount, blocks);
		ReadOnlySpan<byte> lengths = BlockLengths(windowCount, blocks);
		ref readonly ulong firstWindows = ref MemoryMarshal.GetReference(first);
		ref readonly ulong secondWindows = ref MemoryMarshal.GetReference(second);
		int windowLength = ECGeneratorTable<TCurve, SM2Field52, SM2Order>.WindowLength;
		// The windows of 8 bits of SM2VerificationCurve divide 256 bits, those of SM2Curve do not.
		if (256 % TCurve.GeneratorWindowWidth is 0)
		{
			ECGroup<SM2Curve, SM2Field52, SM2Order>.RecodeSpanning(in scalar, TCurve.GeneratorWindowWidth, digits.Slice(0, windowCount));
		}
		else
		{
			ECGroup<SM2Curve, SM2Field52, SM2Order>.Recode(in scalar, TCurve.GeneratorWindowWidth, digits.Slice(0, windowCount));
		}

		int secondDigits = 0;

		if (TSelector.TakesSecondScalar && tables is 2)
		{
			if (256 % TCurve.GeneratorWindowWidth is 0)
			{
				ECGroup<SM2Curve, SM2Field52, SM2Order>.RecodeSpanning(in secondScalar, TCurve.GeneratorWindowWidth, digits.Slice(windowCount));
			}
			else
			{
				ECGroup<SM2Curve, SM2Field52, SM2Order>.Recode(in secondScalar, TCurve.GeneratorWindowWidth, digits.Slice(windowCount));
			}

			secondDigits = windowCount;
		}

		TField.One(out one);

		// Lane 0 holds a longest block.
		for (int round = 0; round < lengths[0]; ++round)
		{
			for (int lane = 0; lane < lanes; ++lane)
			{
				ref ulong entry = ref entries[EntryLength * lane];
				int block = lane & blocks - 1;

				// Which lanes have a window this round depends on the round alone.
				if (round < lengths[block])
				{
					int window = starts[block] + round;
					int digit = TSelector.TakesSecondScalar ? digits[(lane < blocks ? 0 : secondDigits) + window] : digits[window];
					ref readonly ulong windows = ref lane < blocks ? ref firstWindows : ref secondWindows;
					TSelector.Select(in Unsafe.Add(ref Unsafe.AsRef(in windows), window * windowLength * EntryLength), windowLength, digit, ref entry);
					zero[lane] = ZeroMask((ulong)digit);
					negative[lane] = (ulong)(digit >> 31);
				}
				else
				{
					entries.Slice(EntryLength * lane, EntryLength).Clear();
					zero[lane] = ulong.MaxValue;
					negative[lane] = 0;
				}
			}

			// The negated y, 4p − y, has limbs below 2u, which Reduce brings below u and the value below 2p for the subtractions it may meet as the Y of a sum.
			TField.LoadEntries(in entries[0], out x, out y);
			TField.ConditionalNegate(in negative[0], ref y);
			TField.Reduce(in y, out y);

			if (round is 0)
			{
				point.X = x;
				point.Y = y;
				point.Z = one;
				zero.CopyTo(infinity);
				continue;
			}

			// The point of round 0 is an entry, with Z = 1.
			if (round is 1)
			{
				AffineAdd(in point.X, in point.Y, in x, in y, ref scratch, out sum);
			}
			else
			{
				MixedAdd(in point, in x, in y, ref scratch, out sum);
			}

			TField.ConditionalSelect(in infinity[0], in x, in sum.X, out sum.X);
			TField.ConditionalSelect(in infinity[0], in y, in sum.Y, out sum.Y);
			TField.ConditionalSelect(in infinity[0], in one, in sum.Z, out sum.Z);
			SM2JacobianLanes<TField>.ConditionalSelect(in zero[0], in point, in sum, out point);

			for (int lane = 0; lane < lanes; ++lane)
			{
				infinity[lane] &= zero[lane];
			}
		}

		if (blocks is 8)
		{
			Fold(4, ref point, ref sum, ref total, infinity, otherInfinity, ref scratch);
			Fold(2, ref point, ref sum, ref total, infinity, otherInfinity, ref scratch);
		}
		else if (blocks is 4)
		{
			Fold(2, ref point, ref sum, ref total, infinity, otherInfinity, ref scratch);
		}

		// The lanes hold a·2^261 and SM2Field52 a·2^260. The halves stay in storage, which the end clears.
		TField.Halve(in point.X, out point.X);
		TField.Reduce(in point.X, out point.X);
		TField.Halve(in point.Y, out point.Y);
		TField.Reduce(in point.Y, out point.Y);
		TField.Halve(in point.Z, out point.Z);
		TField.Reduce(in point.Z, out point.Z);
		Span<JacobianPoint<SM2Field52>> halves = stackalloc JacobianPoint<SM2Field52>[3];
		Finish(in point, infinity, 0, blocks, halves, out firstResult);

		if (tables is 2)
		{
			Finish(in point, infinity, blocks, blocks, halves, out secondResult);
		}
		else
		{
			Unsafe.SkipInit(out secondResult);
		}

		digits.ZeroMemory();
		entryStorage.ZeroMemory();
		maskStorage.ZeroMemory();
		storage.ZeroMemory();
		halves.ZeroMemory();
	}

	// Fills entries 2 to WindowLength of each window of windows, which ECGeneratorTable lays out for TCurve, from entry 1, its base, as ECGeneratorTable.FillWindows does: the same affine sums and doubles in the same rounds, LaneCount of them at a time. The table is public, so the time may depend on it.
	internal static void FillWindows<TCurve>(Span<ulong> windows) where TCurve : struct, IECCurve
	{
		Debug.Assert(windows.Length == ECGeneratorTable<TCurve, SM2Field52, SM2Order>.Length && Unsafe.SizeOf<TField>() == 9 * TField.LaneCount * sizeof(ulong));

		int windowLength = ECGeneratorTable<TCurve, SM2Field52, SM2Order>.WindowLength;
		TField[] products = new TField[(ECGeneratorTable<TCurve, SM2Field52, SM2Order>.WindowCount * windowLength / 2 + TField.LaneCount - 1) / TField.LaneCount];

		for (int half = 1; half < windowLength; half *= 2)
		{
			FillRound<TCurve>(windows, half, products);
		}
	}

	// Entries half + 1 to 2·half of every window, as ECGeneratorTable.AddRound gives them. Sum s = i·half + m − 1, for window i and m from 1 to half, takes lane s mod LaneCount of group ⌊s/LaneCount⌋, and the spare lanes of the last group repeat the last sum. products[g] holds the products of the denominators of each lane up to group g, so that one inversion of the product of the lanes of the last gives the inverse of every denominator, from the last group back. The terms of λ and x1 − x3 have limbs below 3u + 65, and every other operand of a product comes from Multiply or LoadEntries, in limbs below u + 65; x3 and y3 subtract values of LoadEntries and Reduce, as Subtract takes, and have limbs below 5u + 65, which Halve and Reduce take to the a·2^260 of SM2Field52 below 2p, as ToField52 joins them. The products of λ, x3 and y3, which the chain of inverses does not wait for, take the carry of MultiplyRipple.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private static void FillRound<TCurve>(Span<ulong> windows, int half, Span<TField> products) where TCurve : struct, IECCurve
	{
		int lanes = TField.LaneCount;
		int count = ECGeneratorTable<TCurve, SM2Field52, SM2Order>.WindowCount * half;
		int windowLength = ECGeneratorTable<TCurve, SM2Field52, SM2Order>.WindowLength;
		int groups = (count + lanes - 1) / lanes;
		Span<ulong> firsts = stackalloc ulong[EntryLength * lanes];
		Span<ulong> seconds = stackalloc ulong[EntryLength * lanes];
		Span<ulong> doubling = stackalloc ulong[lanes];
		Span<byte> storage = stackalloc byte[StorageLength<TField>(FillValueCount)];
		Span<TField> values = Align<TField>(storage, FillValueCount);
		ref TField x1 = ref values[0];
		ref TField y1 = ref values[1];
		ref TField x2 = ref values[2];
		ref TField y2 = ref values[3];
		ref TField denominator = ref values[4];
		ref TField numerator = ref values[5];
		ref TField lambda = ref values[6];
		ref TField inverse = ref values[7];
		ref TField x3 = ref values[8];
		ref TField y3 = ref values[9];
		ref TField one = ref values[10];
		ref TField scratch = ref values[11];
		TField.One(out one);
		// The start of the window whose entry half x1 and y1 hold, from half = LaneCount on.
		int window = -1;

		for (int group = 0; group < groups; ++group)
		{
			bool doubles = Load<TCurve>(windows, half, windowLength, group, count, firsts, seconds, doubling, ref window, ref x1, ref y1, out x2, out y2);
			Denominator(in x1, in y1, in x2, in doubling[0], doubles, ref scratch, out denominator);

			if (group is 0)
			{
				products[0] = denominator;
			}
			else
			{
				TField.Multiply(in products[group - 1], in denominator, out products[group]);
			}
		}

		InvertLanes(in products[groups - 1], out inverse);

		for (int group = groups - 1; group >= 0; --group)
		{
			bool doubles = Load<TCurve>(windows, half, windowLength, group, count, firsts, seconds, doubling, ref window, ref x1, ref y1, out x2, out y2);
			Terms(in x1, in y1, in x2, in y2, in one, in doubling[0], doubles, ref scratch, out denominator, out numerator);

			if (group is not 0)
			{
				TField.MultiplyRipple(in inverse, in products[group - 1], out lambda);
				TField.Multiply(in inverse, in denominator, out inverse);
				TField.MultiplyRipple(in numerator, in lambda, out lambda);
			}
			else
			{
				TField.MultiplyRipple(in numerator, in inverse, out lambda);
			}

			// x3 = λ² − x1 − x2 and y3 = λ(x1 − x3) − y1, with x2 = x1 for a double.
			TField.SquareRipple(in lambda, out x3);
			TField.Subtract(in x3, in x1, out x3);
			TField.Subtract(in x3, in x2, out x3);
			TField.Reduce(in x3, out x3);
			TField.Subtract(in x1, in x3, out y3);
			TField.MultiplyRipple(in lambda, in y3, out y3);
			TField.Subtract(in y3, in y1, out y3);
			TField.Halve(in x3, out TField halved);
			TField.Reduce(in halved, out x3);
			TField.Halve(in y3, out halved);
			TField.Reduce(in halved, out y3);
			Scatter<TCurve>(windows, half, group, count, in x3, in y3);
		}
	}

	// x1 and y1 of entry half and x2 and y2 of entry m of the window of each sum of group, and the lanes of doubling where m = half, the sums that are doubles; returns whether any is. From half = LaneCount on, the sums of a group lie in one window, their entries m in a row, which LoadEntries reads in place, and entry half the same in every lane, loaded again only where window, the start of the window that x1 and y1 hold, changes; below, Gather copies the entries of each lane.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool Load<TCurve>(ReadOnlySpan<ulong> windows, int half, int windowLength, int group, int count, Span<ulong> firsts, Span<ulong> seconds, Span<ulong> doubling, ref int window, ref TField x1, ref TField y1, out TField x2, out TField y2) where TCurve : struct, IECCurve
	{
		int lanes = TField.LaneCount;

		if (half < lanes)
		{
			bool doubled = Gather<TCurve>(windows, half, group, count, firsts, seconds, doubling);
			TField.LoadEntries(in firsts[0], out x1, out y1);
			TField.LoadEntries(in seconds[0], out x2, out y2);
			return doubled;
		}

		int sum = group * lanes;
		int start = (sum >> BitOperations.Log2((uint)half)) * windowLength;
		int m = (sum & half - 1) + 1;

		if (start != window)
		{
			window = start;
			ReadOnlySpan<ulong> first = windows.Slice((start + half - 1) * EntryLength, EntryLength);

			for (int lane = 0; lane < lanes; ++lane)
			{
				first.CopyTo(firsts.Slice(lane * EntryLength, EntryLength));
			}

			TField.LoadEntries(in firsts[0], out x1, out y1);
		}

		TField.LoadEntries(in windows[(start + m - 1) * EntryLength], out x2, out y2);
		// m reaches half in the last lane of the last group of a window alone.
		bool doubles = m + lanes - 1 == half;
		doubling.Clear();
		doubling[lanes - 1] = doubles ? ulong.MaxValue : 0;
		return doubles;
	}

	// Copies entry half and entry m of the window of each sum of group into firsts and seconds, as LoadEntries takes them, and sets the lanes of doubling where m = half, the sums that are doubles; returns whether any is.
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private static bool Gather<TCurve>(ReadOnlySpan<ulong> windows, int half, int group, int count, Span<ulong> firsts, Span<ulong> seconds, Span<ulong> doubling) where TCurve : struct, IECCurve
	{
		int windowLength = ECGeneratorTable<TCurve, SM2Field52, SM2Order>.WindowLength;
		int shift = BitOperations.Log2((uint)half);
		bool doubles = false;

		for (int lane = 0; lane < TField.LaneCount; ++lane)
		{
			int sum = Math.Min(group * TField.LaneCount + lane, count - 1);
			int window = (sum >> shift) * windowLength;
			int m = (sum & half - 1) + 1;
			windows.Slice((window + half - 1) * EntryLength, EntryLength).CopyTo(firsts.Slice(lane * EntryLength, EntryLength));
			windows.Slice((window + m - 1) * EntryLength, EntryLength).CopyTo(seconds.Slice(lane * EntryLength, EntryLength));
			doubling[lane] = m == half ? ulong.MaxValue : 0;
			doubles |= m == half;
		}

		return doubles;
	}

	// The denominator and the numerator of λ for each lane: x2 − x1 and y2 − y1, or, where doubling is set, 2·y1 and 3(x1² − 1), whose x1² − 1 goes through Reduce before the factor 3. Each has limbs below 3u + 65, against the products that it meets.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Terms(in TField x1, in TField y1, in TField x2, in TField y2, in TField one, ref readonly ulong doubling, bool doubles, ref TField scratch, out TField denominator, out TField numerator)
	{
		TField.Subtract(in x2, in x1, out denominator);
		TField.Subtract(in y2, in y1, out numerator);

		if (!doubles)
		{
			return;
		}

		ref TField term = ref scratch;
		ref TField twice = ref Unsafe.Add(ref scratch, 1);
		TField.Add(in y1, in y1, out term);
		TField.ConditionalSelect(in doubling, in term, in denominator, out denominator);
		TField.Square(in x1, out term);
		TField.Subtract(in term, in one, out term);
		TField.Reduce(in term, out term);
		TField.Add(in term, in term, out twice);
		TField.Add(in twice, in term, out term);
		TField.ConditionalSelect(in doubling, in term, in numerator, out numerator);
	}

	// The denominator of Terms alone, for the chain of products, which does not take the numerator.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Denominator(in TField x1, in TField y1, in TField x2, ref readonly ulong doubling, bool doubles, ref TField scratch, out TField denominator)
	{
		TField.Subtract(in x2, in x1, out denominator);

		if (!doubles)
		{
			return;
		}

		TField.Add(in y1, in y1, out scratch);
		TField.ConditionalSelect(in doubling, in scratch, in denominator, out denominator);
	}

	// The inverse of each lane of a product, from one inversion of the product of the lanes, which goes through SM2Field52, halved, and back through LoadEntries, doubled.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private static void InvertLanes(in TField value, out TField result)
	{
		int lanes = TField.LaneCount;
		Span<SM2Field52> elements = stackalloc SM2Field52[lanes];
		Span<SM2Field52> prefixes = stackalloc SM2Field52[lanes];
		Span<ulong> entries = stackalloc ulong[EntryLength * lanes];
		TField.Halve(in value, out TField halved);
		TField.Reduce(in halved, out TField reduced);

		for (int lane = 0; lane < lanes; ++lane)
		{
			SM2Field29.ToField52(in reduced, lane, out elements[lane]);
			prefixes[lane] = elements[lane];

			if (lane is not 0)
			{
				SM2Field52.Multiply(in prefixes[lane - 1], in elements[lane], out prefixes[lane]);
			}
		}

		SM2Field52.InvertVariableTime(in prefixes[lanes - 1], out SM2Field52 inverse);
		Unsafe.SkipInit(out AffinePoint<SM2Field52> point);

		for (int lane = lanes - 1; lane >= 0; --lane)
		{
			if (lane is not 0)
			{
				SM2Field52.Multiply(in inverse, in prefixes[lane - 1], out point.X);
				SM2Field52.Multiply(in inverse, in elements[lane], out inverse);
			}
			else
			{
				point.X = inverse;
			}

			point.Y = point.X;
			SM2Field52.Pack(in point, entries.Slice(lane * EntryLength, EntryLength));
		}

		TField.LoadEntries(in entries[0], out result, out _);
	}

	// Writes the sums of group that are not spare to entry half + m of their window, as SM2Field52.Pack writes them, from the coordinates packed on the lanes.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private static void Scatter<TCurve>(Span<ulong> windows, int half, int group, int count, in TField x, in TField y) where TCurve : struct, IECCurve
	{
		int windowLength = ECGeneratorTable<TCurve, SM2Field52, SM2Order>.WindowLength;
		int shift = BitOperations.Log2((uint)half);
		int lanes = TField.LaneCount;
		Span<ulong> packed = stackalloc ulong[EntryLength * lanes];
		int sums = Math.Min(lanes, count - group * lanes);
		Pack(in x, packed);
		Pack(in y, packed.Slice(EntryLength / 2 * lanes));

		for (int lane = 0; lane < sums; ++lane)
		{
			int sum = group * lanes + lane;
			int window = (sum >> shift) * windowLength;
			int m = (sum & half - 1) + 1;
			Span<ulong> entry = windows.Slice((window + half + m - 1) * EntryLength, EntryLength);

			for (int k = 0; k < EntryLength; ++k)
			{
				entry[k] = packed[k * lanes + lane];
			}
		}
	}

	// The canonical value of each lane of a value as Reduce leaves it, below 2p, in four 64-bit limbs, limb k of lane l at destination[k·LaneCount + l]: one pass finds where v − p borrows, which is where v < p, and the next subtracts p elsewhere and joins the limbs of radix 2^29 as they come, so that few vectors stay live. Two lanes at a time, as every width of TField holds a whole number of pairs.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Pack(in TField value, Span<ulong> destination)
	{
		ref ulong limbs = ref Unsafe.As<TField, ulong>(ref Unsafe.AsRef(in value));
		ref ulong words = ref MemoryMarshal.GetReference(destination);
		nuint lanes = (nuint)TField.LaneCount;
		Vector128<ulong> mask = Vector128.Create(SM2Field29.Mask);
		Vector128<ulong> low = Vector128.Create(SM2Field29.PLow);

		for (nuint lane = 0; lane < lanes; lane += 2)
		{
			ref ulong v = ref Unsafe.Add(ref limbs, lane);
			// Each difference is negative just where it borrows, which bit 63 then holds.
			Vector128<ulong> borrow = Vector128.LoadUnsafe(ref v) - low >> 63;
			borrow = Vector128.LoadUnsafe(ref v, lanes) - low - borrow >> 63;
			borrow = Vector128.LoadUnsafe(ref v, 2 * lanes) - Vector128.Create(SM2Field29.P2) - borrow >> 63;
			borrow = Vector128.LoadUnsafe(ref v, 3 * lanes) - Vector128.Create(SM2Field29.P3) - borrow >> 63;
			borrow = Vector128.LoadUnsafe(ref v, 4 * lanes) - low - borrow >> 63;
			borrow = Vector128.LoadUnsafe(ref v, 5 * lanes) - low - borrow >> 63;
			borrow = Vector128.LoadUnsafe(ref v, 6 * lanes) - low - borrow >> 63;
			borrow = Vector128.LoadUnsafe(ref v, 7 * lanes) - Vector128.Create(SM2Field29.P7) - borrow >> 63;
			borrow = Vector128.LoadUnsafe(ref v, 8 * lanes) - Vector128.Create(SM2Field29.P8) - borrow >> 63;
			// All ones where v ≥ p, which loses p.
			Vector128<ulong> subtract = borrow - Vector128<ulong>.One;
			Vector128<ulong> d0 = Vector128.LoadUnsafe(ref v) - (low & subtract);
			Vector128<ulong> d1 = Vector128.LoadUnsafe(ref v, lanes) - (low & subtract) - (d0 >> 63);
			Vector128<ulong> d2 = Vector128.LoadUnsafe(ref v, 2 * lanes) - (Vector128.Create(SM2Field29.P2) & subtract) - (d1 >> 63);
			(d0 & mask | (d1 & mask) << 29 | d2 << 58).StoreUnsafe(ref words, lane);
			Vector128<ulong> d3 = Vector128.LoadUnsafe(ref v, 3 * lanes) - (Vector128.Create(SM2Field29.P3) & subtract) - (d2 >> 63);
			Vector128<ulong> d4 = Vector128.LoadUnsafe(ref v, 4 * lanes) - (low & subtract) - (d3 >> 63);
			((d2 & mask) >> 6 | (d3 & mask) << 23 | d4 << 52).StoreUnsafe(ref words, lanes + lane);
			Vector128<ulong> d5 = Vector128.LoadUnsafe(ref v, 5 * lanes) - (low & subtract) - (d4 >> 63);
			Vector128<ulong> d6 = Vector128.LoadUnsafe(ref v, 6 * lanes) - (low & subtract) - (d5 >> 63);
			((d4 & mask) >> 12 | (d5 & mask) << 17 | d6 << 46).StoreUnsafe(ref words, 2 * lanes + lane);
			Vector128<ulong> d7 = Vector128.LoadUnsafe(ref v, 7 * lanes) - (Vector128.Create(SM2Field29.P7) & subtract) - (d6 >> 63);
			Vector128<ulong> d8 = Vector128.LoadUnsafe(ref v, 8 * lanes) - (Vector128.Create(SM2Field29.P8) & subtract) - (d7 >> 63);
			((d6 & mask) >> 18 | (d7 & mask) << 11 | d8 << 40).StoreUnsafe(ref words, 3 * lanes + lane);
		}
	}

	// The sum of a table whose folds have left its blocks in lanes first and first + 1, or in lane first alone for one block, with their infinity masks at the same lanes of infinity. The formulas of SM2Field52 add the two lanes, as a fold of single lanes would cost as much as one of all of them. The coordinates must be as Halve and Reduce leave them, which ToField52 reads from each lane as it lies in memory. The point at infinity, for k = 0, comes out as (0, 0, 0), as from ECGroup.MultiplyBase.
	// Like Fold, not inlined, so that one copy serves one table and two, and optimized from the first call, as profile-guided inlining would leave the selects calls.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void Finish(in SM2JacobianLanes<TField> point, Span<ulong> infinity, int first, int blocks, Span<JacobianPoint<SM2Field52>> halves, out JacobianPoint<SM2Field52> result)
	{
		JacobianPoint<SM2Field52> cleared = default;
		int lanes = Math.Min(blocks, 2);

		for (int lane = 0; lane < lanes; ++lane)
		{
			ToJacobian(in point, first + lane, out halves[lane]);
		}

		ulong lowInfinity = infinity[first];

		if (blocks is 1)
		{
			JacobianPoint<SM2Field52>.ConditionalSelect(lowInfinity, in cleared, in halves[0], out result);
			return;
		}

		ulong highInfinity = infinity[first + 1];
		_ = ECGroup<SM2Curve, SM2Field52, SM2Order>.AddDistinct(in halves[0], in halves[1], out halves[2]);
		JacobianPoint<SM2Field52>.ConditionalSelect(lowInfinity, in halves[1], in halves[2], out halves[2]);
		JacobianPoint<SM2Field52>.ConditionalSelect(highInfinity, in halves[0], in halves[2], out halves[2]);
		JacobianPoint<SM2Field52>.ConditionalSelect(lowInfinity & highInfinity, in cleared, in halves[2], out result);
	}

	// Lane lane of a point whose coordinates Halve and Reduce have left as SM2Field52 holds them.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ToJacobian(in SM2JacobianLanes<TField> point, int lane, out JacobianPoint<SM2Field52> result)
	{
		SM2Field29.ToField52(in point.X, lane, out result.X);
		SM2Field29.ToField52(in point.Y, lane, out result.Y);
		SM2Field29.ToField52(in point.Z, lane, out result.Z);
	}

	// The first window of the block of each lane of a table of blocks lanes, lane l taking the block whose index is l with its bits reversed: of 43 windows, blocks of 6, 6, 6, 5, 5, 5, 5 and 5 windows for eight, 11, 11, 11 and 10 for four, 22 and 21 for two and all 43 for one; of 32, blocks of 4, 8, 16 and all 32.
	private static ReadOnlySpan<byte> BlockStarts(int windowCount, int blocks)
	{
		if (windowCount is 43)
		{
			return blocks switch
			{
				8 => [0, 23, 12, 33, 6, 28, 18, 38],
				4 => [0, 22, 11, 33],
				2 => [0, 22],
				_ => [0]
			};
		}

		return blocks switch
		{
			8 => [0, 16, 8, 24, 4, 20, 12, 28],
			4 => [0, 16, 8, 24],
			2 => [0, 16],
			_ => [0]
		};
	}

	private static ReadOnlySpan<byte> BlockLengths(int windowCount, int blocks)
	{
		if (windowCount is 43)
		{
			return blocks switch
			{
				8 => [6, 5, 6, 5, 6, 5, 5, 5],
				4 => [11, 11, 11, 10],
				2 => [22, 21],
				_ => [43]
			};
		}

		return blocks switch
		{
			8 => [4, 4, 4, 4, 4, 4, 4, 4],
			4 => [8, 8, 8, 8],
			2 => [16, 16],
			_ => [32]
		};
	}

	// Each lane l whose bit of distance is clear adds lane l + distance, keeping the other where either holds the point at infinity, so that a fold of two tables stays within the half of each; the other lanes hold sums that the later folds and the result do not read. other and total are scratch points, total in scratch 0 to 2, which Add writes after its last reads of them.
	// Not inlined, so that one copy serves one table and two, and optimized from the first call, as profile-guided inlining of Add would leave the selects calls.
	// ReSharper disable once RedundantAssignment
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void Fold(int distance, ref SM2JacobianLanes<TField> point, ref SM2JacobianLanes<TField> other, ref SM2JacobianLanes<TField> total, Span<ulong> infinity, Span<ulong> otherInfinity, ref TField scratch)
	{
		TField.MoveDown(in point.X, distance, out other.X);
		TField.MoveDown(in point.Y, distance, out other.Y);
		TField.MoveDown(in point.Z, distance, out other.Z);

		for (int lane = 0; lane < TField.LaneCount; ++lane)
		{
			if ((lane & distance) is 0)
			{
				otherInfinity[lane] = infinity[lane + distance];
			}
		}

		Add(in point, in other, ref scratch, out total);
		SM2JacobianLanes<TField>.ConditionalSelect(in infinity[0], in other, in total, out total);
		SM2JacobianLanes<TField>.ConditionalSelect(in otherInfinity[0], in point, in total, out point);

		for (int lane = 0; lane < TField.LaneCount; ++lane)
		{
			if ((lane & distance) is 0)
			{
				infinity[lane] &= otherInfinity[lane];
			}
		}
	}

	// left + (x, y) for an affine right, by ECFormulas.AddDistinct, for lanes that hold neither equal nor opposite points nor the point at infinity on the left: those give (0, 0, 0) and Z = 0, which the callers mask. H and R go through Reduce, below 2p in limbs below u, so that the products of H and R stay below 1.3p: Z1², U2 and Y2·Z1³ are below 1.2p, H² below 1.2p, I = 4H² below 4.5p in limbs below 4u + 260, J and V below 1.3p, Y1·J below 1.1p and 2·Z1·H below 2.3p. H before Reduce has limbs below 3u + 65 and 2R below 6u + 130. The products come in rounds of those that need only the ones before, each round together, by MultiplyRipple and SquareRipple, as no product of a round waits for another; the result must not be the left.
	[SkipLocalsInit]
	private static void MixedAdd(in SM2JacobianLanes<TField> left, in TField x, in TField y, ref TField scratch, out SM2JacobianLanes<TField> result)
	{
		ref TField zz = ref scratch;
		ref TField h = ref Unsafe.Add(ref scratch, 1);
		ref TField r = ref Unsafe.Add(ref scratch, 2);
		ref TField i = ref Unsafe.Add(ref scratch, 3);
		ref TField z3 = ref Unsafe.Add(ref scratch, 4);
		ref TField j = ref Unsafe.Add(ref scratch, 5);
		ref TField v = ref Unsafe.Add(ref scratch, 6);
		TField.SquareRipple(in left.Z, out zz);
		TField.MultiplyRipple(in x, in zz, out h);
		TField.MultiplyRipple(in zz, in left.Z, out zz);
		TField.Subtract(in h, in left.X, out h);
		TField.Reduce(in h, out h);
		TField.MultiplyRipple(in y, in zz, out r);
		TField.SquareRipple(in h, out i);
		TField.MultiplyRipple(in left.Z, in h, out z3);
		TField.Subtract(in r, in left.Y, out r);
		TField.Add(in r, in r, out r);
		TField.Reduce(in r, out r);
		TField.Add(in i, in i, out i);
		TField.Add(in i, in i, out i);
		TField.MultiplyRipple(in h, in i, out j);
		TField.MultiplyRipple(in left.X, in i, out v);
		Combine(in left.Y, in r, in j, in v, ref Unsafe.Add(ref scratch, 7), out result.X, out result.Y);
		TField.Add(in z3, in z3, out result.Z);
	}

	// (x1, y1) + (x2, y2), as MixedAdd gives it for Z1 = 1, without the products by Z1: H, R, I, J and V keep the bounds there, and Z3 = 2H, below 4p, goes through Reduce.
	[SkipLocalsInit]
	private static void AffineAdd(in TField x1, in TField y1, in TField x2, in TField y2, ref TField scratch, out SM2JacobianLanes<TField> result)
	{
		ref TField h = ref scratch;
		ref TField r = ref Unsafe.Add(ref scratch, 1);
		ref TField i = ref Unsafe.Add(ref scratch, 2);
		ref TField j = ref Unsafe.Add(ref scratch, 3);
		ref TField v = ref Unsafe.Add(ref scratch, 4);
		TField.Subtract(in x2, in x1, out h);
		TField.Reduce(in h, out h);
		TField.Subtract(in y2, in y1, out r);
		TField.Add(in r, in r, out r);
		TField.Reduce(in r, out r);
		TField.SquareRipple(in h, out i);
		TField.Add(in i, in i, out i);
		TField.Add(in i, in i, out i);
		TField.MultiplyRipple(in h, in i, out j);
		TField.MultiplyRipple(in x1, in i, out v);
		Combine(in y1, in r, in j, in v, ref Unsafe.Add(ref scratch, 5), out result.X, out result.Y);
		TField.Add(in h, in h, out result.Z);
		TField.Reduce(in result.Z, out result.Z);
	}

	// left + right for lanes that hold neither equal nor opposite points nor the point at infinity, by ECFormulas.AddDistinct; H and R go through Reduce as in MixedAdd, and U1, U2, S1 and S2 stay below 1.1p, J and V below 1.3p, S1·J below 1.1p and 2·Z1·Z2·H below 2.2p. The products come in rounds as in MixedAdd; the result must be neither input, and may be scratch 0 to 2: Z1³ and Z2³ there are read for the last time before X3 and Y3 overwrite them, and Z3 doubles Z1·Z2·H in place.
	[SkipLocalsInit]
	private static void Add(in SM2JacobianLanes<TField> left, in SM2JacobianLanes<TField> right, ref TField scratch, out SM2JacobianLanes<TField> result)
	{
		ref TField z1z1 = ref scratch;
		ref TField z2z2 = ref Unsafe.Add(ref scratch, 1);
		ref TField z3 = ref Unsafe.Add(ref scratch, 2);
		ref TField u1 = ref Unsafe.Add(ref scratch, 3);
		ref TField h = ref Unsafe.Add(ref scratch, 4);
		ref TField s1 = ref Unsafe.Add(ref scratch, 5);
		ref TField r = ref Unsafe.Add(ref scratch, 6);
		ref TField i = ref Unsafe.Add(ref scratch, 7);
		ref TField j = ref Unsafe.Add(ref scratch, 8);
		ref TField v = ref Unsafe.Add(ref scratch, 9);
		TField.SquareRipple(in left.Z, out z1z1);
		TField.SquareRipple(in right.Z, out z2z2);
		TField.MultiplyRipple(in left.Z, in right.Z, out z3);
		TField.MultiplyRipple(in left.X, in z2z2, out u1);
		TField.MultiplyRipple(in right.X, in z1z1, out h);
		TField.MultiplyRipple(in z2z2, in right.Z, out z2z2);
		TField.MultiplyRipple(in z1z1, in left.Z, out z1z1);
		TField.Subtract(in h, in u1, out h);
		TField.Reduce(in h, out h);
		TField.MultiplyRipple(in left.Y, in z2z2, out s1);
		TField.MultiplyRipple(in right.Y, in z1z1, out r);
		TField.SquareRipple(in h, out i);
		TField.MultiplyRipple(in z3, in h, out z3);
		TField.Subtract(in r, in s1, out r);
		TField.Add(in r, in r, out r);
		TField.Reduce(in r, out r);
		TField.Add(in i, in i, out i);
		TField.Add(in i, in i, out i);
		TField.MultiplyRipple(in h, in i, out j);
		TField.MultiplyRipple(in u1, in i, out v);
		Combine(in s1, in r, in j, in v, ref Unsafe.Add(ref scratch, 10), out result.X, out result.Y);
		TField.Add(in z3, in z3, out result.Z);
	}

	// X3 = R² − J − 2V and Y3 = R(V − X3) − 2·S·J, for R below 2p in limbs below u and S, J and V below 1.3p in limbs below u + 65: R² − J − 2V has limbs below 7u + 65 and R(V − X3) − 2·S·J limbs below 5u + 65, which Reduce takes, and V − X3 limbs below 3u + 65. R² goes with the product of the round before, and S·J with R(V − X3).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Combine(in TField s, in TField r, in TField j, in TField v, ref TField scratch, out TField x, out TField y)
	{
		ref TField square = ref scratch;
		ref TField sj = ref Unsafe.Add(ref scratch, 1);
		TField.SquareRipple(in r, out square);
		TField.Subtract(in square, in j, out square);
		TField.Subtract(in square, in v, out square);
		TField.Subtract(in square, in v, out square);
		TField.Reduce(in square, out x);
		TField.MultiplyRipple(in s, in j, out sj);
		TField.Subtract(in v, in x, out square);
		TField.MultiplyRipple(in r, in square, out square);
		TField.Subtract(in square, in sj, out square);
		TField.Subtract(in square, in sj, out square);
		TField.Reduce(in square, out y);
	}

	// Writes the entry of digit in window, the windowLength entries there as ECGeneratorTable packs them, or zeros for a digit of 0; TakesSecondScalar tells whether a second table takes a scalar of its own rather than that of the first.
	private interface ISelector
	{
		static abstract bool TakesSecondScalar { get; }

		static abstract void Select(ref readonly ulong window, int windowLength, int digit, ref ulong entry);
	}

	// Every entry of the window is read, so neither the time nor the addresses depend on the digit.
	private readonly struct MaskedScan : ISelector
	{
		public static bool TakesSecondScalar => false;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void Select(ref readonly ulong window, int windowLength, int digit, ref ulong entry)
		{
			int sign = digit >> 31;
			MaskedSelect.Lookup(in window, EntryLength, windowLength, (uint)((digit ^ sign) - sign) - 1, ref entry);
		}
	}

	// For a public digit, which decides the entry read.
	private readonly struct DirectRead : ISelector
	{
		public static bool TakesSecondScalar => true;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void Select(ref readonly ulong window, int windowLength, int digit, ref ulong entry)
		{
			Span<ulong> destination = MemoryMarshal.CreateSpan(ref entry, EntryLength);

			if (digit is 0)
			{
				destination.Clear();
				return;
			}

			MemoryMarshal.CreateReadOnlySpan(in Unsafe.Add(ref Unsafe.AsRef(in window), (Math.Abs(digit) - 1) * EntryLength), EntryLength).CopyTo(destination);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ref SM2JacobianLanes<TField> AsPoint(ref TField first)
	{
		return ref Unsafe.As<TField, SM2JacobianLanes<TField>>(ref first);
	}

	// The bytes of storage for count values, with room to start them on a 64-byte line.
	private static int StorageLength<T>(int count) where T : unmanaged
	{
		return count * Unsafe.SizeOf<T>() + Alignment - 1;
	}

	// count values in storage of StorageLength<T>(count) bytes, from its first 64-byte line: the stack aligns locals to 16 bytes at most, and the writes of a vector that straddles a line do not forward to the reads of the next product.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static unsafe Span<T> Align<T>(Span<byte> storage, int count) where T : unmanaged
	{
		nint address = (nint)Unsafe.AsPointer(ref MemoryMarshal.GetReference(storage));
		int offset = (int)(-address & Alignment - 1);
		return MemoryMarshal.Cast<byte, T>(storage.Slice(offset, count * Unsafe.SizeOf<T>()));
	}
}
