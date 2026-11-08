namespace CryptoBase.EllipticCurves;

// k·P as two chains of the rounds of SM2QuadFormulas, one in each 256-bit half of SM2Field29x8Avx512, which AVX-512 runs: of the digits of SM2OddWindows, the top chain in lanes 0 to 3 takes digits 26 to 51 and the bottom chain in lanes 4 to 7 digits 0 to 25, each by windows of two DoubleTwice and a DoubleAdd, so that k·P = 2^130·T + B for the sums T and B of the chains. 2^130·T then takes 130 doublings on four lanes, and the rounds of SM2QuadFormulas.AddState add B to it on the same lanes. Each half holds the layouts and the bounds of SM2QuadFormulas, which the permutes and shuffles of Vector512 keep within it.
internal static class SM2OctoFormulas
{
	private const int WindowWidth = SM2OddWindows.Width;

	// P, 3P, …, 31P.
	private const int TableLength = 1 << WindowWidth - 1;

	// The entries of SM2QuadFormulas.BuildTable.
	private const int EntryLength = 25;

	private const int CubeOffset = 10;

	private const int SquareOffset = 20;

	private const int LaneCount = 8;

	private const int HalfCount = 4;

	// The digits of each chain.
	private const int ChainLength = SM2OddWindows.HalfCount;

	// n − 38, the one k at which window 0 of a chain over all the odd digits of k adds equal points, as k ≡ 2d_0 (mod n) for its low digit d_0, which is −19 there.
	private static ReadOnlySpan<ulong> TwiceLowDigit => [0x53BBF40939D540FDUL, 0x7203DF6B21C6052BUL, 0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFEFFFFFFFFUL];

	// No addition of a chain meets equal or opposite points or the point at infinity: before it adds d·P, |d| ≤ 31, a chain holds 32a·P for the sum a of its digits above, odd and at most 32^25 − 1 in size, so 32a ∓ d is odd and below 2^130 < n in size, never a multiple of n. The sums T and B are odd and below 2^130 in size, so neither T·P, 2^130·T·P nor B·P is the point at infinity, as n is prime, and they are opposite just for K ≡ 0, so k = 0, where the sum gives some point and the result is cleared. Equal points need 2^130·T − B = jn, for an odd j as B is odd. For s below n, ⌊s/2^130⌋ < 2^126, which bounds 2^130·T − B to [1 − 2^260, 2^257 − 2^260 − 1], whose only odd multiple of n is −15n; for s in [n, 2n), ⌊s/2^130⌋ lies in [2^126 − 2^95, 2^127), which bounds it to [2^257 − 2^260 − 2^226 + 1, 2^258 − 2^260 − 1], whose only odd multiple of n is −13n. A j leaves B ≡ −jn (mod 2^130) two values in (−2^130, 2^130), of which one makes T odd, so it fixes s and k: −15n gives the exception of SM2OddWindows, whose s takes n more and so falls under −13n, and −13n a k whose s is below n and so falls under −15n. Neither the time nor the addresses depend on k or P, and the intermediates are cleared.
	internal static void Multiply(in AffinePoint<SM2Field52> point, in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> result)
	{
		Multiply<MaskedScan>(in point, in scalar, out result);
	}

	// As Multiply for a public k, from the entries read at the digits, with nothing cleared. The time and the addresses read depend on k.
	internal static void MultiplyVariableTime(in AffinePoint<SM2Field52> point, in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> result)
	{
		Multiply<DirectRead>(in point, in scalar, out result);
	}

	// The windows of Multiply, with the entries that TSelector selects.
	[SkipLocalsInit]
	private static void Multiply<TSelector>(in AffinePoint<SM2Field52> point, in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> result) where TSelector : struct, ISelector
	{
		Span<sbyte> digits = stackalloc sbyte[SM2OddWindows.Count];
		Debug.Assert(digits.Length == 2 * ChainLength);

		Span<ulong> table = stackalloc ulong[TableLength * EntryLength];
		Span<ulong> packed = stackalloc ulong[2 * EntryLength];
		Span<ulong> negative = stackalloc ulong[LaneCount];
		SM2OddWindows.Recode(in scalar, digits);
		BuildTable(in point, table);
		Unsafe.SkipInit(out SM2OctoEntry entry);
		Unsafe.SkipInit(out SM2OctoState state);
		Select<TSelector>(table, digits[^1], digits[ChainLength - 1], packed, negative, out entry);
		FromEntry(in entry, out state);

		for (int i = ChainLength - 2; i >= 0; --i)
		{
			DoubleTwice(ref state);
			DoubleTwice(ref state);
			Select<TSelector>(table, digits[ChainLength + i], digits[i], packed, negative, out entry);
			DoubleAdd(ref state, in entry);
		}

		Split(in state, out SM2QuadState top, out SM2QuadState bottom);
		SM2QuadFormulas.DoubleTwice(ref top, ChainLength * WindowWidth / 2);
		// The sum by the rounds of SM2QuadFormulas.AddState, whose points are neither equal nor opposite but for k = 0.
		SM2QuadFormulas.ToEntry(in bottom, out SM2QuadEntry addend);
		SM2QuadFormulas.AddState(ref top, in addend);
		SM2QuadFormulas.ToJacobian(in top, out result);
		// The point at infinity, for k = 0, comes out as (0, 0, 0), as from ECGroup.Multiply.
		JacobianPoint<SM2Field52> cleared = default;
		JacobianPoint<SM2Field52>.ConditionalSelect(FieldElement<SM2Order>.IsZero(in scalar), in cleared, in result, out result);

		if (!TSelector.ClearsIntermediates)
		{
			return;
		}

		digits.ZeroMemory();
		table.ZeroMemory();
		packed.ZeroMemory();
		negative.ZeroMemory();
		entry.ZeroMemory();
		state.ZeroMemory();
		top.ZeroMemory();
		bottom.ZeroMemory();
		addend.ZeroMemory();
	}

	// Sets result to k·P + l·Q for points P and Q on the curve and k and l below n: a chain in each half, k·P in lanes 0 to 3 and l·Q in lanes 4 to 7, each over all 52 odd digits of its scalar from SM2OddWindows, by windows of two DoubleTwice and a DoubleAdd from the tables of BuildTables, and ECGroup.Add of the two sums.
	// A chain holds a single point, so the argument of Multiply bounds its sums: before it adds d_i·P it holds 32a·P for the sum a of the digits above, and |32a ∓ d_i| < 32^(52 − i) is odd, so below n and never a multiple of n for i ≥ 1. Below that window no doubling meets the point at infinity, as 2^m·a would be a multiple of n with |a| < n. In window 0, 32a·P = −d_0·P just for K ≡ 0, so k = 0, whose opposite points give Z ≡ 0, the point at infinity, and 32a·P = d_0·P just for k ≡ 2d_0 (mod n), at TwiceLowDigit, where 2d_0·P = 64a·P, which DoubleTwice gives from the 16a·P that the chain holds before DoubleAdd, takes the place of the sum under a lane mask. ECGroup.Add takes the sums equal, opposite or at infinity. Neither the time nor the addresses depend on k, l, P or Q, and the intermediates are cleared.
	[SkipLocalsInit]
	internal static void MultiplyAdd(in AffinePoint<SM2Field52> point, in FieldElement<SM2Order> scalar, in AffinePoint<SM2Field52> otherPoint, in FieldElement<SM2Order> otherScalar, out JacobianPoint<SM2Field52> result)
	{
		const int count = SM2OddWindows.Count;
		Span<sbyte> digits = stackalloc sbyte[2 * count];
		Span<ulong> table = stackalloc ulong[TableLength * EntryLength];
		Span<ulong> otherTable = stackalloc ulong[TableLength * EntryLength];
		Span<ulong> packed = stackalloc ulong[2 * EntryLength];
		Span<ulong> masks = stackalloc ulong[2 * LaneCount];
		Span<ulong> negative = masks.Slice(0, LaneCount);
		Span<ulong> equal = masks.Slice(LaneCount, LaneCount);
		SM2OddWindows.Recode(in scalar, digits.Slice(0, count));
		SM2OddWindows.Recode(in otherScalar, digits.Slice(count));
		BuildTables(in point, in otherPoint, table, otherTable);
		Unsafe.SkipInit(out SM2OctoEntry entry);
		Unsafe.SkipInit(out SM2OctoState state);
		SelectTwo(table, otherTable, digits[count - 1], digits[2 * count - 1], packed, negative, out entry);
		FromEntry(in entry, out state);

		for (int i = count - 2; i >= 1; --i)
		{
			DoubleTwice(ref state);
			DoubleTwice(ref state);
			SelectTwo(table, otherTable, digits[i], digits[count + i], packed, negative, out entry);
			DoubleAdd(ref state, in entry);
		}

		DoubleTwice(ref state);
		DoubleTwice(ref state);
		SM2OctoState twice = state;
		DoubleTwice(ref twice);
		SelectTwo(table, otherTable, digits[0], digits[count], packed, negative, out entry);
		DoubleAdd(ref state, in entry);
		equal.Slice(0, HalfCount).Fill(IsTwiceLowDigit(in scalar));
		equal.Slice(HalfCount).Fill(IsTwiceLowDigit(in otherScalar));
		SM2Field29x8Avx512.ConditionalSelect(in equal[0], in twice.P, in state.P, out state.P);
		SM2Field29x8Avx512.ConditionalSelect(in equal[0], in twice.Q, in state.Q, out state.Q);
		Split(in state, out SM2QuadState first, out SM2QuadState second);
		Span<JacobianPoint<SM2Field52>> sums = stackalloc JacobianPoint<SM2Field52>[2];
		SM2QuadFormulas.ToJacobian(in first, out sums[0]);
		SM2QuadFormulas.ToJacobian(in second, out sums[1]);
		ECGroup<SM2Curve, SM2Field52, SM2Order>.Add(in sums[0], in sums[1], out result);
		digits.ZeroMemory();
		table.ZeroMemory();
		otherTable.ZeroMemory();
		packed.ZeroMemory();
		masks.ZeroMemory();
		sums.ZeroMemory();
		entry.ZeroMemory();
		state.ZeroMemory();
		twice.ZeroMemory();
		first.ZeroMemory();
		second.ZeroMemory();
	}

	// Sets first to k·P and second to l·Q for points P and Q on the curve and odd k and l whose ChainLength digits SM2OddWindows.RecodeHalf gives: a chain in each half, k·P in lanes 0 to 3 and l·Q in lanes 4 to 7, by the windows of Multiply from the tables of BuildTables, with the entries read at the digits. The argument of Multiply for each of its chains holds here: no addition meets equal or opposite points or the point at infinity, and neither sum is the point at infinity. Every input is public, so the time and the addresses read depend on them.
	[SkipLocalsInit]
	internal static void MultiplyVariableTime(in AffinePoint<SM2Field52> point, ReadOnlySpan<sbyte> digits, in AffinePoint<SM2Field52> otherPoint, ReadOnlySpan<sbyte> otherDigits, out JacobianPoint<SM2Field52> first, out JacobianPoint<SM2Field52> second)
	{
		Debug.Assert(digits.Length is ChainLength && otherDigits.Length is ChainLength);

		Span<ulong> table = stackalloc ulong[TableLength * EntryLength];
		Span<ulong> otherTable = stackalloc ulong[TableLength * EntryLength];
		Span<ulong> negative = stackalloc ulong[LaneCount];
		BuildTables(in point, in otherPoint, table, otherTable);
		ReadTwo(table, otherTable, digits[ChainLength - 1], otherDigits[ChainLength - 1], negative, out SM2OctoEntry entry);
		FromEntry(in entry, out SM2OctoState state);

		for (int i = ChainLength - 2; i >= 0; --i)
		{
			DoubleTwice(ref state);
			DoubleTwice(ref state);
			ReadTwo(table, otherTable, digits[i], otherDigits[i], negative, out entry);
			DoubleAdd(ref state, in entry);
		}

		Split(in state, out SM2QuadState low, out SM2QuadState high);
		SM2QuadFormulas.ToJacobian(in low, out first);
		SM2QuadFormulas.ToJacobian(in high, out second);
	}

	// Writes (2j + 1)·P to entry j of table and (2j + 1)·Q to entry j of otherTable, in the layout of BuildTable: P and Q, 2P and 2Q by DoubleOnce on four lanes each, and then (2j + 1)·P = (2j − 1)·P + 2P beside the same for Q, one in each half, additions of points neither equal nor opposite, as 2j ± 1 and 2 are below n and 2j − 1 is odd. Each HalfCount multiples of a table go to Pack as they are complete, and Start takes the first steps in a frame of its own, so that this frame stays small. Neither the time nor the addresses depend on P or Q, and the intermediates are cleared.
	[SkipLocalsInit]
	internal static void BuildTables(in AffinePoint<SM2Field52> point, in AffinePoint<SM2Field52> otherPoint, Span<ulong> table, Span<ulong> otherTable)
	{
		Debug.Assert(table.Length == TableLength * EntryLength && otherTable.Length == TableLength * EntryLength);

		Span<SM2QuadState> states = stackalloc SM2QuadState[2 * HalfCount];
		Span<SM2QuadState> multiples = states.Slice(0, HalfCount);
		Span<SM2QuadState> otherMultiples = states.Slice(HalfCount);
		Start(in point, in otherPoint, out multiples[0], out otherMultiples[0], out SM2OctoState state, out SM2OctoEntry step);

		for (int j = 1; j < TableLength; ++j)
		{
			int slot = j & HalfCount - 1;
			AddState(ref state, in step);
			Split(in state, out multiples[slot], out otherMultiples[slot]);

			if (slot is HalfCount - 1)
			{
				int start = (j - slot) * EntryLength;
				SM2QuadFormulas.Pack(multiples, table.Slice(start, HalfCount * EntryLength));
				SM2QuadFormulas.Pack(otherMultiples, otherTable.Slice(start, HalfCount * EntryLength));
			}
		}

		states.ZeroMemory();
		state.ZeroMemory();
		step.ZeroMemory();
	}

	// P and Q, the state of both and the entry of 2P and 2Q for BuildTables, the intermediates cleared.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Start(in AffinePoint<SM2Field52> point, in AffinePoint<SM2Field52> otherPoint, out SM2QuadState first, out SM2QuadState otherFirst, out SM2OctoState state, out SM2OctoEntry step)
	{
		SM2QuadFormulas.ToEntry(in point, out SM2QuadEntry one);
		SM2QuadFormulas.ToEntry(in otherPoint, out SM2QuadEntry otherOne);
		Join(in one, in otherOne, out SM2OctoEntry ones);
		FromEntry(in ones, out state);
		Split(in state, out first, out otherFirst);
		SM2QuadState twice = first;
		SM2QuadFormulas.DoubleOnce(ref twice);
		SM2QuadFormulas.ToEntry(in twice, out SM2QuadEntry two);
		twice = otherFirst;
		SM2QuadFormulas.DoubleOnce(ref twice);
		SM2QuadFormulas.ToEntry(in twice, out SM2QuadEntry otherTwo);
		Join(in two, in otherTwo, out step);
		one.ZeroMemory();
		otherOne.ZeroMemory();
		ones.ZeroMemory();
		twice.ZeroMemory();
		two.ZeroMemory();
		otherTwo.ZeroMemory();
	}

	// The entry of an odd digit of the first chain from table and of the second from otherTable, read at the digits, with Y negated for a digit below 0.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ReadTwo(ReadOnlySpan<ulong> table, ReadOnlySpan<ulong> otherTable, int first, int second, Span<ulong> negative, out SM2OctoEntry entry)
	{
		int firstSign = first >> 31;
		int secondSign = second >> 31;
		ref ulong entries = ref MemoryMarshal.GetReference(table);
		ref ulong otherEntries = ref MemoryMarshal.GetReference(otherTable);
		Unpack(ref Unsafe.Add(ref entries, ((first ^ firstSign) - firstSign >> 1) * EntryLength), ref Unsafe.Add(ref otherEntries, ((second ^ secondSign) - secondSign >> 1) * EntryLength), out entry);
		// Y alone, in lane 2 of each half of EA.
		negative.Clear();
		negative[2] = (ulong)firstSign;
		negative[HalfCount + 2] = (ulong)secondSign;
		SM2Field29x8Avx512.ConditionalNegate(in negative[0], ref entry.EA);
	}

	// ulong.MaxValue for the k of TwiceLowDigit and 0 elsewhere, without branching on k.
	private static ulong IsTwiceLowDigit(in FieldElement<SM2Order> scalar)
	{
		ReadOnlySpan<ulong> k = FieldElement<SM2Order>.GetLimbs(in scalar);
		ReadOnlySpan<ulong> twice = TwiceLowDigit;
		return LimbArithmetic.ZeroMask(k[0] ^ twice[0] | k[1] ^ twice[1] | k[2] ^ twice[2] | k[3] ^ twice[3]);
	}

	// Writes (2j + 1)·P to entry j of the table in the layout of SM2QuadFormulas.BuildTable: P, 2P, 3P = 2P + P and 4P on four lanes, then (j + 4)·P = j·P + 4P for j ≡ 1 and j ≡ 3 (mod 4) side by side, one in each half, additions of points neither equal nor opposite, as j is odd and j + 4 below n. Neither the time nor the addresses depend on P, and the intermediates are cleared.
	[SkipLocalsInit]
	internal static void BuildTable(in AffinePoint<SM2Field52> point, Span<ulong> table)
	{
		Debug.Assert(table.Length == TableLength * EntryLength);

		Span<SM2QuadState> multiples = stackalloc SM2QuadState[TableLength];
		SM2QuadFormulas.ToEntry(in point, out SM2QuadEntry one);
		SM2QuadFormulas.FromEntry(in one, out multiples[0]);
		// 2P and then 4P in entry 2, which the first sums take over.
		multiples[2] = multiples[0];
		SM2QuadFormulas.DoubleOnce(ref multiples[2]);
		multiples[1] = multiples[2];
		SM2QuadFormulas.AddState(ref multiples[1], in one);
		SM2QuadFormulas.DoubleOnce(ref multiples[2]);
		SM2QuadFormulas.ToEntry(in multiples[2], out SM2QuadEntry four);
		Join(in multiples[0], in multiples[1], out SM2OctoState state);
		Join(in four, in four, out SM2OctoEntry step);

		for (int j = 2; j < TableLength; j += 2)
		{
			AddState(ref state, in step);
			Split(in state, out multiples[j], out multiples[j + 1]);
		}

		for (int j = 0; j < TableLength; j += HalfCount)
		{
			SM2QuadFormulas.Pack(multiples.Slice(j, HalfCount), table.Slice(j * EntryLength, HalfCount * EntryLength));
		}

		multiples.ZeroMemory();
		one.ZeroMemory();
		four.ZeroMemory();
		state.ZeroMemory();
		step.ZeroMemory();
	}

	// The states low and high in the halves.
	private static void Join(in SM2QuadState low, in SM2QuadState high, out SM2OctoState result)
	{
		result.P.L0 = Vector512.Create(low.P.L0, high.P.L0);
		result.P.L1 = Vector512.Create(low.P.L1, high.P.L1);
		result.P.L2 = Vector512.Create(low.P.L2, high.P.L2);
		result.P.L3 = Vector512.Create(low.P.L3, high.P.L3);
		result.P.L4 = Vector512.Create(low.P.L4, high.P.L4);
		result.P.L5 = Vector512.Create(low.P.L5, high.P.L5);
		result.P.L6 = Vector512.Create(low.P.L6, high.P.L6);
		result.P.L7 = Vector512.Create(low.P.L7, high.P.L7);
		result.P.L8 = Vector512.Create(low.P.L8, high.P.L8);
		result.Q.L0 = Vector512.Create(low.Q.L0, high.Q.L0);
		result.Q.L1 = Vector512.Create(low.Q.L1, high.Q.L1);
		result.Q.L2 = Vector512.Create(low.Q.L2, high.Q.L2);
		result.Q.L3 = Vector512.Create(low.Q.L3, high.Q.L3);
		result.Q.L4 = Vector512.Create(low.Q.L4, high.Q.L4);
		result.Q.L5 = Vector512.Create(low.Q.L5, high.Q.L5);
		result.Q.L6 = Vector512.Create(low.Q.L6, high.Q.L6);
		result.Q.L7 = Vector512.Create(low.Q.L7, high.Q.L7);
		result.Q.L8 = Vector512.Create(low.Q.L8, high.Q.L8);
	}

	// The entries low and high in the halves.
	private static void Join(in SM2QuadEntry low, in SM2QuadEntry high, out SM2OctoEntry result)
	{
		result.EA.L0 = Vector512.Create(low.EA.L0, high.EA.L0);
		result.EA.L1 = Vector512.Create(low.EA.L1, high.EA.L1);
		result.EA.L2 = Vector512.Create(low.EA.L2, high.EA.L2);
		result.EA.L3 = Vector512.Create(low.EA.L3, high.EA.L3);
		result.EA.L4 = Vector512.Create(low.EA.L4, high.EA.L4);
		result.EA.L5 = Vector512.Create(low.EA.L5, high.EA.L5);
		result.EA.L6 = Vector512.Create(low.EA.L6, high.EA.L6);
		result.EA.L7 = Vector512.Create(low.EA.L7, high.EA.L7);
		result.EA.L8 = Vector512.Create(low.EA.L8, high.EA.L8);
		result.EB.L0 = Vector512.Create(low.EB.L0, high.EB.L0);
		result.EB.L1 = Vector512.Create(low.EB.L1, high.EB.L1);
		result.EB.L2 = Vector512.Create(low.EB.L2, high.EB.L2);
		result.EB.L3 = Vector512.Create(low.EB.L3, high.EB.L3);
		result.EB.L4 = Vector512.Create(low.EB.L4, high.EB.L4);
		result.EB.L5 = Vector512.Create(low.EB.L5, high.EB.L5);
		result.EB.L6 = Vector512.Create(low.EB.L6, high.EB.L6);
		result.EB.L7 = Vector512.Create(low.EB.L7, high.EB.L7);
		result.EB.L8 = Vector512.Create(low.EB.L8, high.EB.L8);
	}

	// The rounds of SM2QuadFormulas.AddState in each half.
	[SkipLocalsInit]
	private static void AddState(ref SM2OctoState state, in SM2OctoEntry entry)
	{
		Unsafe.SkipInit(out SM2Field29x8Avx512 left);
		Unsafe.SkipInit(out SM2Field29x8Avx512 right);
		Unsafe.SkipInit(out SM2Field29x8Avx512 next);
		left.L0 = Blend23(state.Q.L0, Broadcast3(state.P.L0));
		left.L1 = Blend23(state.Q.L1, Broadcast3(state.P.L1));
		left.L2 = Blend23(state.Q.L2, Broadcast3(state.P.L2));
		left.L3 = Blend23(state.Q.L3, Broadcast3(state.P.L3));
		left.L4 = Blend23(state.Q.L4, Broadcast3(state.P.L4));
		left.L5 = Blend23(state.Q.L5, Broadcast3(state.P.L5));
		left.L6 = Blend23(state.Q.L6, Broadcast3(state.P.L6));
		left.L7 = Blend23(state.Q.L7, Broadcast3(state.P.L7));
		left.L8 = Blend23(state.Q.L8, Broadcast3(state.P.L8));
		SM2Field29x8Avx512.Multiply(in left, in entry.EA, out SM2Field29x8Avx512 third);
		// The right of A1, [H, H, δ1, Z2³], carried.
		Vector512<ulong> c0 = third.L0;
		Vector512<ulong> d0 = c0 + Vector512.Create(SM2Field29.FourP0) - Swap(c0);
		left.L0 = Blend23(Blend1(Broadcast3(c0), d0), Blend3(c0, Avx512F.Permute4x64(state.P.L0, 0x40)));
		Vector512<ulong> o0 = Blend3(Blend2(Avx512F.UnpackHigh(d0, d0), Broadcast1(state.Q.L0)), entry.EB.L0);
		right.L0 = o0 & Vector512.Create(SM2Field29.Mask);
		Vector512<ulong> c1 = third.L1;
		Vector512<ulong> d1 = c1 + Vector512.Create(SM2Field29.FourP1) - Swap(c1);
		left.L1 = Blend23(Blend1(Broadcast3(c1), d1), Blend3(c1, Avx512F.Permute4x64(state.P.L1, 0x40)));
		Vector512<ulong> o1 = Blend3(Blend2(Avx512F.UnpackHigh(d1, d1), Broadcast1(state.Q.L1)), entry.EB.L1);
		right.L1 = (o1 & Vector512.Create(SM2Field29.Mask)) + (o0 >> SM2Field29.Bits);
		Vector512<ulong> c2 = third.L2;
		Vector512<ulong> d2 = c2 + Vector512.Create(SM2Field29.FourP2) - Swap(c2);
		left.L2 = Blend23(Blend1(Broadcast3(c2), d2), Blend3(c2, Avx512F.Permute4x64(state.P.L2, 0x40)));
		Vector512<ulong> o2 = Blend3(Blend2(Avx512F.UnpackHigh(d2, d2), Broadcast1(state.Q.L2)), entry.EB.L2);
		right.L2 = (o2 & Vector512.Create(SM2Field29.Mask)) + (o1 >> SM2Field29.Bits);
		Vector512<ulong> c3 = third.L3;
		Vector512<ulong> d3 = c3 + Vector512.Create(SM2Field29.FourP3) - Swap(c3);
		left.L3 = Blend23(Blend1(Broadcast3(c3), d3), Blend3(c3, Avx512F.Permute4x64(state.P.L3, 0x40)));
		Vector512<ulong> o3 = Blend3(Blend2(Avx512F.UnpackHigh(d3, d3), Broadcast1(state.Q.L3)), entry.EB.L3);
		right.L3 = (o3 & Vector512.Create(SM2Field29.Mask)) + (o2 >> SM2Field29.Bits);
		Vector512<ulong> c4 = third.L4;
		Vector512<ulong> d4 = c4 + Vector512.Create(SM2Field29.FourPMiddle) - Swap(c4);
		left.L4 = Blend23(Blend1(Broadcast3(c4), d4), Blend3(c4, Avx512F.Permute4x64(state.P.L4, 0x40)));
		Vector512<ulong> o4 = Blend3(Blend2(Avx512F.UnpackHigh(d4, d4), Broadcast1(state.Q.L4)), entry.EB.L4);
		right.L4 = (o4 & Vector512.Create(SM2Field29.Mask)) + (o3 >> SM2Field29.Bits);
		Vector512<ulong> c5 = third.L5;
		Vector512<ulong> d5 = c5 + Vector512.Create(SM2Field29.FourPMiddle) - Swap(c5);
		left.L5 = Blend23(Blend1(Broadcast3(c5), d5), Blend3(c5, Avx512F.Permute4x64(state.P.L5, 0x40)));
		Vector512<ulong> o5 = Blend3(Blend2(Avx512F.UnpackHigh(d5, d5), Broadcast1(state.Q.L5)), entry.EB.L5);
		right.L5 = (o5 & Vector512.Create(SM2Field29.Mask)) + (o4 >> SM2Field29.Bits);
		Vector512<ulong> c6 = third.L6;
		Vector512<ulong> d6 = c6 + Vector512.Create(SM2Field29.FourPMiddle) - Swap(c6);
		left.L6 = Blend23(Blend1(Broadcast3(c6), d6), Blend3(c6, Avx512F.Permute4x64(state.P.L6, 0x40)));
		Vector512<ulong> o6 = Blend3(Blend2(Avx512F.UnpackHigh(d6, d6), Broadcast1(state.Q.L6)), entry.EB.L6);
		right.L6 = (o6 & Vector512.Create(SM2Field29.Mask)) + (o5 >> SM2Field29.Bits);
		Vector512<ulong> c7 = third.L7;
		Vector512<ulong> d7 = c7 + Vector512.Create(SM2Field29.FourP7) - Swap(c7);
		left.L7 = Blend23(Blend1(Broadcast3(c7), d7), Blend3(c7, Avx512F.Permute4x64(state.P.L7, 0x40)));
		Vector512<ulong> o7 = Blend3(Blend2(Avx512F.UnpackHigh(d7, d7), Broadcast1(state.Q.L7)), entry.EB.L7);
		right.L7 = (o7 & Vector512.Create(SM2Field29.Mask)) + (o6 >> SM2Field29.Bits);
		Vector512<ulong> c8 = third.L8;
		Vector512<ulong> d8 = c8 + Vector512.Create(SM2Field29.FourP8) - Swap(c8);
		left.L8 = Blend23(Blend1(Broadcast3(c8), d8), Blend3(c8, Avx512F.Permute4x64(state.P.L8, 0x40)));
		Vector512<ulong> o8 = Blend3(Blend2(Avx512F.UnpackHigh(d8, d8), Broadcast1(state.Q.L8)), entry.EB.L8);
		right.L8 = o8 + (o7 >> SM2Field29.Bits);
		SM2Field29x8Avx512.Multiply(in left, in right, out SM2Field29x8Avx512 fourth);
		// R carried, in the lanes 2 of both operands of A2; H from lane 1 of the right of A1, read before right takes that of A2.
		Vector512<ulong> b0 = fourth.L0;
		Vector512<ulong> r0 = b0 + Vector512.Create(SM2Field29.FourP0) - Swap(b0);
		Vector512<ulong> q0 = Blend3(r0 & Vector512.Create(SM2Field29.Mask), Broadcast0(b0));
		left.L0 = Blend23(Blend1(third.L0, right.L0), q0);
		right.L0 = Blend23(Avx512F.UnpackHigh(b0, b0), q0);
		Vector512<ulong> b1 = fourth.L1;
		Vector512<ulong> r1 = b1 + Vector512.Create(SM2Field29.FourP1) - Swap(b1);
		Vector512<ulong> q1 = Blend3((r1 & Vector512.Create(SM2Field29.Mask)) + (r0 >> SM2Field29.Bits), Broadcast0(b1));
		left.L1 = Blend23(Blend1(third.L1, right.L1), q1);
		right.L1 = Blend23(Avx512F.UnpackHigh(b1, b1), q1);
		Vector512<ulong> b2 = fourth.L2;
		Vector512<ulong> r2 = b2 + Vector512.Create(SM2Field29.FourP2) - Swap(b2);
		Vector512<ulong> q2 = Blend3((r2 & Vector512.Create(SM2Field29.Mask)) + (r1 >> SM2Field29.Bits), Broadcast0(b2));
		left.L2 = Blend23(Blend1(third.L2, right.L2), q2);
		right.L2 = Blend23(Avx512F.UnpackHigh(b2, b2), q2);
		Vector512<ulong> b3 = fourth.L3;
		Vector512<ulong> r3 = b3 + Vector512.Create(SM2Field29.FourP3) - Swap(b3);
		Vector512<ulong> q3 = Blend3((r3 & Vector512.Create(SM2Field29.Mask)) + (r2 >> SM2Field29.Bits), Broadcast0(b3));
		left.L3 = Blend23(Blend1(third.L3, right.L3), q3);
		right.L3 = Blend23(Avx512F.UnpackHigh(b3, b3), q3);
		Vector512<ulong> b4 = fourth.L4;
		Vector512<ulong> r4 = b4 + Vector512.Create(SM2Field29.FourPMiddle) - Swap(b4);
		Vector512<ulong> q4 = Blend3((r4 & Vector512.Create(SM2Field29.Mask)) + (r3 >> SM2Field29.Bits), Broadcast0(b4));
		left.L4 = Blend23(Blend1(third.L4, right.L4), q4);
		right.L4 = Blend23(Avx512F.UnpackHigh(b4, b4), q4);
		Vector512<ulong> b5 = fourth.L5;
		Vector512<ulong> r5 = b5 + Vector512.Create(SM2Field29.FourPMiddle) - Swap(b5);
		Vector512<ulong> q5 = Blend3((r5 & Vector512.Create(SM2Field29.Mask)) + (r4 >> SM2Field29.Bits), Broadcast0(b5));
		left.L5 = Blend23(Blend1(third.L5, right.L5), q5);
		right.L5 = Blend23(Avx512F.UnpackHigh(b5, b5), q5);
		Vector512<ulong> b6 = fourth.L6;
		Vector512<ulong> r6 = b6 + Vector512.Create(SM2Field29.FourPMiddle) - Swap(b6);
		Vector512<ulong> q6 = Blend3((r6 & Vector512.Create(SM2Field29.Mask)) + (r5 >> SM2Field29.Bits), Broadcast0(b6));
		left.L6 = Blend23(Blend1(third.L6, right.L6), q6);
		right.L6 = Blend23(Avx512F.UnpackHigh(b6, b6), q6);
		Vector512<ulong> b7 = fourth.L7;
		Vector512<ulong> r7 = b7 + Vector512.Create(SM2Field29.FourP7) - Swap(b7);
		Vector512<ulong> q7 = Blend3((r7 & Vector512.Create(SM2Field29.Mask)) + (r6 >> SM2Field29.Bits), Broadcast0(b7));
		left.L7 = Blend23(Blend1(third.L7, right.L7), q7);
		right.L7 = Blend23(Avx512F.UnpackHigh(b7, b7), q7);
		Vector512<ulong> b8 = fourth.L8;
		Vector512<ulong> r8 = b8 + Vector512.Create(SM2Field29.FourP8) - Swap(b8);
		Vector512<ulong> q8 = Blend3(r8 + (r7 >> SM2Field29.Bits), Broadcast0(b8));
		left.L8 = Blend23(Blend1(third.L8, right.L8), q8);
		right.L8 = Blend23(Avx512F.UnpackHigh(b8, b8), q8);
		// fifth and sixth take the buffer of third once no later step reads what it held, so that the frame stays under a page.
		ref SM2Field29x8Avx512 fifth = ref third;
		SM2Field29x8Avx512.Multiply(in left, in right, out fifth);
		Vector512<ulong> e0 = fifth.L0;
		Vector512<ulong> p0 = Broadcast0(e0);
		Vector512<ulong> n0 = Broadcast1(e0);
		next.L0 = e0 + Vector512.Create(3 * SM2Field29.FourP0) - (n0 + (p0 << 1));
		// The right of A3 takes W and H3 here and 3(X + δ) in lane 0 below.
		right.L0 = Blend3((p0 << 1) + p0 + n0 + Vector512.Create(SM2Field29.FourP0) - e0, n0);
		Vector512<ulong> e1 = fifth.L1;
		Vector512<ulong> p1 = Broadcast0(e1);
		Vector512<ulong> n1 = Broadcast1(e1);
		next.L1 = e1 + Vector512.Create(3 * SM2Field29.FourP1) - (n1 + (p1 << 1));
		right.L1 = Blend3((p1 << 1) + p1 + n1 + Vector512.Create(SM2Field29.FourP1) - e1, n1);
		Vector512<ulong> e2 = fifth.L2;
		Vector512<ulong> p2 = Broadcast0(e2);
		Vector512<ulong> n2 = Broadcast1(e2);
		next.L2 = e2 + Vector512.Create(3 * SM2Field29.FourP2) - (n2 + (p2 << 1));
		right.L2 = Blend3((p2 << 1) + p2 + n2 + Vector512.Create(SM2Field29.FourP2) - e2, n2);
		Vector512<ulong> e3 = fifth.L3;
		Vector512<ulong> p3 = Broadcast0(e3);
		Vector512<ulong> n3 = Broadcast1(e3);
		next.L3 = e3 + Vector512.Create(3 * SM2Field29.FourP3) - (n3 + (p3 << 1));
		right.L3 = Blend3((p3 << 1) + p3 + n3 + Vector512.Create(SM2Field29.FourP3) - e3, n3);
		Vector512<ulong> e4 = fifth.L4;
		Vector512<ulong> p4 = Broadcast0(e4);
		Vector512<ulong> n4 = Broadcast1(e4);
		next.L4 = e4 + Vector512.Create(3 * SM2Field29.FourPMiddle) - (n4 + (p4 << 1));
		right.L4 = Blend3((p4 << 1) + p4 + n4 + Vector512.Create(SM2Field29.FourPMiddle) - e4, n4);
		Vector512<ulong> e5 = fifth.L5;
		Vector512<ulong> p5 = Broadcast0(e5);
		Vector512<ulong> n5 = Broadcast1(e5);
		next.L5 = e5 + Vector512.Create(3 * SM2Field29.FourPMiddle) - (n5 + (p5 << 1));
		right.L5 = Blend3((p5 << 1) + p5 + n5 + Vector512.Create(SM2Field29.FourPMiddle) - e5, n5);
		Vector512<ulong> e6 = fifth.L6;
		Vector512<ulong> p6 = Broadcast0(e6);
		Vector512<ulong> n6 = Broadcast1(e6);
		next.L6 = e6 + Vector512.Create(3 * SM2Field29.FourPMiddle) - (n6 + (p6 << 1));
		right.L6 = Blend3((p6 << 1) + p6 + n6 + Vector512.Create(SM2Field29.FourPMiddle) - e6, n6);
		Vector512<ulong> e7 = fifth.L7;
		Vector512<ulong> p7 = Broadcast0(e7);
		Vector512<ulong> n7 = Broadcast1(e7);
		next.L7 = e7 + Vector512.Create(3 * SM2Field29.FourP7) - (n7 + (p7 << 1));
		right.L7 = Blend3((p7 << 1) + p7 + n7 + Vector512.Create(SM2Field29.FourP7) - e7, n7);
		Vector512<ulong> e8 = fifth.L8;
		Vector512<ulong> p8 = Broadcast0(e8);
		Vector512<ulong> n8 = Broadcast1(e8);
		next.L8 = e8 + Vector512.Create(3 * SM2Field29.FourP8) - (n8 + (p8 << 1));
		right.L8 = Blend3((p8 << 1) + p8 + n8 + Vector512.Create(SM2Field29.FourP8) - e8, n8);
		SM2Field29x8Avx512.Reduce(in next, out next);
		// The right of A3 carried.
		Vector512<ulong> x0 = Avx512F.Permute4x64(Blend3(next.L0, fifth.L0), 0xEE);
		Vector512<ulong> m0 = Swap(x0);
		Vector512<ulong> t0 = x0 + m0;
		// The state, whose point no later round reads, keeps the X and δ of the sum in Q, and R comes from lane 2 of the left of A2.
		state.Q.L0 = x0;
		left.L0 = Blend0(Blend3(left.L0, fourth.L0), x0 + Vector512.Create(SM2Field29.FourP0) - m0);
		Vector512<ulong> w0 = Blend0(right.L0, t0 + (t0 << 1));
		right.L0 = w0 & Vector512.Create(SM2Field29.Mask);
		Vector512<ulong> x1 = Avx512F.Permute4x64(Blend3(next.L1, fifth.L1), 0xEE);
		Vector512<ulong> m1 = Swap(x1);
		Vector512<ulong> t1 = x1 + m1;
		state.Q.L1 = x1;
		left.L1 = Blend0(Blend3(left.L1, fourth.L1), x1 + Vector512.Create(SM2Field29.FourP1) - m1);
		Vector512<ulong> w1 = Blend0(right.L1, t1 + (t1 << 1));
		right.L1 = (w1 & Vector512.Create(SM2Field29.Mask)) + (w0 >> SM2Field29.Bits);
		Vector512<ulong> x2 = Avx512F.Permute4x64(Blend3(next.L2, fifth.L2), 0xEE);
		Vector512<ulong> m2 = Swap(x2);
		Vector512<ulong> t2 = x2 + m2;
		state.Q.L2 = x2;
		left.L2 = Blend0(Blend3(left.L2, fourth.L2), x2 + Vector512.Create(SM2Field29.FourP2) - m2);
		Vector512<ulong> w2 = Blend0(right.L2, t2 + (t2 << 1));
		right.L2 = (w2 & Vector512.Create(SM2Field29.Mask)) + (w1 >> SM2Field29.Bits);
		Vector512<ulong> x3 = Avx512F.Permute4x64(Blend3(next.L3, fifth.L3), 0xEE);
		Vector512<ulong> m3 = Swap(x3);
		Vector512<ulong> t3 = x3 + m3;
		state.Q.L3 = x3;
		left.L3 = Blend0(Blend3(left.L3, fourth.L3), x3 + Vector512.Create(SM2Field29.FourP3) - m3);
		Vector512<ulong> w3 = Blend0(right.L3, t3 + (t3 << 1));
		right.L3 = (w3 & Vector512.Create(SM2Field29.Mask)) + (w2 >> SM2Field29.Bits);
		Vector512<ulong> x4 = Avx512F.Permute4x64(Blend3(next.L4, fifth.L4), 0xEE);
		Vector512<ulong> m4 = Swap(x4);
		Vector512<ulong> t4 = x4 + m4;
		state.Q.L4 = x4;
		left.L4 = Blend0(Blend3(left.L4, fourth.L4), x4 + Vector512.Create(SM2Field29.FourPMiddle) - m4);
		Vector512<ulong> w4 = Blend0(right.L4, t4 + (t4 << 1));
		right.L4 = (w4 & Vector512.Create(SM2Field29.Mask)) + (w3 >> SM2Field29.Bits);
		Vector512<ulong> x5 = Avx512F.Permute4x64(Blend3(next.L5, fifth.L5), 0xEE);
		Vector512<ulong> m5 = Swap(x5);
		Vector512<ulong> t5 = x5 + m5;
		state.Q.L5 = x5;
		left.L5 = Blend0(Blend3(left.L5, fourth.L5), x5 + Vector512.Create(SM2Field29.FourPMiddle) - m5);
		Vector512<ulong> w5 = Blend0(right.L5, t5 + (t5 << 1));
		right.L5 = (w5 & Vector512.Create(SM2Field29.Mask)) + (w4 >> SM2Field29.Bits);
		Vector512<ulong> x6 = Avx512F.Permute4x64(Blend3(next.L6, fifth.L6), 0xEE);
		Vector512<ulong> m6 = Swap(x6);
		Vector512<ulong> t6 = x6 + m6;
		state.Q.L6 = x6;
		left.L6 = Blend0(Blend3(left.L6, fourth.L6), x6 + Vector512.Create(SM2Field29.FourPMiddle) - m6);
		Vector512<ulong> w6 = Blend0(right.L6, t6 + (t6 << 1));
		right.L6 = (w6 & Vector512.Create(SM2Field29.Mask)) + (w5 >> SM2Field29.Bits);
		Vector512<ulong> x7 = Avx512F.Permute4x64(Blend3(next.L7, fifth.L7), 0xEE);
		Vector512<ulong> m7 = Swap(x7);
		Vector512<ulong> t7 = x7 + m7;
		state.Q.L7 = x7;
		left.L7 = Blend0(Blend3(left.L7, fourth.L7), x7 + Vector512.Create(SM2Field29.FourP7) - m7);
		Vector512<ulong> w7 = Blend0(right.L7, t7 + (t7 << 1));
		right.L7 = (w7 & Vector512.Create(SM2Field29.Mask)) + (w6 >> SM2Field29.Bits);
		Vector512<ulong> x8 = Avx512F.Permute4x64(Blend3(next.L8, fifth.L8), 0xEE);
		Vector512<ulong> m8 = Swap(x8);
		Vector512<ulong> t8 = x8 + m8;
		state.Q.L8 = x8;
		left.L8 = Blend0(Blend3(left.L8, fourth.L8), x8 + Vector512.Create(SM2Field29.FourP8) - m8);
		Vector512<ulong> w8 = Blend0(right.L8, t8 + (t8 << 1));
		right.L8 = w8 + (w7 >> SM2Field29.Bits);
		ref SM2Field29x8Avx512 sixth = ref third;
		SM2Field29x8Avx512.Multiply(in left, in right, out sixth);
		// Y3 folded, and Y3 and Z3 carried.
		Vector512<ulong> f8 = sixth.L8;
		Vector512<ulong> y8 = f8 + Vector512.Create(SM2Field29.FourP8) - Swap(f8);
		Vector512<ulong> j = y8 >> 24;
		y8 &= Vector512.Create(SM2Field29.TopMask);
		Vector512<ulong> f0 = sixth.L0;
		Vector512<ulong> y0 = f0 + Vector512.Create(SM2Field29.FourP0) - Swap(f0) + j;
		Vector512<ulong> u0 = Blend3(y0, Broadcast0(fourth.L0));
		Vector512<ulong> k0 = state.Q.L0;
		state.P.L0 = Blend2(Avx512F.Permute4x64(Blend0(u0 & Vector512.Create(SM2Field29.Mask), f0), 0xE8), Broadcast0(k0));
		state.Q.L0 = Blend3(k0, Broadcast0(f0));
		Vector512<ulong> f1 = sixth.L1;
		Vector512<ulong> y1 = f1 + Vector512.Create(SM2Field29.FourP1) - Swap(f1);
		Vector512<ulong> u1 = Blend3(y1, Broadcast0(fourth.L1));
		Vector512<ulong> k1 = state.Q.L1;
		state.P.L1 = Blend2(Avx512F.Permute4x64(Blend0((u1 & Vector512.Create(SM2Field29.Mask)) + (u0 >> SM2Field29.Bits), f1), 0xE8), Broadcast0(k1));
		state.Q.L1 = Blend3(k1, Broadcast0(f1));
		Vector512<ulong> f2 = sixth.L2;
		Vector512<ulong> y2 = f2 + Vector512.Create(SM2Field29.FourPFold2) - Swap(f2) - (j << 6);
		Vector512<ulong> u2 = Blend3(y2, Broadcast0(fourth.L2));
		Vector512<ulong> k2 = state.Q.L2;
		state.P.L2 = Blend2(Avx512F.Permute4x64(Blend0((u2 & Vector512.Create(SM2Field29.Mask)) + (u1 >> SM2Field29.Bits), f2), 0xE8), Broadcast0(k2));
		state.Q.L2 = Blend3(k2, Broadcast0(f2));
		Vector512<ulong> f3 = sixth.L3;
		Vector512<ulong> y3 = f3 + Vector512.Create(SM2Field29.FourPFold3) - Swap(f3) + (j << 9);
		Vector512<ulong> u3 = Blend3(y3, Broadcast0(fourth.L3));
		Vector512<ulong> k3 = state.Q.L3;
		state.P.L3 = Blend2(Avx512F.Permute4x64(Blend0((u3 & Vector512.Create(SM2Field29.Mask)) + (u2 >> SM2Field29.Bits), f3), 0xE8), Broadcast0(k3));
		state.Q.L3 = Blend3(k3, Broadcast0(f3));
		Vector512<ulong> f4 = sixth.L4;
		Vector512<ulong> y4 = f4 + Vector512.Create(SM2Field29.FourPMiddle) - Swap(f4);
		Vector512<ulong> u4 = Blend3(y4, Broadcast0(fourth.L4));
		Vector512<ulong> k4 = state.Q.L4;
		state.P.L4 = Blend2(Avx512F.Permute4x64(Blend0((u4 & Vector512.Create(SM2Field29.Mask)) + (u3 >> SM2Field29.Bits), f4), 0xE8), Broadcast0(k4));
		state.Q.L4 = Blend3(k4, Broadcast0(f4));
		Vector512<ulong> f5 = sixth.L5;
		Vector512<ulong> y5 = f5 + Vector512.Create(SM2Field29.FourPMiddle) - Swap(f5);
		Vector512<ulong> u5 = Blend3(y5, Broadcast0(fourth.L5));
		Vector512<ulong> k5 = state.Q.L5;
		state.P.L5 = Blend2(Avx512F.Permute4x64(Blend0((u5 & Vector512.Create(SM2Field29.Mask)) + (u4 >> SM2Field29.Bits), f5), 0xE8), Broadcast0(k5));
		state.Q.L5 = Blend3(k5, Broadcast0(f5));
		Vector512<ulong> f6 = sixth.L6;
		Vector512<ulong> y6 = f6 + Vector512.Create(SM2Field29.FourPMiddle) - Swap(f6);
		Vector512<ulong> u6 = Blend3(y6, Broadcast0(fourth.L6));
		Vector512<ulong> k6 = state.Q.L6;
		state.P.L6 = Blend2(Avx512F.Permute4x64(Blend0((u6 & Vector512.Create(SM2Field29.Mask)) + (u5 >> SM2Field29.Bits), f6), 0xE8), Broadcast0(k6));
		state.Q.L6 = Blend3(k6, Broadcast0(f6));
		Vector512<ulong> f7 = sixth.L7;
		Vector512<ulong> y7 = f7 + Vector512.Create(SM2Field29.FourP7) - Swap(f7) + (j << 21);
		Vector512<ulong> u7 = Blend3(y7, Broadcast0(fourth.L7));
		Vector512<ulong> k7 = state.Q.L7;
		state.P.L7 = Blend2(Avx512F.Permute4x64(Blend0((u7 & Vector512.Create(SM2Field29.Mask)) + (u6 >> SM2Field29.Bits), f7), 0xE8), Broadcast0(k7));
		state.Q.L7 = Blend3(k7, Broadcast0(f7));
		Vector512<ulong> u8 = Blend3(y8, Broadcast0(fourth.L8));
		Vector512<ulong> k8 = state.Q.L8;
		state.P.L8 = Blend2(Avx512F.Permute4x64(Blend0(u8 + (u7 >> SM2Field29.Bits), f8), 0xE8), Broadcast0(k8));
		state.Q.L8 = Blend3(k8, Broadcast0(f8));
	}

	// The states of the halves.
	private static void Split(in SM2OctoState state, out SM2QuadState low, out SM2QuadState high)
	{
		low.P.L0 = state.P.L0.GetLower();
		high.P.L0 = state.P.L0.GetUpper();
		low.P.L1 = state.P.L1.GetLower();
		high.P.L1 = state.P.L1.GetUpper();
		low.P.L2 = state.P.L2.GetLower();
		high.P.L2 = state.P.L2.GetUpper();
		low.P.L3 = state.P.L3.GetLower();
		high.P.L3 = state.P.L3.GetUpper();
		low.P.L4 = state.P.L4.GetLower();
		high.P.L4 = state.P.L4.GetUpper();
		low.P.L5 = state.P.L5.GetLower();
		high.P.L5 = state.P.L5.GetUpper();
		low.P.L6 = state.P.L6.GetLower();
		high.P.L6 = state.P.L6.GetUpper();
		low.P.L7 = state.P.L7.GetLower();
		high.P.L7 = state.P.L7.GetUpper();
		low.P.L8 = state.P.L8.GetLower();
		high.P.L8 = state.P.L8.GetUpper();
		low.Q.L0 = state.Q.L0.GetLower();
		high.Q.L0 = state.Q.L0.GetUpper();
		low.Q.L1 = state.Q.L1.GetLower();
		high.Q.L1 = state.Q.L1.GetUpper();
		low.Q.L2 = state.Q.L2.GetLower();
		high.Q.L2 = state.Q.L2.GetUpper();
		low.Q.L3 = state.Q.L3.GetLower();
		high.Q.L3 = state.Q.L3.GetUpper();
		low.Q.L4 = state.Q.L4.GetLower();
		high.Q.L4 = state.Q.L4.GetUpper();
		low.Q.L5 = state.Q.L5.GetLower();
		high.Q.L5 = state.Q.L5.GetUpper();
		low.Q.L6 = state.Q.L6.GetLower();
		high.Q.L6 = state.Q.L6.GetUpper();
		low.Q.L7 = state.Q.L7.GetLower();
		high.Q.L7 = state.Q.L7.GetUpper();
		low.Q.L8 = state.Q.L8.GetLower();
		high.Q.L8 = state.Q.L8.GetUpper();
	}

	// The rounds of SM2QuadFormulas.FromEntry in each half.
	[SkipLocalsInit]
	internal static void FromEntry(in SM2OctoEntry entry, out SM2OctoState state)
	{
		Unsafe.SkipInit(out state);
		Unsafe.SkipInit(out SM2Field29x8Avx512 left);
		Unsafe.SkipInit(out SM2Field29x8Avx512 right);
		Vector512<ulong> b0 = entry.EB.L0;
		Vector512<ulong> s0 = Swap(b0);
		Vector512<ulong> t0 = b0 + s0;
		left.L0 = b0 + Vector512.Create(SM2Field29.FourP0) - s0;
		Vector512<ulong> m0 = t0 + (t0 << 1);
		right.L0 = m0 & Vector512.Create(SM2Field29.Mask);
		Vector512<ulong> b1 = entry.EB.L1;
		Vector512<ulong> s1 = Swap(b1);
		Vector512<ulong> t1 = b1 + s1;
		left.L1 = b1 + Vector512.Create(SM2Field29.FourP1) - s1;
		Vector512<ulong> m1 = t1 + (t1 << 1);
		right.L1 = (m1 & Vector512.Create(SM2Field29.Mask)) + (m0 >> SM2Field29.Bits);
		Vector512<ulong> b2 = entry.EB.L2;
		Vector512<ulong> s2 = Swap(b2);
		Vector512<ulong> t2 = b2 + s2;
		left.L2 = b2 + Vector512.Create(SM2Field29.FourP2) - s2;
		Vector512<ulong> m2 = t2 + (t2 << 1);
		right.L2 = (m2 & Vector512.Create(SM2Field29.Mask)) + (m1 >> SM2Field29.Bits);
		Vector512<ulong> b3 = entry.EB.L3;
		Vector512<ulong> s3 = Swap(b3);
		Vector512<ulong> t3 = b3 + s3;
		left.L3 = b3 + Vector512.Create(SM2Field29.FourP3) - s3;
		Vector512<ulong> m3 = t3 + (t3 << 1);
		right.L3 = (m3 & Vector512.Create(SM2Field29.Mask)) + (m2 >> SM2Field29.Bits);
		Vector512<ulong> b4 = entry.EB.L4;
		Vector512<ulong> s4 = Swap(b4);
		Vector512<ulong> t4 = b4 + s4;
		left.L4 = b4 + Vector512.Create(SM2Field29.FourPMiddle) - s4;
		Vector512<ulong> m4 = t4 + (t4 << 1);
		right.L4 = (m4 & Vector512.Create(SM2Field29.Mask)) + (m3 >> SM2Field29.Bits);
		Vector512<ulong> b5 = entry.EB.L5;
		Vector512<ulong> s5 = Swap(b5);
		Vector512<ulong> t5 = b5 + s5;
		left.L5 = b5 + Vector512.Create(SM2Field29.FourPMiddle) - s5;
		Vector512<ulong> m5 = t5 + (t5 << 1);
		right.L5 = (m5 & Vector512.Create(SM2Field29.Mask)) + (m4 >> SM2Field29.Bits);
		Vector512<ulong> b6 = entry.EB.L6;
		Vector512<ulong> s6 = Swap(b6);
		Vector512<ulong> t6 = b6 + s6;
		left.L6 = b6 + Vector512.Create(SM2Field29.FourPMiddle) - s6;
		Vector512<ulong> m6 = t6 + (t6 << 1);
		right.L6 = (m6 & Vector512.Create(SM2Field29.Mask)) + (m5 >> SM2Field29.Bits);
		Vector512<ulong> b7 = entry.EB.L7;
		Vector512<ulong> s7 = Swap(b7);
		Vector512<ulong> t7 = b7 + s7;
		left.L7 = b7 + Vector512.Create(SM2Field29.FourP7) - s7;
		Vector512<ulong> m7 = t7 + (t7 << 1);
		right.L7 = (m7 & Vector512.Create(SM2Field29.Mask)) + (m6 >> SM2Field29.Bits);
		Vector512<ulong> b8 = entry.EB.L8;
		Vector512<ulong> s8 = Swap(b8);
		Vector512<ulong> t8 = b8 + s8;
		left.L8 = b8 + Vector512.Create(SM2Field29.FourP8) - s8;
		Vector512<ulong> m8 = t8 + (t8 << 1);
		right.L8 = m8 + (m7 >> SM2Field29.Bits);
		SM2Field29x8Avx512.Multiply(in left, in right, out SM2Field29x8Avx512 alpha);
		state.P.L0 = Blend0(Avx512F.Permute4x64(entry.EA.L0, 0xD8), alpha.L0);
		state.Q.L0 = Blend3(entry.EB.L0, Broadcast0(alpha.L0));
		state.P.L1 = Blend0(Avx512F.Permute4x64(entry.EA.L1, 0xD8), alpha.L1);
		state.Q.L1 = Blend3(entry.EB.L1, Broadcast0(alpha.L1));
		state.P.L2 = Blend0(Avx512F.Permute4x64(entry.EA.L2, 0xD8), alpha.L2);
		state.Q.L2 = Blend3(entry.EB.L2, Broadcast0(alpha.L2));
		state.P.L3 = Blend0(Avx512F.Permute4x64(entry.EA.L3, 0xD8), alpha.L3);
		state.Q.L3 = Blend3(entry.EB.L3, Broadcast0(alpha.L3));
		state.P.L4 = Blend0(Avx512F.Permute4x64(entry.EA.L4, 0xD8), alpha.L4);
		state.Q.L4 = Blend3(entry.EB.L4, Broadcast0(alpha.L4));
		state.P.L5 = Blend0(Avx512F.Permute4x64(entry.EA.L5, 0xD8), alpha.L5);
		state.Q.L5 = Blend3(entry.EB.L5, Broadcast0(alpha.L5));
		state.P.L6 = Blend0(Avx512F.Permute4x64(entry.EA.L6, 0xD8), alpha.L6);
		state.Q.L6 = Blend3(entry.EB.L6, Broadcast0(alpha.L6));
		state.P.L7 = Blend0(Avx512F.Permute4x64(entry.EA.L7, 0xD8), alpha.L7);
		state.Q.L7 = Blend3(entry.EB.L7, Broadcast0(alpha.L7));
		state.P.L8 = Blend0(Avx512F.Permute4x64(entry.EA.L8, 0xD8), alpha.L8);
		state.Q.L8 = Blend3(entry.EB.L8, Broadcast0(alpha.L8));
	}

	// The rounds of SM2QuadFormulas.DoubleTwice in each half.
	[SkipLocalsInit]
	internal static void DoubleTwice(ref SM2OctoState state)
	{
		Unsafe.SkipInit(out SM2OctoScratch5 scratch);
		ref SM2Field29x8Avx512 left = ref AlignedScratch.Start<SM2OctoScratch5, SM2Field29x8Avx512>(ref scratch);
		ref SM2Field29x8Avx512 right = ref Unsafe.Add(ref left, 1);
		ref SM2Field29x8Avx512 first = ref Unsafe.Add(ref left, 2);
		ref SM2Field29x8Avx512 second = ref Unsafe.Add(ref left, 3);
		ref SM2Field29x8Avx512 third = ref Unsafe.Add(ref left, 4);
		left.L0 = Avx512F.Permute4x64(state.P.L0, 0x44);
		left.L1 = Avx512F.Permute4x64(state.P.L1, 0x44);
		left.L2 = Avx512F.Permute4x64(state.P.L2, 0x44);
		left.L3 = Avx512F.Permute4x64(state.P.L3, 0x44);
		left.L4 = Avx512F.Permute4x64(state.P.L4, 0x44);
		left.L5 = Avx512F.Permute4x64(state.P.L5, 0x44);
		left.L6 = Avx512F.Permute4x64(state.P.L6, 0x44);
		left.L7 = Avx512F.Permute4x64(state.P.L7, 0x44);
		left.L8 = Avx512F.Permute4x64(state.P.L8, 0x44);
		SM2Field29x8Avx512.Multiply(in left, in state.P, out first);
		// The right of E1, [8γ, 4γ, 4γ, A], carried; T takes 2γ from it before.
		Vector512<ulong> a0 = first.L0;
		Vector512<ulong> g0 = Avx512F.ShiftLeftLogicalVariable(Avx512F.Permute4x64(a0, 0x15), Vector512.Create(3UL, 2, 2, 0, 3, 2, 2, 0));
		left.L0 = Blend2(state.Q.L0, a0 + (a0 << 1) + Vector512.Create(2 * SM2Field29.FourP0) - (g0 >> 1));
		right.L0 = g0 & Vector512.Create(SM2Field29.Mask);
		Vector512<ulong> a1 = first.L1;
		Vector512<ulong> g1 = Avx512F.ShiftLeftLogicalVariable(Avx512F.Permute4x64(a1, 0x15), Vector512.Create(3UL, 2, 2, 0, 3, 2, 2, 0));
		left.L1 = Blend2(state.Q.L1, a1 + (a1 << 1) + Vector512.Create(2 * SM2Field29.FourP1) - (g1 >> 1));
		right.L1 = (g1 & Vector512.Create(SM2Field29.Mask)) + (g0 >> SM2Field29.Bits);
		Vector512<ulong> a2 = first.L2;
		Vector512<ulong> g2 = Avx512F.ShiftLeftLogicalVariable(Avx512F.Permute4x64(a2, 0x15), Vector512.Create(3UL, 2, 2, 0, 3, 2, 2, 0));
		left.L2 = Blend2(state.Q.L2, a2 + (a2 << 1) + Vector512.Create(2 * SM2Field29.FourP2) - (g2 >> 1));
		right.L2 = (g2 & Vector512.Create(SM2Field29.Mask)) + (g1 >> SM2Field29.Bits);
		Vector512<ulong> a3 = first.L3;
		Vector512<ulong> g3 = Avx512F.ShiftLeftLogicalVariable(Avx512F.Permute4x64(a3, 0x15), Vector512.Create(3UL, 2, 2, 0, 3, 2, 2, 0));
		left.L3 = Blend2(state.Q.L3, a3 + (a3 << 1) + Vector512.Create(2 * SM2Field29.FourP3) - (g3 >> 1));
		right.L3 = (g3 & Vector512.Create(SM2Field29.Mask)) + (g2 >> SM2Field29.Bits);
		Vector512<ulong> a4 = first.L4;
		Vector512<ulong> g4 = Avx512F.ShiftLeftLogicalVariable(Avx512F.Permute4x64(a4, 0x15), Vector512.Create(3UL, 2, 2, 0, 3, 2, 2, 0));
		left.L4 = Blend2(state.Q.L4, a4 + (a4 << 1) + Vector512.Create(2 * SM2Field29.FourPMiddle) - (g4 >> 1));
		right.L4 = (g4 & Vector512.Create(SM2Field29.Mask)) + (g3 >> SM2Field29.Bits);
		Vector512<ulong> a5 = first.L5;
		Vector512<ulong> g5 = Avx512F.ShiftLeftLogicalVariable(Avx512F.Permute4x64(a5, 0x15), Vector512.Create(3UL, 2, 2, 0, 3, 2, 2, 0));
		left.L5 = Blend2(state.Q.L5, a5 + (a5 << 1) + Vector512.Create(2 * SM2Field29.FourPMiddle) - (g5 >> 1));
		right.L5 = (g5 & Vector512.Create(SM2Field29.Mask)) + (g4 >> SM2Field29.Bits);
		Vector512<ulong> a6 = first.L6;
		Vector512<ulong> g6 = Avx512F.ShiftLeftLogicalVariable(Avx512F.Permute4x64(a6, 0x15), Vector512.Create(3UL, 2, 2, 0, 3, 2, 2, 0));
		left.L6 = Blend2(state.Q.L6, a6 + (a6 << 1) + Vector512.Create(2 * SM2Field29.FourPMiddle) - (g6 >> 1));
		right.L6 = (g6 & Vector512.Create(SM2Field29.Mask)) + (g5 >> SM2Field29.Bits);
		Vector512<ulong> a7 = first.L7;
		Vector512<ulong> g7 = Avx512F.ShiftLeftLogicalVariable(Avx512F.Permute4x64(a7, 0x15), Vector512.Create(3UL, 2, 2, 0, 3, 2, 2, 0));
		left.L7 = Blend2(state.Q.L7, a7 + (a7 << 1) + Vector512.Create(2 * SM2Field29.FourP7) - (g7 >> 1));
		right.L7 = (g7 & Vector512.Create(SM2Field29.Mask)) + (g6 >> SM2Field29.Bits);
		Vector512<ulong> a8 = first.L8;
		Vector512<ulong> g8 = Avx512F.ShiftLeftLogicalVariable(Avx512F.Permute4x64(a8, 0x15), Vector512.Create(3UL, 2, 2, 0, 3, 2, 2, 0));
		left.L8 = Blend2(state.Q.L8, a8 + (a8 << 1) + Vector512.Create(2 * SM2Field29.FourP8) - (g8 >> 1));
		right.L8 = g8 + (g7 >> SM2Field29.Bits);
		SM2Field29x8Avx512.Multiply(in left, in right, out second);
		// X′ and Y′ folded, and the right of O0, [3(X′ + δ′), X′, Y′, Z′], carried.
		Vector512<ulong> s8 = Swap(second.L8);
		Vector512<ulong> v8 = Blend23(first.L8, second.L8) + Vector512.Create(SM2Field29.FourP8) - Blend23(second.L8, s8);
		Vector512<ulong> h = v8 >> 24;
		v8 &= Vector512.Create(SM2Field29.TopMask);
		Vector512<ulong> s0 = Swap(second.L0);
		Vector512<ulong> v0 = Blend23(first.L0, second.L0) + Vector512.Create(SM2Field29.FourP0) - Blend23(second.L0, s0) + h;
		Vector512<ulong> w0 = Avx512F.UnpackLow(v0, v0);
		Vector512<ulong> t0 = w0 + s0;
		left.L0 = Blend0(w0, w0 + Vector512.Create(SM2Field29.FourP0) - s0);
		Vector512<ulong> m0 = Blend3(Blend0(w0, t0 + (t0 << 1)), first.L0 << 1);
		right.L0 = m0 & Vector512.Create(SM2Field29.Mask);
		Vector512<ulong> s1 = Swap(second.L1);
		Vector512<ulong> v1 = Blend23(first.L1, second.L1) + Vector512.Create(SM2Field29.FourP1) - Blend23(second.L1, s1);
		Vector512<ulong> w1 = Avx512F.UnpackLow(v1, v1);
		Vector512<ulong> t1 = w1 + s1;
		left.L1 = Blend0(w1, w1 + Vector512.Create(SM2Field29.FourP1) - s1);
		Vector512<ulong> m1 = Blend3(Blend0(w1, t1 + (t1 << 1)), first.L1 << 1);
		right.L1 = (m1 & Vector512.Create(SM2Field29.Mask)) + (m0 >> SM2Field29.Bits);
		Vector512<ulong> s2 = Swap(second.L2);
		Vector512<ulong> v2 = Blend23(first.L2, second.L2) + Vector512.Create(SM2Field29.FourPFold2) - Blend23(second.L2, s2) - (h << 6);
		Vector512<ulong> w2 = Avx512F.UnpackLow(v2, v2);
		Vector512<ulong> t2 = w2 + s2;
		left.L2 = Blend0(w2, w2 + Vector512.Create(SM2Field29.FourP2) - s2);
		Vector512<ulong> m2 = Blend3(Blend0(w2, t2 + (t2 << 1)), first.L2 << 1);
		right.L2 = (m2 & Vector512.Create(SM2Field29.Mask)) + (m1 >> SM2Field29.Bits);
		Vector512<ulong> s3 = Swap(second.L3);
		Vector512<ulong> v3 = Blend23(first.L3, second.L3) + Vector512.Create(SM2Field29.FourPFold3) - Blend23(second.L3, s3) + (h << 9);
		Vector512<ulong> w3 = Avx512F.UnpackLow(v3, v3);
		Vector512<ulong> t3 = w3 + s3;
		left.L3 = Blend0(w3, w3 + Vector512.Create(SM2Field29.FourP3) - s3);
		Vector512<ulong> m3 = Blend3(Blend0(w3, t3 + (t3 << 1)), first.L3 << 1);
		right.L3 = (m3 & Vector512.Create(SM2Field29.Mask)) + (m2 >> SM2Field29.Bits);
		Vector512<ulong> s4 = Swap(second.L4);
		Vector512<ulong> v4 = Blend23(first.L4, second.L4) + Vector512.Create(SM2Field29.FourPMiddle) - Blend23(second.L4, s4);
		Vector512<ulong> w4 = Avx512F.UnpackLow(v4, v4);
		Vector512<ulong> t4 = w4 + s4;
		left.L4 = Blend0(w4, w4 + Vector512.Create(SM2Field29.FourPMiddle) - s4);
		Vector512<ulong> m4 = Blend3(Blend0(w4, t4 + (t4 << 1)), first.L4 << 1);
		right.L4 = (m4 & Vector512.Create(SM2Field29.Mask)) + (m3 >> SM2Field29.Bits);
		Vector512<ulong> s5 = Swap(second.L5);
		Vector512<ulong> v5 = Blend23(first.L5, second.L5) + Vector512.Create(SM2Field29.FourPMiddle) - Blend23(second.L5, s5);
		Vector512<ulong> w5 = Avx512F.UnpackLow(v5, v5);
		Vector512<ulong> t5 = w5 + s5;
		left.L5 = Blend0(w5, w5 + Vector512.Create(SM2Field29.FourPMiddle) - s5);
		Vector512<ulong> m5 = Blend3(Blend0(w5, t5 + (t5 << 1)), first.L5 << 1);
		right.L5 = (m5 & Vector512.Create(SM2Field29.Mask)) + (m4 >> SM2Field29.Bits);
		Vector512<ulong> s6 = Swap(second.L6);
		Vector512<ulong> v6 = Blend23(first.L6, second.L6) + Vector512.Create(SM2Field29.FourPMiddle) - Blend23(second.L6, s6);
		Vector512<ulong> w6 = Avx512F.UnpackLow(v6, v6);
		Vector512<ulong> t6 = w6 + s6;
		left.L6 = Blend0(w6, w6 + Vector512.Create(SM2Field29.FourPMiddle) - s6);
		Vector512<ulong> m6 = Blend3(Blend0(w6, t6 + (t6 << 1)), first.L6 << 1);
		right.L6 = (m6 & Vector512.Create(SM2Field29.Mask)) + (m5 >> SM2Field29.Bits);
		Vector512<ulong> s7 = Swap(second.L7);
		Vector512<ulong> v7 = Blend23(first.L7, second.L7) + Vector512.Create(SM2Field29.FourP7) - Blend23(second.L7, s7) + (h << 21);
		Vector512<ulong> w7 = Avx512F.UnpackLow(v7, v7);
		Vector512<ulong> t7 = w7 + s7;
		left.L7 = Blend0(w7, w7 + Vector512.Create(SM2Field29.FourP7) - s7);
		Vector512<ulong> m7 = Blend3(Blend0(w7, t7 + (t7 << 1)), first.L7 << 1);
		right.L7 = (m7 & Vector512.Create(SM2Field29.Mask)) + (m6 >> SM2Field29.Bits);
		Vector512<ulong> w8 = Avx512F.UnpackLow(v8, v8);
		Vector512<ulong> t8 = w8 + s8;
		left.L8 = Blend0(w8, w8 + Vector512.Create(SM2Field29.FourP8) - s8);
		Vector512<ulong> m8 = Blend3(Blend0(w8, t8 + (t8 << 1)), first.L8 << 1);
		right.L8 = m8 + (m7 >> SM2Field29.Bits);
		SM2Field29x8Avx512.Multiply(in left, in right, out third);
		// gamma and fifth take the buffer of first, fourth that of second and carried that of left, each once no later step reads what it held, so that the frame stays under a page. gamma holds [α′, α′, 8γ′, 4γ′] as O2 takes it, and carried the same carried for O1. The right of O1, [X′, α′, X′, δ′], takes X′ from lane 1 of the left of O0 and δ′ from lane 1 of second.
		ref SM2Field29x8Avx512 gamma = ref first;
		ref SM2Field29x8Avx512 carried = ref left;
		Vector512<ulong> d0 = Avx512F.UnpackLow(third.L0, third.L0);
		Vector512<ulong> e0 = Avx512F.ShiftLeftLogicalVariable(d0, Vector512.Create(0UL, 0, 3, 2, 0, 0, 3, 2));
		gamma.L0 = e0;
		right.L0 = Blend1(Avx512F.Permute4x64(Avx512F.UnpackHigh(left.L0, second.L0), 0x40), d0);
		carried.L0 = e0 & Vector512.Create(SM2Field29.Mask);
		Vector512<ulong> d1 = Avx512F.UnpackLow(third.L1, third.L1);
		Vector512<ulong> e1 = Avx512F.ShiftLeftLogicalVariable(d1, Vector512.Create(0UL, 0, 3, 2, 0, 0, 3, 2));
		gamma.L1 = e1;
		right.L1 = Blend1(Avx512F.Permute4x64(Avx512F.UnpackHigh(left.L1, second.L1), 0x40), d1);
		carried.L1 = (e1 & Vector512.Create(SM2Field29.Mask)) + (e0 >> SM2Field29.Bits);
		Vector512<ulong> d2 = Avx512F.UnpackLow(third.L2, third.L2);
		Vector512<ulong> e2 = Avx512F.ShiftLeftLogicalVariable(d2, Vector512.Create(0UL, 0, 3, 2, 0, 0, 3, 2));
		gamma.L2 = e2;
		right.L2 = Blend1(Avx512F.Permute4x64(Avx512F.UnpackHigh(left.L2, second.L2), 0x40), d2);
		carried.L2 = (e2 & Vector512.Create(SM2Field29.Mask)) + (e1 >> SM2Field29.Bits);
		Vector512<ulong> d3 = Avx512F.UnpackLow(third.L3, third.L3);
		Vector512<ulong> e3 = Avx512F.ShiftLeftLogicalVariable(d3, Vector512.Create(0UL, 0, 3, 2, 0, 0, 3, 2));
		gamma.L3 = e3;
		right.L3 = Blend1(Avx512F.Permute4x64(Avx512F.UnpackHigh(left.L3, second.L3), 0x40), d3);
		carried.L3 = (e3 & Vector512.Create(SM2Field29.Mask)) + (e2 >> SM2Field29.Bits);
		Vector512<ulong> d4 = Avx512F.UnpackLow(third.L4, third.L4);
		Vector512<ulong> e4 = Avx512F.ShiftLeftLogicalVariable(d4, Vector512.Create(0UL, 0, 3, 2, 0, 0, 3, 2));
		gamma.L4 = e4;
		right.L4 = Blend1(Avx512F.Permute4x64(Avx512F.UnpackHigh(left.L4, second.L4), 0x40), d4);
		carried.L4 = (e4 & Vector512.Create(SM2Field29.Mask)) + (e3 >> SM2Field29.Bits);
		Vector512<ulong> d5 = Avx512F.UnpackLow(third.L5, third.L5);
		Vector512<ulong> e5 = Avx512F.ShiftLeftLogicalVariable(d5, Vector512.Create(0UL, 0, 3, 2, 0, 0, 3, 2));
		gamma.L5 = e5;
		right.L5 = Blend1(Avx512F.Permute4x64(Avx512F.UnpackHigh(left.L5, second.L5), 0x40), d5);
		carried.L5 = (e5 & Vector512.Create(SM2Field29.Mask)) + (e4 >> SM2Field29.Bits);
		Vector512<ulong> d6 = Avx512F.UnpackLow(third.L6, third.L6);
		Vector512<ulong> e6 = Avx512F.ShiftLeftLogicalVariable(d6, Vector512.Create(0UL, 0, 3, 2, 0, 0, 3, 2));
		gamma.L6 = e6;
		right.L6 = Blend1(Avx512F.Permute4x64(Avx512F.UnpackHigh(left.L6, second.L6), 0x40), d6);
		carried.L6 = (e6 & Vector512.Create(SM2Field29.Mask)) + (e5 >> SM2Field29.Bits);
		Vector512<ulong> d7 = Avx512F.UnpackLow(third.L7, third.L7);
		Vector512<ulong> e7 = Avx512F.ShiftLeftLogicalVariable(d7, Vector512.Create(0UL, 0, 3, 2, 0, 0, 3, 2));
		gamma.L7 = e7;
		right.L7 = Blend1(Avx512F.Permute4x64(Avx512F.UnpackHigh(left.L7, second.L7), 0x40), d7);
		carried.L7 = (e7 & Vector512.Create(SM2Field29.Mask)) + (e6 >> SM2Field29.Bits);
		Vector512<ulong> d8 = Avx512F.UnpackLow(third.L8, third.L8);
		Vector512<ulong> e8 = Avx512F.ShiftLeftLogicalVariable(d8, Vector512.Create(0UL, 0, 3, 2, 0, 0, 3, 2));
		gamma.L8 = e8;
		right.L8 = Blend1(Avx512F.Permute4x64(Avx512F.UnpackHigh(left.L8, second.L8), 0x40), d8);
		carried.L8 = e8 + (e7 >> SM2Field29.Bits);
		ref SM2Field29x8Avx512 fourth = ref second;
		SM2Field29x8Avx512.Multiply(in carried, in right, out fourth);
		// X″ folded, and the right of O2, [4γ′, α′, 3(X″ + δ″), 4γ′], carried.
		Vector512<ulong> b8 = fourth.L8;
		Vector512<ulong> x8 = Avx512F.Permute4x64(b8, 0xD4) + Vector512.Create(SM2Field29.FourP8) - b8;
		Vector512<ulong> k = x8 >> 24;
		x8 &= Vector512.Create(SM2Field29.TopMask);
		Vector512<ulong> b0 = fourth.L0;
		Vector512<ulong> x0 = Avx512F.Permute4x64(b0, 0xD4) + Vector512.Create(SM2Field29.FourP0) - b0 + k;
		Vector512<ulong> r0 = Avx512F.Permute4x64(gamma.L0, 0xE7);
		Vector512<ulong> n0 = Swap(b0);
		Vector512<ulong> q0 = x0 + n0;
		// The state, whose point no later round reads, takes [X″, δ″, X″, δ″] in Q, whose lane 3 takes α″ after O2.
		state.Q.L0 = Avx512F.Permute4x64(Blend3(x0, b0), 0xEE);
		Vector512<ulong> o0 = Blend2(r0, q0 + (q0 << 1));
		right.L0 = o0 & Vector512.Create(SM2Field29.Mask);
		left.L0 = Blend2(Blend1(b0 + (b0 << 1) + Vector512.Create(2 * SM2Field29.FourP0) - (r0 >> 1), b0), x0 + Vector512.Create(SM2Field29.FourP0) - n0);
		Vector512<ulong> b1 = fourth.L1;
		Vector512<ulong> x1 = Avx512F.Permute4x64(b1, 0xD4) + Vector512.Create(SM2Field29.FourP1) - b1;
		Vector512<ulong> r1 = Avx512F.Permute4x64(gamma.L1, 0xE7);
		Vector512<ulong> n1 = Swap(b1);
		Vector512<ulong> q1 = x1 + n1;
		state.Q.L1 = Avx512F.Permute4x64(Blend3(x1, b1), 0xEE);
		Vector512<ulong> o1 = Blend2(r1, q1 + (q1 << 1));
		right.L1 = (o1 & Vector512.Create(SM2Field29.Mask)) + (o0 >> SM2Field29.Bits);
		left.L1 = Blend2(Blend1(b1 + (b1 << 1) + Vector512.Create(2 * SM2Field29.FourP1) - (r1 >> 1), b1), x1 + Vector512.Create(SM2Field29.FourP1) - n1);
		Vector512<ulong> b2 = fourth.L2;
		Vector512<ulong> x2 = Avx512F.Permute4x64(b2, 0xD4) + Vector512.Create(SM2Field29.FourPFold2) - b2 - (k << 6);
		Vector512<ulong> r2 = Avx512F.Permute4x64(gamma.L2, 0xE7);
		Vector512<ulong> n2 = Swap(b2);
		Vector512<ulong> q2 = x2 + n2;
		state.Q.L2 = Avx512F.Permute4x64(Blend3(x2, b2), 0xEE);
		Vector512<ulong> o2 = Blend2(r2, q2 + (q2 << 1));
		right.L2 = (o2 & Vector512.Create(SM2Field29.Mask)) + (o1 >> SM2Field29.Bits);
		left.L2 = Blend2(Blend1(b2 + (b2 << 1) + Vector512.Create(2 * SM2Field29.FourP2) - (r2 >> 1), b2), x2 + Vector512.Create(SM2Field29.FourP2) - n2);
		Vector512<ulong> b3 = fourth.L3;
		Vector512<ulong> x3 = Avx512F.Permute4x64(b3, 0xD4) + Vector512.Create(SM2Field29.FourPFold3) - b3 + (k << 9);
		Vector512<ulong> r3 = Avx512F.Permute4x64(gamma.L3, 0xE7);
		Vector512<ulong> n3 = Swap(b3);
		Vector512<ulong> q3 = x3 + n3;
		state.Q.L3 = Avx512F.Permute4x64(Blend3(x3, b3), 0xEE);
		Vector512<ulong> o3 = Blend2(r3, q3 + (q3 << 1));
		right.L3 = (o3 & Vector512.Create(SM2Field29.Mask)) + (o2 >> SM2Field29.Bits);
		left.L3 = Blend2(Blend1(b3 + (b3 << 1) + Vector512.Create(2 * SM2Field29.FourP3) - (r3 >> 1), b3), x3 + Vector512.Create(SM2Field29.FourP3) - n3);
		Vector512<ulong> b4 = fourth.L4;
		Vector512<ulong> x4 = Avx512F.Permute4x64(b4, 0xD4) + Vector512.Create(SM2Field29.FourPMiddle) - b4;
		Vector512<ulong> r4 = Avx512F.Permute4x64(gamma.L4, 0xE7);
		Vector512<ulong> n4 = Swap(b4);
		Vector512<ulong> q4 = x4 + n4;
		state.Q.L4 = Avx512F.Permute4x64(Blend3(x4, b4), 0xEE);
		Vector512<ulong> o4 = Blend2(r4, q4 + (q4 << 1));
		right.L4 = (o4 & Vector512.Create(SM2Field29.Mask)) + (o3 >> SM2Field29.Bits);
		left.L4 = Blend2(Blend1(b4 + (b4 << 1) + Vector512.Create(2 * SM2Field29.FourPMiddle) - (r4 >> 1), b4), x4 + Vector512.Create(SM2Field29.FourPMiddle) - n4);
		Vector512<ulong> b5 = fourth.L5;
		Vector512<ulong> x5 = Avx512F.Permute4x64(b5, 0xD4) + Vector512.Create(SM2Field29.FourPMiddle) - b5;
		Vector512<ulong> r5 = Avx512F.Permute4x64(gamma.L5, 0xE7);
		Vector512<ulong> n5 = Swap(b5);
		Vector512<ulong> q5 = x5 + n5;
		state.Q.L5 = Avx512F.Permute4x64(Blend3(x5, b5), 0xEE);
		Vector512<ulong> o5 = Blend2(r5, q5 + (q5 << 1));
		right.L5 = (o5 & Vector512.Create(SM2Field29.Mask)) + (o4 >> SM2Field29.Bits);
		left.L5 = Blend2(Blend1(b5 + (b5 << 1) + Vector512.Create(2 * SM2Field29.FourPMiddle) - (r5 >> 1), b5), x5 + Vector512.Create(SM2Field29.FourPMiddle) - n5);
		Vector512<ulong> b6 = fourth.L6;
		Vector512<ulong> x6 = Avx512F.Permute4x64(b6, 0xD4) + Vector512.Create(SM2Field29.FourPMiddle) - b6;
		Vector512<ulong> r6 = Avx512F.Permute4x64(gamma.L6, 0xE7);
		Vector512<ulong> n6 = Swap(b6);
		Vector512<ulong> q6 = x6 + n6;
		state.Q.L6 = Avx512F.Permute4x64(Blend3(x6, b6), 0xEE);
		Vector512<ulong> o6 = Blend2(r6, q6 + (q6 << 1));
		right.L6 = (o6 & Vector512.Create(SM2Field29.Mask)) + (o5 >> SM2Field29.Bits);
		left.L6 = Blend2(Blend1(b6 + (b6 << 1) + Vector512.Create(2 * SM2Field29.FourPMiddle) - (r6 >> 1), b6), x6 + Vector512.Create(SM2Field29.FourPMiddle) - n6);
		Vector512<ulong> b7 = fourth.L7;
		Vector512<ulong> x7 = Avx512F.Permute4x64(b7, 0xD4) + Vector512.Create(SM2Field29.FourP7) - b7 + (k << 21);
		Vector512<ulong> r7 = Avx512F.Permute4x64(gamma.L7, 0xE7);
		Vector512<ulong> n7 = Swap(b7);
		Vector512<ulong> q7 = x7 + n7;
		state.Q.L7 = Avx512F.Permute4x64(Blend3(x7, b7), 0xEE);
		Vector512<ulong> o7 = Blend2(r7, q7 + (q7 << 1));
		right.L7 = (o7 & Vector512.Create(SM2Field29.Mask)) + (o6 >> SM2Field29.Bits);
		left.L7 = Blend2(Blend1(b7 + (b7 << 1) + Vector512.Create(2 * SM2Field29.FourP7) - (r7 >> 1), b7), x7 + Vector512.Create(SM2Field29.FourP7) - n7);
		Vector512<ulong> r8 = Avx512F.Permute4x64(gamma.L8, 0xE7);
		Vector512<ulong> n8 = Swap(b8);
		Vector512<ulong> q8 = x8 + n8;
		state.Q.L8 = Avx512F.Permute4x64(Blend3(x8, b8), 0xEE);
		Vector512<ulong> o8 = Blend2(r8, q8 + (q8 << 1));
		right.L8 = o8 + (o7 >> SM2Field29.Bits);
		left.L8 = Blend2(Blend1(b8 + (b8 << 1) + Vector512.Create(2 * SM2Field29.FourP8) - (r8 >> 1), b8), x8 + Vector512.Create(SM2Field29.FourP8) - n8);
		ref SM2Field29x8Avx512 fifth = ref first;
		SM2Field29x8Avx512.Multiply(in left, in right, out fifth);
		// Y″ folded and carried.
		Vector512<ulong> c8 = fifth.L8;
		Vector512<ulong> f8 = Swap(c8);
		Vector512<ulong> y8 = c8 + Vector512.Create(SM2Field29.FourP8) - f8;
		Vector512<ulong> j = y8 >> 24;
		y8 &= Vector512.Create(SM2Field29.TopMask);
		Vector512<ulong> c0 = fifth.L0;
		Vector512<ulong> f0 = Swap(c0);
		Vector512<ulong> y0 = c0 + Vector512.Create(SM2Field29.FourP0) - f0 + j;
		Vector512<ulong> z0 = state.Q.L0;
		state.P.L0 = Blend3(Blend2(Avx512F.Permute4x64(Blend2(y0 & Vector512.Create(SM2Field29.Mask), c0), 0xE2), z0), third.L0 << 1);
		state.Q.L0 = Blend3(z0, f0);
		Vector512<ulong> c1 = fifth.L1;
		Vector512<ulong> f1 = Swap(c1);
		Vector512<ulong> y1 = c1 + Vector512.Create(SM2Field29.FourP1) - f1;
		Vector512<ulong> z1 = state.Q.L1;
		state.P.L1 = Blend3(Blend2(Avx512F.Permute4x64(Blend2((y1 & Vector512.Create(SM2Field29.Mask)) + (y0 >> SM2Field29.Bits), c1), 0xE2), z1), third.L1 << 1);
		state.Q.L1 = Blend3(z1, f1);
		Vector512<ulong> c2 = fifth.L2;
		Vector512<ulong> f2 = Swap(c2);
		Vector512<ulong> y2 = c2 + Vector512.Create(SM2Field29.FourPFold2) - f2 - (j << 6);
		Vector512<ulong> z2 = state.Q.L2;
		state.P.L2 = Blend3(Blend2(Avx512F.Permute4x64(Blend2((y2 & Vector512.Create(SM2Field29.Mask)) + (y1 >> SM2Field29.Bits), c2), 0xE2), z2), third.L2 << 1);
		state.Q.L2 = Blend3(z2, f2);
		Vector512<ulong> c3 = fifth.L3;
		Vector512<ulong> f3 = Swap(c3);
		Vector512<ulong> y3 = c3 + Vector512.Create(SM2Field29.FourPFold3) - f3 + (j << 9);
		Vector512<ulong> z3 = state.Q.L3;
		state.P.L3 = Blend3(Blend2(Avx512F.Permute4x64(Blend2((y3 & Vector512.Create(SM2Field29.Mask)) + (y2 >> SM2Field29.Bits), c3), 0xE2), z3), third.L3 << 1);
		state.Q.L3 = Blend3(z3, f3);
		Vector512<ulong> c4 = fifth.L4;
		Vector512<ulong> f4 = Swap(c4);
		Vector512<ulong> y4 = c4 + Vector512.Create(SM2Field29.FourPMiddle) - f4;
		Vector512<ulong> z4 = state.Q.L4;
		state.P.L4 = Blend3(Blend2(Avx512F.Permute4x64(Blend2((y4 & Vector512.Create(SM2Field29.Mask)) + (y3 >> SM2Field29.Bits), c4), 0xE2), z4), third.L4 << 1);
		state.Q.L4 = Blend3(z4, f4);
		Vector512<ulong> c5 = fifth.L5;
		Vector512<ulong> f5 = Swap(c5);
		Vector512<ulong> y5 = c5 + Vector512.Create(SM2Field29.FourPMiddle) - f5;
		Vector512<ulong> z5 = state.Q.L5;
		state.P.L5 = Blend3(Blend2(Avx512F.Permute4x64(Blend2((y5 & Vector512.Create(SM2Field29.Mask)) + (y4 >> SM2Field29.Bits), c5), 0xE2), z5), third.L5 << 1);
		state.Q.L5 = Blend3(z5, f5);
		Vector512<ulong> c6 = fifth.L6;
		Vector512<ulong> f6 = Swap(c6);
		Vector512<ulong> y6 = c6 + Vector512.Create(SM2Field29.FourPMiddle) - f6;
		Vector512<ulong> z6 = state.Q.L6;
		state.P.L6 = Blend3(Blend2(Avx512F.Permute4x64(Blend2((y6 & Vector512.Create(SM2Field29.Mask)) + (y5 >> SM2Field29.Bits), c6), 0xE2), z6), third.L6 << 1);
		state.Q.L6 = Blend3(z6, f6);
		Vector512<ulong> c7 = fifth.L7;
		Vector512<ulong> f7 = Swap(c7);
		Vector512<ulong> y7 = c7 + Vector512.Create(SM2Field29.FourP7) - f7 + (j << 21);
		Vector512<ulong> z7 = state.Q.L7;
		state.P.L7 = Blend3(Blend2(Avx512F.Permute4x64(Blend2((y7 & Vector512.Create(SM2Field29.Mask)) + (y6 >> SM2Field29.Bits), c7), 0xE2), z7), third.L7 << 1);
		state.Q.L7 = Blend3(z7, f7);
		Vector512<ulong> z8 = state.Q.L8;
		state.P.L8 = Blend3(Blend2(Avx512F.Permute4x64(Blend2(y8 + (y7 >> SM2Field29.Bits), c8), 0xE2), z8), third.L8 << 1);
		state.Q.L8 = Blend3(z8, f8);
	}

	// The rounds of SM2QuadFormulas.DoubleAdd in each half, without its masks: every lane takes the sum.
	[SkipLocalsInit]
	internal static void DoubleAdd(ref SM2OctoState state, in SM2OctoEntry entry)
	{
		Unsafe.SkipInit(out SM2Field29x8Avx512 left);
		Unsafe.SkipInit(out SM2Field29x8Avx512 right);
		Unsafe.SkipInit(out SM2Field29x8Avx512 next);
		Vector512<ulong> mask = Vector512.Create(SM2Field29.Mask);
		Vector512<ulong> top = Vector512.Create(SM2Field29.TopMask);
		Vector512<ulong> evenShifts = Vector512.Create(3UL, 2, 2, 0, 3, 2, 2, 0);
		left.L0 = Avx512F.Permute4x64(state.P.L0, 0x44);
		left.L1 = Avx512F.Permute4x64(state.P.L1, 0x44);
		left.L2 = Avx512F.Permute4x64(state.P.L2, 0x44);
		left.L3 = Avx512F.Permute4x64(state.P.L3, 0x44);
		left.L4 = Avx512F.Permute4x64(state.P.L4, 0x44);
		left.L5 = Avx512F.Permute4x64(state.P.L5, 0x44);
		left.L6 = Avx512F.Permute4x64(state.P.L6, 0x44);
		left.L7 = Avx512F.Permute4x64(state.P.L7, 0x44);
		left.L8 = Avx512F.Permute4x64(state.P.L8, 0x44);
		SM2Field29x8Avx512.Multiply(in left, in state.P, out SM2Field29x8Avx512 first);
		Vector512<ulong> a0 = first.L0;
		Vector512<ulong> g0 = Avx512F.ShiftLeftLogicalVariable(Avx512F.Permute4x64(a0, 0x15), evenShifts);
		left.L0 = Blend2(state.Q.L0, a0 + (a0 << 1) + Vector512.Create(2 * SM2Field29.FourP0) - (g0 >> 1));
		right.L0 = g0 & mask;
		Vector512<ulong> a1 = first.L1;
		Vector512<ulong> g1 = Avx512F.ShiftLeftLogicalVariable(Avx512F.Permute4x64(a1, 0x15), evenShifts);
		left.L1 = Blend2(state.Q.L1, a1 + (a1 << 1) + Vector512.Create(2 * SM2Field29.FourP1) - (g1 >> 1));
		right.L1 = (g1 & mask) + (g0 >> SM2Field29.Bits);
		Vector512<ulong> a2 = first.L2;
		Vector512<ulong> g2 = Avx512F.ShiftLeftLogicalVariable(Avx512F.Permute4x64(a2, 0x15), evenShifts);
		left.L2 = Blend2(state.Q.L2, a2 + (a2 << 1) + Vector512.Create(2 * SM2Field29.FourP2) - (g2 >> 1));
		right.L2 = (g2 & mask) + (g1 >> SM2Field29.Bits);
		Vector512<ulong> a3 = first.L3;
		Vector512<ulong> g3 = Avx512F.ShiftLeftLogicalVariable(Avx512F.Permute4x64(a3, 0x15), evenShifts);
		left.L3 = Blend2(state.Q.L3, a3 + (a3 << 1) + Vector512.Create(2 * SM2Field29.FourP3) - (g3 >> 1));
		right.L3 = (g3 & mask) + (g2 >> SM2Field29.Bits);
		Vector512<ulong> a4 = first.L4;
		Vector512<ulong> g4 = Avx512F.ShiftLeftLogicalVariable(Avx512F.Permute4x64(a4, 0x15), evenShifts);
		left.L4 = Blend2(state.Q.L4, a4 + (a4 << 1) + Vector512.Create(2 * SM2Field29.FourPMiddle) - (g4 >> 1));
		right.L4 = (g4 & mask) + (g3 >> SM2Field29.Bits);
		Vector512<ulong> a5 = first.L5;
		Vector512<ulong> g5 = Avx512F.ShiftLeftLogicalVariable(Avx512F.Permute4x64(a5, 0x15), evenShifts);
		left.L5 = Blend2(state.Q.L5, a5 + (a5 << 1) + Vector512.Create(2 * SM2Field29.FourPMiddle) - (g5 >> 1));
		right.L5 = (g5 & mask) + (g4 >> SM2Field29.Bits);
		Vector512<ulong> a6 = first.L6;
		Vector512<ulong> g6 = Avx512F.ShiftLeftLogicalVariable(Avx512F.Permute4x64(a6, 0x15), evenShifts);
		left.L6 = Blend2(state.Q.L6, a6 + (a6 << 1) + Vector512.Create(2 * SM2Field29.FourPMiddle) - (g6 >> 1));
		right.L6 = (g6 & mask) + (g5 >> SM2Field29.Bits);
		Vector512<ulong> a7 = first.L7;
		Vector512<ulong> g7 = Avx512F.ShiftLeftLogicalVariable(Avx512F.Permute4x64(a7, 0x15), evenShifts);
		left.L7 = Blend2(state.Q.L7, a7 + (a7 << 1) + Vector512.Create(2 * SM2Field29.FourP7) - (g7 >> 1));
		right.L7 = (g7 & mask) + (g6 >> SM2Field29.Bits);
		Vector512<ulong> a8 = first.L8;
		Vector512<ulong> g8 = Avx512F.ShiftLeftLogicalVariable(Avx512F.Permute4x64(a8, 0x15), evenShifts);
		left.L8 = Blend2(state.Q.L8, a8 + (a8 << 1) + Vector512.Create(2 * SM2Field29.FourP8) - (g8 >> 1));
		right.L8 = g8 + (g7 >> SM2Field29.Bits);
		SM2Field29x8Avx512.Multiply(in left, in right, out SM2Field29x8Avx512 second);
		Vector512<ulong> s8 = Swap(second.L8);
		Vector512<ulong> v8 = Blend23(first.L8, second.L8) + Vector512.Create(SM2Field29.FourP8) - Blend23(second.L8, s8);
		Vector512<ulong> h = v8 >> 24;
		v8 &= top;
		Vector512<ulong> s0 = Swap(second.L0);
		Vector512<ulong> v0 = Blend23(first.L0, second.L0) + Vector512.Create(SM2Field29.FourP0) - Blend23(second.L0, s0) + h;
		Vector512<ulong> z0 = first.L0 << 1;
		// The state, whose point no later round reads, keeps [X′, ·, Y′, Z′] of the double in P for the Y′ of A1, which takes δ′ from lane 1 of second before A1 writes over it.
		state.P.L0 = Blend3(v0, z0);
		left.L0 = Blend1(Blend23(v0, Avx512F.UnpackHigh(z0, z0)), second.L0);
		Vector512<ulong> s1 = Swap(second.L1);
		Vector512<ulong> v1 = Blend23(first.L1, second.L1) + Vector512.Create(SM2Field29.FourP1) - Blend23(second.L1, s1);
		Vector512<ulong> z1 = first.L1 << 1;
		state.P.L1 = Blend3(v1, z1);
		left.L1 = Blend1(Blend23(v1, Avx512F.UnpackHigh(z1, z1)), second.L1);
		Vector512<ulong> s2 = Swap(second.L2);
		Vector512<ulong> v2 = Blend23(first.L2, second.L2) + Vector512.Create(SM2Field29.FourPFold2) - Blend23(second.L2, s2) - (h << 6);
		Vector512<ulong> z2 = first.L2 << 1;
		state.P.L2 = Blend3(v2, z2);
		left.L2 = Blend1(Blend23(v2, Avx512F.UnpackHigh(z2, z2)), second.L2);
		Vector512<ulong> s3 = Swap(second.L3);
		Vector512<ulong> v3 = Blend23(first.L3, second.L3) + Vector512.Create(SM2Field29.FourPFold3) - Blend23(second.L3, s3) + (h << 9);
		Vector512<ulong> z3 = first.L3 << 1;
		state.P.L3 = Blend3(v3, z3);
		left.L3 = Blend1(Blend23(v3, Avx512F.UnpackHigh(z3, z3)), second.L3);
		Vector512<ulong> s4 = Swap(second.L4);
		Vector512<ulong> v4 = Blend23(first.L4, second.L4) + Vector512.Create(SM2Field29.FourPMiddle) - Blend23(second.L4, s4);
		Vector512<ulong> z4 = first.L4 << 1;
		state.P.L4 = Blend3(v4, z4);
		left.L4 = Blend1(Blend23(v4, Avx512F.UnpackHigh(z4, z4)), second.L4);
		Vector512<ulong> s5 = Swap(second.L5);
		Vector512<ulong> v5 = Blend23(first.L5, second.L5) + Vector512.Create(SM2Field29.FourPMiddle) - Blend23(second.L5, s5);
		Vector512<ulong> z5 = first.L5 << 1;
		state.P.L5 = Blend3(v5, z5);
		left.L5 = Blend1(Blend23(v5, Avx512F.UnpackHigh(z5, z5)), second.L5);
		Vector512<ulong> s6 = Swap(second.L6);
		Vector512<ulong> v6 = Blend23(first.L6, second.L6) + Vector512.Create(SM2Field29.FourPMiddle) - Blend23(second.L6, s6);
		Vector512<ulong> z6 = first.L6 << 1;
		state.P.L6 = Blend3(v6, z6);
		left.L6 = Blend1(Blend23(v6, Avx512F.UnpackHigh(z6, z6)), second.L6);
		Vector512<ulong> s7 = Swap(second.L7);
		Vector512<ulong> v7 = Blend23(first.L7, second.L7) + Vector512.Create(SM2Field29.FourP7) - Blend23(second.L7, s7) + (h << 21);
		Vector512<ulong> z7 = first.L7 << 1;
		state.P.L7 = Blend3(v7, z7);
		left.L7 = Blend1(Blend23(v7, Avx512F.UnpackHigh(z7, z7)), second.L7);
		Vector512<ulong> z8 = first.L8 << 1;
		state.P.L8 = Blend3(v8, z8);
		left.L8 = Blend1(Blend23(v8, Avx512F.UnpackHigh(z8, z8)), second.L8);
		// third, fifth and sixth take the buffer of first, and fourth that of second, each once no later step reads what it held, so that the frame stays under a page.
		ref SM2Field29x8Avx512 third = ref first;
		SM2Field29x8Avx512.Multiply(in left, in entry.EA, out third);
		// The right of A1, [H, H, δ1, Z2³], carried.
		Vector512<ulong> c0 = third.L0;
		Vector512<ulong> d0 = c0 + Vector512.Create(SM2Field29.FourP0) - Swap(c0);
		left.L0 = Blend23(Blend1(Broadcast3(c0), d0), Blend3(c0, Swap(state.P.L0)));
		Vector512<ulong> o0 = Blend3(Blend2(Avx512F.UnpackHigh(d0, d0), Broadcast1(second.L0)), entry.EB.L0);
		right.L0 = o0 & mask;
		Vector512<ulong> c1 = third.L1;
		Vector512<ulong> d1 = c1 + Vector512.Create(SM2Field29.FourP1) - Swap(c1);
		left.L1 = Blend23(Blend1(Broadcast3(c1), d1), Blend3(c1, Swap(state.P.L1)));
		Vector512<ulong> o1 = Blend3(Blend2(Avx512F.UnpackHigh(d1, d1), Broadcast1(second.L1)), entry.EB.L1);
		right.L1 = (o1 & mask) + (o0 >> SM2Field29.Bits);
		Vector512<ulong> c2 = third.L2;
		Vector512<ulong> d2 = c2 + Vector512.Create(SM2Field29.FourP2) - Swap(c2);
		left.L2 = Blend23(Blend1(Broadcast3(c2), d2), Blend3(c2, Swap(state.P.L2)));
		Vector512<ulong> o2 = Blend3(Blend2(Avx512F.UnpackHigh(d2, d2), Broadcast1(second.L2)), entry.EB.L2);
		right.L2 = (o2 & mask) + (o1 >> SM2Field29.Bits);
		Vector512<ulong> c3 = third.L3;
		Vector512<ulong> d3 = c3 + Vector512.Create(SM2Field29.FourP3) - Swap(c3);
		left.L3 = Blend23(Blend1(Broadcast3(c3), d3), Blend3(c3, Swap(state.P.L3)));
		Vector512<ulong> o3 = Blend3(Blend2(Avx512F.UnpackHigh(d3, d3), Broadcast1(second.L3)), entry.EB.L3);
		right.L3 = (o3 & mask) + (o2 >> SM2Field29.Bits);
		Vector512<ulong> c4 = third.L4;
		Vector512<ulong> d4 = c4 + Vector512.Create(SM2Field29.FourPMiddle) - Swap(c4);
		left.L4 = Blend23(Blend1(Broadcast3(c4), d4), Blend3(c4, Swap(state.P.L4)));
		Vector512<ulong> o4 = Blend3(Blend2(Avx512F.UnpackHigh(d4, d4), Broadcast1(second.L4)), entry.EB.L4);
		right.L4 = (o4 & mask) + (o3 >> SM2Field29.Bits);
		Vector512<ulong> c5 = third.L5;
		Vector512<ulong> d5 = c5 + Vector512.Create(SM2Field29.FourPMiddle) - Swap(c5);
		left.L5 = Blend23(Blend1(Broadcast3(c5), d5), Blend3(c5, Swap(state.P.L5)));
		Vector512<ulong> o5 = Blend3(Blend2(Avx512F.UnpackHigh(d5, d5), Broadcast1(second.L5)), entry.EB.L5);
		right.L5 = (o5 & mask) + (o4 >> SM2Field29.Bits);
		Vector512<ulong> c6 = third.L6;
		Vector512<ulong> d6 = c6 + Vector512.Create(SM2Field29.FourPMiddle) - Swap(c6);
		left.L6 = Blend23(Blend1(Broadcast3(c6), d6), Blend3(c6, Swap(state.P.L6)));
		Vector512<ulong> o6 = Blend3(Blend2(Avx512F.UnpackHigh(d6, d6), Broadcast1(second.L6)), entry.EB.L6);
		right.L6 = (o6 & mask) + (o5 >> SM2Field29.Bits);
		Vector512<ulong> c7 = third.L7;
		Vector512<ulong> d7 = c7 + Vector512.Create(SM2Field29.FourP7) - Swap(c7);
		left.L7 = Blend23(Blend1(Broadcast3(c7), d7), Blend3(c7, Swap(state.P.L7)));
		Vector512<ulong> o7 = Blend3(Blend2(Avx512F.UnpackHigh(d7, d7), Broadcast1(second.L7)), entry.EB.L7);
		right.L7 = (o7 & mask) + (o6 >> SM2Field29.Bits);
		Vector512<ulong> c8 = third.L8;
		Vector512<ulong> d8 = c8 + Vector512.Create(SM2Field29.FourP8) - Swap(c8);
		left.L8 = Blend23(Blend1(Broadcast3(c8), d8), Blend3(c8, Swap(state.P.L8)));
		Vector512<ulong> o8 = Blend3(Blend2(Avx512F.UnpackHigh(d8, d8), Broadcast1(second.L8)), entry.EB.L8);
		right.L8 = o8 + (o7 >> SM2Field29.Bits);
		ref SM2Field29x8Avx512 fourth = ref second;
		SM2Field29x8Avx512.Multiply(in left, in right, out fourth);
		// R carried, in the lanes 2 of both operands of A2; H from lane 1 of the right of A1, read before right takes that of A2.
		Vector512<ulong> b0 = fourth.L0;
		Vector512<ulong> r0 = b0 + Vector512.Create(SM2Field29.FourP0) - Swap(b0);
		Vector512<ulong> q0 = Blend3(r0 & mask, Broadcast0(b0));
		left.L0 = Blend23(Blend1(third.L0, right.L0), q0);
		right.L0 = Blend23(Avx512F.UnpackHigh(b0, b0), q0);
		Vector512<ulong> b1 = fourth.L1;
		Vector512<ulong> r1 = b1 + Vector512.Create(SM2Field29.FourP1) - Swap(b1);
		Vector512<ulong> q1 = Blend3((r1 & mask) + (r0 >> SM2Field29.Bits), Broadcast0(b1));
		left.L1 = Blend23(Blend1(third.L1, right.L1), q1);
		right.L1 = Blend23(Avx512F.UnpackHigh(b1, b1), q1);
		Vector512<ulong> b2 = fourth.L2;
		Vector512<ulong> r2 = b2 + Vector512.Create(SM2Field29.FourP2) - Swap(b2);
		Vector512<ulong> q2 = Blend3((r2 & mask) + (r1 >> SM2Field29.Bits), Broadcast0(b2));
		left.L2 = Blend23(Blend1(third.L2, right.L2), q2);
		right.L2 = Blend23(Avx512F.UnpackHigh(b2, b2), q2);
		Vector512<ulong> b3 = fourth.L3;
		Vector512<ulong> r3 = b3 + Vector512.Create(SM2Field29.FourP3) - Swap(b3);
		Vector512<ulong> q3 = Blend3((r3 & mask) + (r2 >> SM2Field29.Bits), Broadcast0(b3));
		left.L3 = Blend23(Blend1(third.L3, right.L3), q3);
		right.L3 = Blend23(Avx512F.UnpackHigh(b3, b3), q3);
		Vector512<ulong> b4 = fourth.L4;
		Vector512<ulong> r4 = b4 + Vector512.Create(SM2Field29.FourPMiddle) - Swap(b4);
		Vector512<ulong> q4 = Blend3((r4 & mask) + (r3 >> SM2Field29.Bits), Broadcast0(b4));
		left.L4 = Blend23(Blend1(third.L4, right.L4), q4);
		right.L4 = Blend23(Avx512F.UnpackHigh(b4, b4), q4);
		Vector512<ulong> b5 = fourth.L5;
		Vector512<ulong> r5 = b5 + Vector512.Create(SM2Field29.FourPMiddle) - Swap(b5);
		Vector512<ulong> q5 = Blend3((r5 & mask) + (r4 >> SM2Field29.Bits), Broadcast0(b5));
		left.L5 = Blend23(Blend1(third.L5, right.L5), q5);
		right.L5 = Blend23(Avx512F.UnpackHigh(b5, b5), q5);
		Vector512<ulong> b6 = fourth.L6;
		Vector512<ulong> r6 = b6 + Vector512.Create(SM2Field29.FourPMiddle) - Swap(b6);
		Vector512<ulong> q6 = Blend3((r6 & mask) + (r5 >> SM2Field29.Bits), Broadcast0(b6));
		left.L6 = Blend23(Blend1(third.L6, right.L6), q6);
		right.L6 = Blend23(Avx512F.UnpackHigh(b6, b6), q6);
		Vector512<ulong> b7 = fourth.L7;
		Vector512<ulong> r7 = b7 + Vector512.Create(SM2Field29.FourP7) - Swap(b7);
		Vector512<ulong> q7 = Blend3((r7 & mask) + (r6 >> SM2Field29.Bits), Broadcast0(b7));
		left.L7 = Blend23(Blend1(third.L7, right.L7), q7);
		right.L7 = Blend23(Avx512F.UnpackHigh(b7, b7), q7);
		Vector512<ulong> b8 = fourth.L8;
		Vector512<ulong> r8 = b8 + Vector512.Create(SM2Field29.FourP8) - Swap(b8);
		Vector512<ulong> q8 = Blend3(r8 + (r7 >> SM2Field29.Bits), Broadcast0(b8));
		left.L8 = Blend23(Blend1(third.L8, right.L8), q8);
		right.L8 = Blend23(Avx512F.UnpackHigh(b8, b8), q8);
		ref SM2Field29x8Avx512 fifth = ref first;
		SM2Field29x8Avx512.Multiply(in left, in right, out fifth);
		Vector512<ulong> e0 = fifth.L0;
		Vector512<ulong> p0 = Broadcast0(e0);
		Vector512<ulong> n0 = Broadcast1(e0);
		next.L0 = e0 + Vector512.Create(3 * SM2Field29.FourP0) - (n0 + (p0 << 1));
		// The right of A3 takes W and H3 here and 3(X + δ) in lane 0 below.
		right.L0 = Blend3((p0 << 1) + p0 + n0 + Vector512.Create(SM2Field29.FourP0) - e0, n0);
		Vector512<ulong> e1 = fifth.L1;
		Vector512<ulong> p1 = Broadcast0(e1);
		Vector512<ulong> n1 = Broadcast1(e1);
		next.L1 = e1 + Vector512.Create(3 * SM2Field29.FourP1) - (n1 + (p1 << 1));
		right.L1 = Blend3((p1 << 1) + p1 + n1 + Vector512.Create(SM2Field29.FourP1) - e1, n1);
		Vector512<ulong> e2 = fifth.L2;
		Vector512<ulong> p2 = Broadcast0(e2);
		Vector512<ulong> n2 = Broadcast1(e2);
		next.L2 = e2 + Vector512.Create(3 * SM2Field29.FourP2) - (n2 + (p2 << 1));
		right.L2 = Blend3((p2 << 1) + p2 + n2 + Vector512.Create(SM2Field29.FourP2) - e2, n2);
		Vector512<ulong> e3 = fifth.L3;
		Vector512<ulong> p3 = Broadcast0(e3);
		Vector512<ulong> n3 = Broadcast1(e3);
		next.L3 = e3 + Vector512.Create(3 * SM2Field29.FourP3) - (n3 + (p3 << 1));
		right.L3 = Blend3((p3 << 1) + p3 + n3 + Vector512.Create(SM2Field29.FourP3) - e3, n3);
		Vector512<ulong> e4 = fifth.L4;
		Vector512<ulong> p4 = Broadcast0(e4);
		Vector512<ulong> n4 = Broadcast1(e4);
		next.L4 = e4 + Vector512.Create(3 * SM2Field29.FourPMiddle) - (n4 + (p4 << 1));
		right.L4 = Blend3((p4 << 1) + p4 + n4 + Vector512.Create(SM2Field29.FourPMiddle) - e4, n4);
		Vector512<ulong> e5 = fifth.L5;
		Vector512<ulong> p5 = Broadcast0(e5);
		Vector512<ulong> n5 = Broadcast1(e5);
		next.L5 = e5 + Vector512.Create(3 * SM2Field29.FourPMiddle) - (n5 + (p5 << 1));
		right.L5 = Blend3((p5 << 1) + p5 + n5 + Vector512.Create(SM2Field29.FourPMiddle) - e5, n5);
		Vector512<ulong> e6 = fifth.L6;
		Vector512<ulong> p6 = Broadcast0(e6);
		Vector512<ulong> n6 = Broadcast1(e6);
		next.L6 = e6 + Vector512.Create(3 * SM2Field29.FourPMiddle) - (n6 + (p6 << 1));
		right.L6 = Blend3((p6 << 1) + p6 + n6 + Vector512.Create(SM2Field29.FourPMiddle) - e6, n6);
		Vector512<ulong> e7 = fifth.L7;
		Vector512<ulong> p7 = Broadcast0(e7);
		Vector512<ulong> n7 = Broadcast1(e7);
		next.L7 = e7 + Vector512.Create(3 * SM2Field29.FourP7) - (n7 + (p7 << 1));
		right.L7 = Blend3((p7 << 1) + p7 + n7 + Vector512.Create(SM2Field29.FourP7) - e7, n7);
		Vector512<ulong> e8 = fifth.L8;
		Vector512<ulong> p8 = Broadcast0(e8);
		Vector512<ulong> n8 = Broadcast1(e8);
		next.L8 = e8 + Vector512.Create(3 * SM2Field29.FourP8) - (n8 + (p8 << 1));
		right.L8 = Blend3((p8 << 1) + p8 + n8 + Vector512.Create(SM2Field29.FourP8) - e8, n8);
		SM2Field29x8Avx512.Reduce(in next, out next);
		// The right of A3 carried.
		Vector512<ulong> x0 = Avx512F.Permute4x64(Blend3(next.L0, fifth.L0), 0xEE);
		Vector512<ulong> m0 = Swap(x0);
		Vector512<ulong> t0 = x0 + m0;
		// Q keeps the X and δ of the sum, and R comes from lane 2 of the left of A2.
		state.Q.L0 = x0;
		left.L0 = Blend0(Blend3(left.L0, fourth.L0), x0 + Vector512.Create(SM2Field29.FourP0) - m0);
		Vector512<ulong> w0 = Blend0(right.L0, t0 + (t0 << 1));
		right.L0 = w0 & mask;
		Vector512<ulong> x1 = Avx512F.Permute4x64(Blend3(next.L1, fifth.L1), 0xEE);
		Vector512<ulong> m1 = Swap(x1);
		Vector512<ulong> t1 = x1 + m1;
		state.Q.L1 = x1;
		left.L1 = Blend0(Blend3(left.L1, fourth.L1), x1 + Vector512.Create(SM2Field29.FourP1) - m1);
		Vector512<ulong> w1 = Blend0(right.L1, t1 + (t1 << 1));
		right.L1 = (w1 & mask) + (w0 >> SM2Field29.Bits);
		Vector512<ulong> x2 = Avx512F.Permute4x64(Blend3(next.L2, fifth.L2), 0xEE);
		Vector512<ulong> m2 = Swap(x2);
		Vector512<ulong> t2 = x2 + m2;
		state.Q.L2 = x2;
		left.L2 = Blend0(Blend3(left.L2, fourth.L2), x2 + Vector512.Create(SM2Field29.FourP2) - m2);
		Vector512<ulong> w2 = Blend0(right.L2, t2 + (t2 << 1));
		right.L2 = (w2 & mask) + (w1 >> SM2Field29.Bits);
		Vector512<ulong> x3 = Avx512F.Permute4x64(Blend3(next.L3, fifth.L3), 0xEE);
		Vector512<ulong> m3 = Swap(x3);
		Vector512<ulong> t3 = x3 + m3;
		state.Q.L3 = x3;
		left.L3 = Blend0(Blend3(left.L3, fourth.L3), x3 + Vector512.Create(SM2Field29.FourP3) - m3);
		Vector512<ulong> w3 = Blend0(right.L3, t3 + (t3 << 1));
		right.L3 = (w3 & mask) + (w2 >> SM2Field29.Bits);
		Vector512<ulong> x4 = Avx512F.Permute4x64(Blend3(next.L4, fifth.L4), 0xEE);
		Vector512<ulong> m4 = Swap(x4);
		Vector512<ulong> t4 = x4 + m4;
		state.Q.L4 = x4;
		left.L4 = Blend0(Blend3(left.L4, fourth.L4), x4 + Vector512.Create(SM2Field29.FourPMiddle) - m4);
		Vector512<ulong> w4 = Blend0(right.L4, t4 + (t4 << 1));
		right.L4 = (w4 & mask) + (w3 >> SM2Field29.Bits);
		Vector512<ulong> x5 = Avx512F.Permute4x64(Blend3(next.L5, fifth.L5), 0xEE);
		Vector512<ulong> m5 = Swap(x5);
		Vector512<ulong> t5 = x5 + m5;
		state.Q.L5 = x5;
		left.L5 = Blend0(Blend3(left.L5, fourth.L5), x5 + Vector512.Create(SM2Field29.FourPMiddle) - m5);
		Vector512<ulong> w5 = Blend0(right.L5, t5 + (t5 << 1));
		right.L5 = (w5 & mask) + (w4 >> SM2Field29.Bits);
		Vector512<ulong> x6 = Avx512F.Permute4x64(Blend3(next.L6, fifth.L6), 0xEE);
		Vector512<ulong> m6 = Swap(x6);
		Vector512<ulong> t6 = x6 + m6;
		state.Q.L6 = x6;
		left.L6 = Blend0(Blend3(left.L6, fourth.L6), x6 + Vector512.Create(SM2Field29.FourPMiddle) - m6);
		Vector512<ulong> w6 = Blend0(right.L6, t6 + (t6 << 1));
		right.L6 = (w6 & mask) + (w5 >> SM2Field29.Bits);
		Vector512<ulong> x7 = Avx512F.Permute4x64(Blend3(next.L7, fifth.L7), 0xEE);
		Vector512<ulong> m7 = Swap(x7);
		Vector512<ulong> t7 = x7 + m7;
		state.Q.L7 = x7;
		left.L7 = Blend0(Blend3(left.L7, fourth.L7), x7 + Vector512.Create(SM2Field29.FourP7) - m7);
		Vector512<ulong> w7 = Blend0(right.L7, t7 + (t7 << 1));
		right.L7 = (w7 & mask) + (w6 >> SM2Field29.Bits);
		Vector512<ulong> x8 = Avx512F.Permute4x64(Blend3(next.L8, fifth.L8), 0xEE);
		Vector512<ulong> m8 = Swap(x8);
		Vector512<ulong> t8 = x8 + m8;
		state.Q.L8 = x8;
		left.L8 = Blend0(Blend3(left.L8, fourth.L8), x8 + Vector512.Create(SM2Field29.FourP8) - m8);
		Vector512<ulong> w8 = Blend0(right.L8, t8 + (t8 << 1));
		right.L8 = w8 + (w7 >> SM2Field29.Bits);
		ref SM2Field29x8Avx512 sixth = ref first;
		SM2Field29x8Avx512.Multiply(in left, in right, out sixth);
		// Y3 folded, and the Y and Z of the result carried.
		Vector512<ulong> f8 = sixth.L8;
		Vector512<ulong> y8 = f8 + Vector512.Create(SM2Field29.FourP8) - Swap(f8);
		Vector512<ulong> j = y8 >> 24;
		y8 &= top;
		Vector512<ulong> f0 = sixth.L0;
		Vector512<ulong> y0 = f0 + Vector512.Create(SM2Field29.FourP0) - Swap(f0) + j;
		Vector512<ulong> u0 = Blend3(y0, Broadcast0(fourth.L0));
		Vector512<ulong> k0 = state.Q.L0;
		state.P.L0 = Blend2(Avx512F.Permute4x64(Blend0(u0 & mask, f0), 0xE8), Broadcast0(k0));
		state.Q.L0 = Blend3(k0, Broadcast0(f0));
		Vector512<ulong> f1 = sixth.L1;
		Vector512<ulong> y1 = f1 + Vector512.Create(SM2Field29.FourP1) - Swap(f1);
		Vector512<ulong> u1 = Blend3(y1, Broadcast0(fourth.L1));
		Vector512<ulong> k1 = state.Q.L1;
		state.P.L1 = Blend2(Avx512F.Permute4x64(Blend0((u1 & mask) + (u0 >> SM2Field29.Bits), f1), 0xE8), Broadcast0(k1));
		state.Q.L1 = Blend3(k1, Broadcast0(f1));
		Vector512<ulong> f2 = sixth.L2;
		Vector512<ulong> y2 = f2 + Vector512.Create(SM2Field29.FourPFold2) - Swap(f2) - (j << 6);
		Vector512<ulong> u2 = Blend3(y2, Broadcast0(fourth.L2));
		Vector512<ulong> k2 = state.Q.L2;
		state.P.L2 = Blend2(Avx512F.Permute4x64(Blend0((u2 & mask) + (u1 >> SM2Field29.Bits), f2), 0xE8), Broadcast0(k2));
		state.Q.L2 = Blend3(k2, Broadcast0(f2));
		Vector512<ulong> f3 = sixth.L3;
		Vector512<ulong> y3 = f3 + Vector512.Create(SM2Field29.FourPFold3) - Swap(f3) + (j << 9);
		Vector512<ulong> u3 = Blend3(y3, Broadcast0(fourth.L3));
		Vector512<ulong> k3 = state.Q.L3;
		state.P.L3 = Blend2(Avx512F.Permute4x64(Blend0((u3 & mask) + (u2 >> SM2Field29.Bits), f3), 0xE8), Broadcast0(k3));
		state.Q.L3 = Blend3(k3, Broadcast0(f3));
		Vector512<ulong> f4 = sixth.L4;
		Vector512<ulong> y4 = f4 + Vector512.Create(SM2Field29.FourPMiddle) - Swap(f4);
		Vector512<ulong> u4 = Blend3(y4, Broadcast0(fourth.L4));
		Vector512<ulong> k4 = state.Q.L4;
		state.P.L4 = Blend2(Avx512F.Permute4x64(Blend0((u4 & mask) + (u3 >> SM2Field29.Bits), f4), 0xE8), Broadcast0(k4));
		state.Q.L4 = Blend3(k4, Broadcast0(f4));
		Vector512<ulong> f5 = sixth.L5;
		Vector512<ulong> y5 = f5 + Vector512.Create(SM2Field29.FourPMiddle) - Swap(f5);
		Vector512<ulong> u5 = Blend3(y5, Broadcast0(fourth.L5));
		Vector512<ulong> k5 = state.Q.L5;
		state.P.L5 = Blend2(Avx512F.Permute4x64(Blend0((u5 & mask) + (u4 >> SM2Field29.Bits), f5), 0xE8), Broadcast0(k5));
		state.Q.L5 = Blend3(k5, Broadcast0(f5));
		Vector512<ulong> f6 = sixth.L6;
		Vector512<ulong> y6 = f6 + Vector512.Create(SM2Field29.FourPMiddle) - Swap(f6);
		Vector512<ulong> u6 = Blend3(y6, Broadcast0(fourth.L6));
		Vector512<ulong> k6 = state.Q.L6;
		state.P.L6 = Blend2(Avx512F.Permute4x64(Blend0((u6 & mask) + (u5 >> SM2Field29.Bits), f6), 0xE8), Broadcast0(k6));
		state.Q.L6 = Blend3(k6, Broadcast0(f6));
		Vector512<ulong> f7 = sixth.L7;
		Vector512<ulong> y7 = f7 + Vector512.Create(SM2Field29.FourP7) - Swap(f7) + (j << 21);
		Vector512<ulong> u7 = Blend3(y7, Broadcast0(fourth.L7));
		Vector512<ulong> k7 = state.Q.L7;
		state.P.L7 = Blend2(Avx512F.Permute4x64(Blend0((u7 & mask) + (u6 >> SM2Field29.Bits), f7), 0xE8), Broadcast0(k7));
		state.Q.L7 = Blend3(k7, Broadcast0(f7));
		Vector512<ulong> u8 = Blend3(y8, Broadcast0(fourth.L8));
		Vector512<ulong> k8 = state.Q.L8;
		state.P.L8 = Blend2(Avx512F.Permute4x64(Blend0(u8 + (u7 >> SM2Field29.Bits), f8), 0xE8), Broadcast0(k8));
		state.Q.L8 = Blend3(k8, Broadcast0(f8));
	}

	// The entries of an odd digit of each chain, as TSelector reads them, with Y negated for a digit below 0.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Select<TSelector>(ReadOnlySpan<ulong> table, int top, int bottom, Span<ulong> packed, Span<ulong> negative, out SM2OctoEntry entry) where TSelector : struct, ISelector
	{
		int topSign = top >> 31;
		int bottomSign = bottom >> 31;
		TSelector.Unpack(table, (uint)((top ^ topSign) - topSign) >> 1, (uint)((bottom ^ bottomSign) - bottomSign) >> 1, packed, out entry);
		// Y alone, in lane 2 of each half of EA.
		negative.Clear();
		negative[2] = (ulong)topSign;
		negative[HalfCount + 2] = (ulong)bottomSign;
		SM2Field29x8Avx512.ConditionalNegate(in negative[0], ref entry.EA);
	}

	// The entry of an odd digit of the first chain from table and of the second from otherTable, read by one masked scan of each, with Y negated for a digit below 0.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void SelectTwo(ReadOnlySpan<ulong> table, ReadOnlySpan<ulong> otherTable, int first, int second, Span<ulong> packed, Span<ulong> negative, out SM2OctoEntry entry)
	{
		int firstSign = first >> 31;
		int secondSign = second >> 31;
		LookupTwo(in table[0], in otherTable[0], (uint)((first ^ firstSign) - firstSign) >> 1, (uint)((second ^ secondSign) - secondSign) >> 1, ref packed[0], ref packed[EntryLength]);
		Unpack(ref packed[0], ref packed[EntryLength], out entry);
		// Y alone, in lane 2 of each half of EA.
		negative.Clear();
		negative[2] = (ulong)firstSign;
		negative[HalfCount + 2] = (ulong)secondSign;
		SM2Field29x8Avx512.ConditionalNegate(in negative[0], ref entry.EA);
	}

	// Entry first of table to low and entry second of otherTable to high, as LookupPair reads two entries of one table.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void LookupTwo(ref readonly ulong table, ref readonly ulong otherTable, uint first, uint second, ref ulong low, ref ulong high)
	{
		Vector512<ulong> firstTarget = Vector512.Create((ulong)first);
		Vector512<ulong> secondTarget = Vector512.Create((ulong)second);
		Vector512<ulong> position = Vector512<ulong>.Zero;
		Vector512<ulong> a0 = Vector512<ulong>.Zero;
		Vector512<ulong> a1 = a0;
		Vector512<ulong> a2 = a0;
		Vector512<ulong> a3 = a0;
		Vector512<ulong> b0 = a0;
		Vector512<ulong> b1 = a0;
		Vector512<ulong> b2 = a0;
		Vector512<ulong> b3 = a0;
		ref ulong entry = ref Unsafe.AsRef(in table);
		ref ulong otherEntry = ref Unsafe.AsRef(in otherTable);

		for (int j = 0; j < TableLength; ++j)
		{
			Vector512<ulong> firstMask = Vector512.Equals(position, firstTarget);
			Vector512<ulong> secondMask = Vector512.Equals(position, secondTarget);
			a0 |= Vector512.LoadUnsafe(ref entry) & firstMask;
			a1 |= Vector512.LoadUnsafe(ref entry, 8) & firstMask;
			a2 |= Vector512.LoadUnsafe(ref entry, 16) & firstMask;
			a3 |= Vector512.LoadUnsafe(ref entry, EntryLength - 8) & firstMask;
			b0 |= Vector512.LoadUnsafe(ref otherEntry) & secondMask;
			b1 |= Vector512.LoadUnsafe(ref otherEntry, 8) & secondMask;
			b2 |= Vector512.LoadUnsafe(ref otherEntry, 16) & secondMask;
			b3 |= Vector512.LoadUnsafe(ref otherEntry, EntryLength - 8) & secondMask;
			position += Vector512<ulong>.One;
			entry = ref Unsafe.Add(ref entry, EntryLength);
			otherEntry = ref Unsafe.Add(ref otherEntry, EntryLength);
		}

		a0.StoreUnsafe(ref low);
		a1.StoreUnsafe(ref low, 8);
		a2.StoreUnsafe(ref low, 16);
		a3.StoreUnsafe(ref low, EntryLength - 8);
		b0.StoreUnsafe(ref high);
		b1.StoreUnsafe(ref high, 8);
		b2.StoreUnsafe(ref high, 16);
		b3.StoreUnsafe(ref high, EntryLength - 8);
	}

	// Entries first and second of the table, to low and high, in one scan that reads every limb of every entry once and keeps what matches each index under a mask, so that neither the time nor the addresses depend on the indices. The last block of an entry overlaps the one before it, and both write the same values to the shared limbs.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void LookupPair(ref readonly ulong table, uint first, uint second, ref ulong low, ref ulong high)
	{
		Vector512<ulong> firstTarget = Vector512.Create((ulong)first);
		Vector512<ulong> secondTarget = Vector512.Create((ulong)second);
		Vector512<ulong> position = Vector512<ulong>.Zero;
		Vector512<ulong> a0 = Vector512<ulong>.Zero;
		Vector512<ulong> a1 = a0;
		Vector512<ulong> a2 = a0;
		Vector512<ulong> a3 = a0;
		Vector512<ulong> b0 = a0;
		Vector512<ulong> b1 = a0;
		Vector512<ulong> b2 = a0;
		Vector512<ulong> b3 = a0;
		ref ulong entry = ref Unsafe.AsRef(in table);

		for (int j = 0; j < TableLength; ++j)
		{
			Vector512<ulong> firstMask = Vector512.Equals(position, firstTarget);
			Vector512<ulong> secondMask = Vector512.Equals(position, secondTarget);
			Vector512<ulong> e0 = Vector512.LoadUnsafe(ref entry);
			Vector512<ulong> e1 = Vector512.LoadUnsafe(ref entry, 8);
			Vector512<ulong> e2 = Vector512.LoadUnsafe(ref entry, 16);
			Vector512<ulong> e3 = Vector512.LoadUnsafe(ref entry, EntryLength - 8);
			a0 |= e0 & firstMask;
			a1 |= e1 & firstMask;
			a2 |= e2 & firstMask;
			a3 |= e3 & firstMask;
			b0 |= e0 & secondMask;
			b1 |= e1 & secondMask;
			b2 |= e2 & secondMask;
			b3 |= e3 & secondMask;
			position += Vector512<ulong>.One;
			entry = ref Unsafe.Add(ref entry, EntryLength);
		}

		a0.StoreUnsafe(ref low);
		a1.StoreUnsafe(ref low, 8);
		a2.StoreUnsafe(ref low, 16);
		a3.StoreUnsafe(ref low, EntryLength - 8);
		b0.StoreUnsafe(ref high);
		b1.StoreUnsafe(ref high, 8);
		b2.StoreUnsafe(ref high, 16);
		b3.StoreUnsafe(ref high, EntryLength - 8);
	}

	// The entries of EntryLength limbs at low and high in the halves, each in the layout of SM2QuadFormulas.BuildTable.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Unpack(ref ulong low, ref ulong high, out SM2OctoEntry entry)
	{
		Unsafe.SkipInit(out entry);
		Vector512<ulong> mask = Vector512.Create(SM2Field29.Mask);
		Joined(ref low, ref high, 0, out Vector512<ulong> a0, out Vector512<ulong> b0);
		entry.EA.L0 = a0 & mask;
		entry.EA.L1 = a0 >> SM2Field29.Bits;
		entry.EB.L0 = b0 & mask;
		entry.EB.L1 = b0 >> SM2Field29.Bits;
		Joined(ref low, ref high, 1, out Vector512<ulong> a2, out Vector512<ulong> b2);
		entry.EA.L2 = a2 & mask;
		entry.EA.L3 = a2 >> SM2Field29.Bits;
		entry.EB.L2 = b2 & mask;
		entry.EB.L3 = b2 >> SM2Field29.Bits;
		Joined(ref low, ref high, 2, out Vector512<ulong> a4, out Vector512<ulong> b4);
		entry.EA.L4 = a4 & mask;
		entry.EA.L5 = a4 >> SM2Field29.Bits;
		entry.EB.L4 = b4 & mask;
		entry.EB.L5 = b4 >> SM2Field29.Bits;
		Joined(ref low, ref high, 3, out Vector512<ulong> a6, out Vector512<ulong> b6);
		entry.EA.L6 = a6 & mask;
		entry.EA.L7 = a6 >> SM2Field29.Bits;
		entry.EB.L6 = b6 & mask;
		entry.EB.L7 = b6 >> SM2Field29.Bits;
		Joined(ref low, ref high, 4, out Vector512<ulong> a8, out Vector512<ulong> b8);
		entry.EA.L8 = a8;
		entry.EB.L8 = b8;
	}

	// Limbs 2i and 2i + 1 joined into one ulong, or limb 8 for i = 4, of the entries at low and high, one in each half: [Z², X, Y, Z] in a and [X, Z², Z³, Z³] in b.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Joined(ref ulong low, ref ulong high, int i, out Vector512<ulong> a, out Vector512<ulong> b)
	{
		Vector128<ulong> xyl = Vector128.LoadUnsafe(ref low, (nuint)(2 * i));
		Vector128<ulong> czl = Vector128.LoadUnsafe(ref low, (nuint)(CubeOffset + 2 * i));
		Vector128<ulong> sl = Vector128.CreateScalar(Unsafe.Add(ref low, SquareOffset + i));
		Vector128<ulong> xyh = Vector128.LoadUnsafe(ref high, (nuint)(2 * i));
		Vector128<ulong> czh = Vector128.LoadUnsafe(ref high, (nuint)(CubeOffset + 2 * i));
		Vector128<ulong> sh = Vector128.CreateScalar(Unsafe.Add(ref high, SquareOffset + i));
		// The low half goes into a vector whose upper half the insertion writes over, which Vector512.Create would first take from a slot of the stack.
		a = Avx512F.InsertVector256(Vector256.Create(Sse2.UnpackLow(sl, xyl), Sse2.UnpackHigh(xyl, czl)).ToVector512Unsafe(), Vector256.Create(Sse2.UnpackLow(sh, xyh), Sse2.UnpackHigh(xyh, czh)), 1);
		b = Avx512F.InsertVector256(Vector256.Create(Sse2.UnpackLow(xyl, sl), Sse2.UnpackLow(czl, czl)).ToVector512Unsafe(), Vector256.Create(Sse2.UnpackLow(xyh, sh), Sse2.UnpackLow(czh, czh)), 1);
	}

	// Unpacks entries first and second of the table into the halves of entry; ClearsIntermediates tells whether Multiply clears what it kept.
	private interface ISelector
	{
		static abstract bool ClearsIntermediates { get; }

		static abstract void Unpack(ReadOnlySpan<ulong> table, uint first, uint second, Span<ulong> packed, out SM2OctoEntry entry);
	}

	// One masked scan of the table, through packed, so that neither the time nor the addresses depend on the indices.
	private readonly struct MaskedScan : ISelector
	{
		public static bool ClearsIntermediates => true;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void Unpack(ReadOnlySpan<ulong> table, uint first, uint second, Span<ulong> packed, out SM2OctoEntry entry)
		{
			LookupPair(in table[0], first, second, ref packed[0], ref packed[EntryLength]);
			SM2OctoFormulas.Unpack(ref packed[0], ref packed[EntryLength], out entry);
		}
	}

	// The entries at public indices, read in place.
	private readonly struct DirectRead : ISelector
	{
		public static bool ClearsIntermediates => false;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void Unpack(ReadOnlySpan<ulong> table, uint first, uint second, Span<ulong> packed, out SM2OctoEntry entry)
		{
			ref ulong entries = ref MemoryMarshal.GetReference(table);
			SM2OctoFormulas.Unpack(ref Unsafe.Add(ref entries, first * EntryLength), ref Unsafe.Add(ref entries, second * EntryLength), out entry);
		}
	}

	// Lane 0 of each half of b, the others of a. A blend under a mask register, unlike a select by a mask vector, lets the JIT merge it into the operation that computes b.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> Blend0(Vector512<ulong> a, Vector512<ulong> b)
	{
		return Avx512F.BlendVariable(a, b, Vector512.Create(ulong.MaxValue, 0, 0, 0, ulong.MaxValue, 0, 0, 0));
	}

	// Lane 1 of each half of b, the others of a.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> Blend1(Vector512<ulong> a, Vector512<ulong> b)
	{
		return Avx512F.BlendVariable(a, b, Vector512.Create(0, ulong.MaxValue, 0, 0, 0, ulong.MaxValue, 0, 0));
	}

	// Lane 2 of each half of b, the others of a.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> Blend2(Vector512<ulong> a, Vector512<ulong> b)
	{
		return Avx512F.BlendVariable(a, b, Vector512.Create(0, 0, ulong.MaxValue, 0, 0, 0, ulong.MaxValue, 0));
	}

	// Lane 3 of each half of b, the others of a.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> Blend3(Vector512<ulong> a, Vector512<ulong> b)
	{
		return Avx512F.BlendVariable(a, b, Vector512.Create(0, 0, 0, ulong.MaxValue, 0, 0, 0, ulong.MaxValue));
	}

	// Lanes 2 and 3 of each half of b, the others of a.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> Blend23(Vector512<ulong> a, Vector512<ulong> b)
	{
		return Avx512F.BlendVariable(a, b, Vector512.Create(0, 0, ulong.MaxValue, ulong.MaxValue, 0, 0, ulong.MaxValue, ulong.MaxValue));
	}

	// Lane 0 of each half in every lane of the half.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> Broadcast0(Vector512<ulong> a)
	{
		return Avx512F.Permute4x64(a, 0x00);
	}

	// Lane 1 of each half in every lane of the half.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> Broadcast1(Vector512<ulong> a)
	{
		return Avx512F.Permute4x64(a, 0x55);
	}

	// Lane 3 of each half in every lane of the half.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> Broadcast3(Vector512<ulong> a)
	{
		return Avx512F.Permute4x64(a, 0xFF);
	}

	// The two lanes of each 128-bit block swapped.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> Swap(Vector512<ulong> a)
	{
		return Avx512F.Shuffle(a.AsUInt32(), 0x4E).AsUInt64();
	}
}

// The states of SM2OctoFormulas: an SM2QuadState in each half.
internal struct SM2OctoState
{
	internal SM2Field29x8Avx512 P;
	internal SM2Field29x8Avx512 Q;
}

// The entries of SM2OctoFormulas: an SM2QuadEntry in each half.
internal struct SM2OctoEntry
{
	internal SM2Field29x8Avx512 EA;
	internal SM2Field29x8Avx512 EB;
}
