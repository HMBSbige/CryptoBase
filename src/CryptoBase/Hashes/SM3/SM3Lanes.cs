namespace CryptoBase.Hashes.SM3;

// The compression function of SM3 over the lanes of TLanes, and the blocks SM3(prefix ‖ ct) of the KDF of GB/T 32918.4-2016, Sec. 5.4.3, for consecutive counters ct, one counter to a lane. The rounds follow those of SM3Core: the eight state vectors take new roles each round rather than moving, so that four rounds bring them back to their places.
// A round waits on six dependent vector steps, so one group of lanes leaves most of the vector pipelines idle: where there are 32 vector registers, which two states and the temporaries fill, Write takes two groups at a time, their rounds in turn, and one group only for the rest of the key that fits in it.
internal static class SM3Lanes<TLanes, TVector> where TLanes : ISM3Lanes<TVector> where TVector : unmanaged
{
	internal const int BlockLength = 32;

	private const int ScheduleLength = 68;

	// With 16 vector registers, the two states alone would fill them, and the JIT would spill nearly every temporary of the rounds.
	private static bool TakesPairs
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => Avx512F.VL.IsSupported || AdvSimd.Arm64.IsSupported;
	}

	// The key that one pass of Write takes: two groups or one.
	internal static int PassLength
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => (TakesPairs ? 2 : 1) * TLanes.Lanes * BlockLength;
	}

	// Writes SM3(prefix ‖ ct) for ct = counter, counter + 1, … to destination, which is not empty, 32 bytes each, the last cut to fit, for the prefix that blocks finish. The counters do not wrap: counter + ⌈destination.Length / 32⌉ − 1 is at most 2^32 − 1. Every lane of the last groups is computed, but only the blocks within destination are written. The words of the prefix that the method copies are erased.
	// Inlined where it is hot, it would leave the JIT no budget for its own steps, so it stays a call.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static void Write(ref readonly SM3CounterBlocks blocks, uint counter, Span<byte> destination)
	{
		Debug.Assert(TLanes.IsSupported && !destination.IsEmpty);
		Debug.Assert(counter + ((ulong)destination.Length - 1) / BlockLength <= uint.MaxValue);

		// Group 1 of a pair has its state from vector 8 on and its schedule from vector 68 on.
		Unsafe.SkipInit(out InlineArray16<TVector> state);
		Unsafe.SkipInit(out SM3LaneSchedule<TVector> schedule);
		int groupLength = TLanes.Lanes * BlockLength;
		ref byte output = ref MemoryMarshal.GetReference(destination);
		int remaining = destination.Length;

		if (TakesPairs)
		{
			for (; remaining >= 2 * groupLength; remaining -= 2 * groupLength)
			{
				HashPair(in blocks, counter, ref state[0], ref schedule[0]);
				Store(ref state[0], ref output);
				Store(ref state[8], ref Unsafe.Add(ref output, groupLength));
				output = ref Unsafe.Add(ref output, 2 * groupLength);
				counter += (uint)(2 * TLanes.Lanes);
			}
		}
		else
		{
			for (; remaining >= groupLength; remaining -= groupLength)
			{
				Hash(in blocks, counter, ref state[0], ref schedule[0]);
				Store(ref state[0], ref output);
				output = ref Unsafe.Add(ref output, groupLength);
				counter += (uint)TLanes.Lanes;
			}
		}

		if (remaining is not 0)
		{
			// The blocks of two groups take 16 vectors, which the schedule frees once the rounds are done.
			ref byte rest = ref Unsafe.As<TVector, byte>(ref schedule[0]);

			if (TakesPairs && remaining > groupLength)
			{
				HashPair(in blocks, counter, ref state[0], ref schedule[0]);
				Store(ref state[0], ref rest);
				Store(ref state[8], ref Unsafe.Add(ref rest, groupLength));
			}
			else
			{
				Hash(in blocks, counter, ref state[0], ref schedule[0]);
				Store(ref state[0], ref rest);
			}

			Unsafe.CopyBlockUnaligned(ref output, ref rest, (uint)remaining);
		}

		// Group 1 is used only for a key longer than a group, and only in pairs.
		state.ZeroMemory();
		MemoryMarshal.CreateSpan(ref schedule[0], TakesPairs && destination.Length > groupLength ? 2 * ScheduleLength : ScheduleLength).ZeroMemory();
	}

	// Compresses the block of each lane, its 16 words at schedule, into the state of the lane, its 8 words at state, and leaves the working state and then W[8..67] of the expanded block at schedule, which the caller erases.
	// The JIT tracks a limited number of locals, which the inlined steps of all 64 rounds would come near, and over it would leave the state on the stack; so the rounds run in three methods, which pass the working state through W[0..7], which no round reads past round 15, as for two groups.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Compress(ref TVector state, ref TVector schedule)
	{
		RoundsEarly(ref state, ref schedule);
		RoundsMiddle(ref schedule);
		RoundsLate(ref state, ref schedule);
	}

	// Rounds 0 to 15, from state into W[0..7].
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void RoundsEarly(ref TVector state, ref TVector schedule)
	{
		Rounds(ref state, ref schedule, ref schedule, 0, 16, false, true, false);
	}

	// Rounds 16 to 51, in W[0..7].
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void RoundsMiddle(ref TVector schedule)
	{
		Rounds(ref schedule, ref schedule, ref schedule, 16, 52, true, true, false);
	}

	// Rounds 52 to 63, from W[0..7], and the state that they finish XORed into state.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void RoundsLate(ref TVector state, ref TVector schedule)
	{
		Rounds(ref schedule, ref state, ref schedule, 52, 64, true, false, true);
	}

	// Rounds first to last − 1, from the state at source to destination, which it replaces or, for feedForward, is XORed into.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Rounds(ref TVector source, ref TVector destination, ref TVector schedule, int first, int last, bool late, bool expand, bool feedForward)
	{
		TVector a = source;
		TVector b = Unsafe.Add(ref source, 1);
		TVector c = Unsafe.Add(ref source, 2);
		TVector d = Unsafe.Add(ref source, 3);
		TVector e = Unsafe.Add(ref source, 4);
		TVector f = Unsafe.Add(ref source, 5);
		TVector g = Unsafe.Add(ref source, 6);
		TVector h = Unsafe.Add(ref source, 7);
		ref TVector words = ref Unsafe.Add(ref schedule, first);
		ref uint roundConstants = ref Unsafe.Add(ref MemoryMarshal.GetReference(SM3Core.RoundConstants), first);

		for (int round = first; round < last; round += 4)
		{
			Round4(ref a, ref b, ref c, ref d, ref e, ref f, ref g, ref h, ref words, ref roundConstants, late, expand);
			words = ref Unsafe.Add(ref words, 4);
			roundConstants = ref Unsafe.Add(ref roundConstants, 4);
		}

		Finish(ref destination, a, b, c, d, e, f, g, h, feedForward);
	}

	// Compress for two groups: state0 and schedule0, state1 and schedule1.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Compress(ref TVector state0, ref TVector schedule0, ref TVector state1, ref TVector schedule1)
	{
		RoundsEarly(ref state0, ref state1, ref schedule0, ref schedule1);
		RoundsMiddle(ref schedule0, ref schedule1);
		RoundsLate(ref state0, ref state1, ref schedule0, ref schedule1);
	}

	// Rounds 0 to 15 of two groups, from state0 and state1 into W[0..7] of each.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void RoundsEarly(ref TVector state0, ref TVector state1, ref TVector schedule0, ref TVector schedule1)
	{
		Rounds(ref state0, ref state1, ref schedule0, ref schedule1, ref schedule0, ref schedule1, 0, 16, false, true, false);
	}

	// Rounds 16 to 51 of two groups, in W[0..7] of each.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void RoundsMiddle(ref TVector schedule0, ref TVector schedule1)
	{
		Rounds(ref schedule0, ref schedule1, ref schedule0, ref schedule1, ref schedule0, ref schedule1, 16, 52, true, true, false);
	}

	// Rounds 52 to 63 of two groups, from W[0..7] of each, and the states that they finish XORed into state0 and state1.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void RoundsLate(ref TVector state0, ref TVector state1, ref TVector schedule0, ref TVector schedule1)
	{
		Rounds(ref schedule0, ref schedule1, ref state0, ref state1, ref schedule0, ref schedule1, 52, 64, true, false, true);
	}

	// Rounds first to last − 1 of two groups, from the states at source0 and source1 to destination0 and destination1, which they replace or, for feedForward, are XORed into.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Rounds(ref TVector source0, ref TVector source1, ref TVector destination0, ref TVector destination1, ref TVector schedule0, ref TVector schedule1, int first, int last, bool late, bool expand, bool feedForward)
	{
		TVector a0 = source0;
		TVector b0 = Unsafe.Add(ref source0, 1);
		TVector c0 = Unsafe.Add(ref source0, 2);
		TVector d0 = Unsafe.Add(ref source0, 3);
		TVector e0 = Unsafe.Add(ref source0, 4);
		TVector f0 = Unsafe.Add(ref source0, 5);
		TVector g0 = Unsafe.Add(ref source0, 6);
		TVector h0 = Unsafe.Add(ref source0, 7);
		TVector a1 = source1;
		TVector b1 = Unsafe.Add(ref source1, 1);
		TVector c1 = Unsafe.Add(ref source1, 2);
		TVector d1 = Unsafe.Add(ref source1, 3);
		TVector e1 = Unsafe.Add(ref source1, 4);
		TVector f1 = Unsafe.Add(ref source1, 5);
		TVector g1 = Unsafe.Add(ref source1, 6);
		TVector h1 = Unsafe.Add(ref source1, 7);
		ref TVector words0 = ref Unsafe.Add(ref schedule0, first);
		ref TVector words1 = ref Unsafe.Add(ref schedule1, first);
		ref uint roundConstants = ref Unsafe.Add(ref MemoryMarshal.GetReference(SM3Core.RoundConstants), first);

		for (int round = first; round < last; round += 4)
		{
			Round4(ref a0, ref b0, ref c0, ref d0, ref e0, ref f0, ref g0, ref h0, ref a1, ref b1, ref c1, ref d1, ref e1, ref f1, ref g1, ref h1, ref words0, ref words1, ref roundConstants, late, expand);
			words0 = ref Unsafe.Add(ref words0, 4);
			words1 = ref Unsafe.Add(ref words1, 4);
			roundConstants = ref Unsafe.Add(ref roundConstants, 4);
		}

		Finish(ref destination0, a0, b0, c0, d0, e0, f0, g0, h0, feedForward);
		Finish(ref destination1, a1, b1, c1, d1, e1, f1, g1, h1, feedForward);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Finish(ref TVector destination, TVector a, TVector b, TVector c, TVector d, TVector e, TVector f, TVector g, TVector h, bool feedForward)
	{
		destination = feedForward ? TLanes.Xor(destination, a) : a;
		Unsafe.Add(ref destination, 1) = feedForward ? TLanes.Xor(Unsafe.Add(ref destination, 1), b) : b;
		Unsafe.Add(ref destination, 2) = feedForward ? TLanes.Xor(Unsafe.Add(ref destination, 2), c) : c;
		Unsafe.Add(ref destination, 3) = feedForward ? TLanes.Xor(Unsafe.Add(ref destination, 3), d) : d;
		Unsafe.Add(ref destination, 4) = feedForward ? TLanes.Xor(Unsafe.Add(ref destination, 4), e) : e;
		Unsafe.Add(ref destination, 5) = feedForward ? TLanes.Xor(Unsafe.Add(ref destination, 5), f) : f;
		Unsafe.Add(ref destination, 6) = feedForward ? TLanes.Xor(Unsafe.Add(ref destination, 6), g) : g;
		Unsafe.Add(ref destination, 7) = feedForward ? TLanes.Xor(Unsafe.Add(ref destination, 7), h) : h;
	}

	// The state of the chaining value of the prefix in every lane, then the last one or two blocks with the counters of the lanes from counter on, compressed into it.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Hash(ref readonly SM3CounterBlocks blocks, uint counter, ref TVector state, ref TVector schedule)
	{
		TVector counters = TLanes.Counters(counter);
		LoadChainingValue(in blocks, ref state);
		LoadBlock(in blocks, 0, counters, ref schedule);
		Compress(ref state, ref schedule);

		if (blocks.TwoBlocks)
		{
			LoadBlock(in blocks, 1, counters, ref schedule);
			Compress(ref state, ref schedule);
		}
	}

	// Hash for two groups, group 1 taking the counters after those of group 0.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void HashPair(ref readonly SM3CounterBlocks blocks, uint counter, ref TVector state, ref TVector schedule)
	{
		ref TVector state1 = ref Unsafe.Add(ref state, 8);
		ref TVector schedule1 = ref Unsafe.Add(ref schedule, ScheduleLength);
		TVector counters0 = TLanes.Counters(counter);
		TVector counters1 = TLanes.Counters(counter + (uint)TLanes.Lanes);
		LoadChainingValue(in blocks, ref state);
		LoadChainingValue(in blocks, ref state1);
		LoadBlock(in blocks, 0, counters0, ref schedule);
		LoadBlock(in blocks, 0, counters1, ref schedule1);
		Compress(ref state, ref schedule, ref state1, ref schedule1);

		if (blocks.TwoBlocks)
		{
			LoadBlock(in blocks, 1, counters0, ref schedule);
			LoadBlock(in blocks, 1, counters1, ref schedule1);
			Compress(ref state, ref schedule, ref state1, ref schedule1);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void LoadChainingValue(ref readonly SM3CounterBlocks blocks, ref TVector state)
	{
		// Indexing a readonly inline array goes through a span, which the JIT leaves as a call in Write.
		ref uint chainingValue = ref Unsafe.As<InlineArray8<uint>, uint>(ref Unsafe.AsRef(in blocks.ChainingValue));

		for (int i = 0; i < 8; ++i)
		{
			Unsafe.Add(ref state, i) = TLanes.Create(Unsafe.Add(ref chainingValue, i));
		}
	}

	// Block 0 or 1 of the blocks, with counters in its bytes: the counter takes the low 32 − shift bits of word, from its top, and its low shift bits go to the top of the next word, which is word 0 of block 1 for word 15.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void LoadBlock(ref readonly SM3CounterBlocks blocks, int block, TVector counters, ref TVector schedule)
	{
		ref uint words = ref Unsafe.Add(ref Unsafe.As<InlineArray32<uint>, uint>(ref Unsafe.AsRef(in blocks.Words)), 16 * block);

		for (int i = 0; i < 16; ++i)
		{
			Unsafe.Add(ref schedule, i) = TLanes.Create(Unsafe.Add(ref words, i));
		}

		int word = blocks.Offset >> 2;
		int shift = (blocks.Offset & 3) * 8;

		if (block is 0)
		{
			ref TVector first = ref Unsafe.Add(ref schedule, word);
			first = TLanes.Or(first, TLanes.ShiftRightLogical(counters, shift));
		}

		int next = word + 1 - 16 * block;

		if (shift is not 0 && next is >= 0 and < 16)
		{
			ref TVector rest = ref Unsafe.Add(ref schedule, next);
			rest = TLanes.Or(rest, TLanes.ShiftLeft(counters, 32 - shift));
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Store(ref TVector state, ref byte destination)
	{
		TLanes.Store(state, Unsafe.Add(ref state, 1), Unsafe.Add(ref state, 2), Unsafe.Add(ref state, 3), Unsafe.Add(ref state, 4), Unsafe.Add(ref state, 5), Unsafe.Add(ref state, 6), Unsafe.Add(ref state, 7), ref destination);
	}

	// Rounds j..j+3 with words = &W[j] and roundConstants = &T[j]; expand also writes W[j+16..j+19].
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Round4(ref TVector a, ref TVector b, ref TVector c, ref TVector d, ref TVector e, ref TVector f, ref TVector g, ref TVector h, ref TVector words, ref uint roundConstants, bool late, bool expand)
	{
		Round1(ref a, ref b, ref c, ref d, ref e, ref f, ref g, ref h, ref words, ref roundConstants, late);

		if (expand)
		{
			Expand(ref words);
		}

		Round1(ref d, ref a, ref b, ref c, ref h, ref e, ref f, ref g, ref Unsafe.Add(ref words, 1), ref Unsafe.Add(ref roundConstants, 1), late);

		if (expand)
		{
			Expand(ref Unsafe.Add(ref words, 1));
		}

		Round1(ref c, ref d, ref a, ref b, ref g, ref h, ref e, ref f, ref Unsafe.Add(ref words, 2), ref Unsafe.Add(ref roundConstants, 2), late);

		if (expand)
		{
			Expand(ref Unsafe.Add(ref words, 2));
		}

		Round1(ref b, ref c, ref d, ref a, ref f, ref g, ref h, ref e, ref Unsafe.Add(ref words, 3), ref Unsafe.Add(ref roundConstants, 3), late);

		if (expand)
		{
			Expand(ref Unsafe.Add(ref words, 3));
		}
	}

	// Round4 for two groups, their rounds in turn.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Round4
	(
		ref TVector a0, ref TVector b0, ref TVector c0, ref TVector d0, ref TVector e0, ref TVector f0, ref TVector g0, ref TVector h0,
		ref TVector a1, ref TVector b1, ref TVector c1, ref TVector d1, ref TVector e1, ref TVector f1, ref TVector g1, ref TVector h1,
		ref TVector words0, ref TVector words1, ref uint roundConstants, bool late, bool expand
	)
	{
		Round1(ref a0, ref b0, ref c0, ref d0, ref e0, ref f0, ref g0, ref h0, ref words0, ref roundConstants, late);
		Round1(ref a1, ref b1, ref c1, ref d1, ref e1, ref f1, ref g1, ref h1, ref words1, ref roundConstants, late);

		if (expand)
		{
			Expand(ref words0);
			Expand(ref words1);
		}

		Round1(ref d0, ref a0, ref b0, ref c0, ref h0, ref e0, ref f0, ref g0, ref Unsafe.Add(ref words0, 1), ref Unsafe.Add(ref roundConstants, 1), late);
		Round1(ref d1, ref a1, ref b1, ref c1, ref h1, ref e1, ref f1, ref g1, ref Unsafe.Add(ref words1, 1), ref Unsafe.Add(ref roundConstants, 1), late);

		if (expand)
		{
			Expand(ref Unsafe.Add(ref words0, 1));
			Expand(ref Unsafe.Add(ref words1, 1));
		}

		Round1(ref c0, ref d0, ref a0, ref b0, ref g0, ref h0, ref e0, ref f0, ref Unsafe.Add(ref words0, 2), ref Unsafe.Add(ref roundConstants, 2), late);
		Round1(ref c1, ref d1, ref a1, ref b1, ref g1, ref h1, ref e1, ref f1, ref Unsafe.Add(ref words1, 2), ref Unsafe.Add(ref roundConstants, 2), late);

		if (expand)
		{
			Expand(ref Unsafe.Add(ref words0, 2));
			Expand(ref Unsafe.Add(ref words1, 2));
		}

		Round1(ref b0, ref c0, ref d0, ref a0, ref f0, ref g0, ref h0, ref e0, ref Unsafe.Add(ref words0, 3), ref Unsafe.Add(ref roundConstants, 3), late);
		Round1(ref b1, ref c1, ref d1, ref a1, ref f1, ref g1, ref h1, ref e1, ref Unsafe.Add(ref words1, 3), ref Unsafe.Add(ref roundConstants, 3), late);

		if (expand)
		{
			Expand(ref Unsafe.Add(ref words0, 3));
			Expand(ref Unsafe.Add(ref words1, 3));
		}
	}

	// The round of words = &W[j]: TT1 takes the place of d, and P0(TT2) that of h; b and f rotate in place.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Round1(ref TVector a, ref TVector b, ref TVector c, ref TVector d, ref TVector e, ref TVector f, ref TVector g, ref TVector h, ref TVector words, ref uint roundConstant, bool late)
	{
		TVector word = words;
		d = Round(a, b, c, d, e, f, g, h, word, TLanes.Xor(word, Unsafe.Add(ref words, 4)), ref roundConstant, late, out h);
		b = TLanes.RotateLeft(b, 9);
		f = TLanes.RotateLeft(f, 19);
	}

	// W[j+16] for words = &W[j].
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Expand(ref TVector words)
	{
		TVector mixed = TLanes.Xor(words, Unsafe.Add(ref words, 7), TLanes.RotateLeft(Unsafe.Add(ref words, 13), 15));
		Unsafe.Add(ref words, 16) = TLanes.Xor(TLanes.P1(mixed), TLanes.RotateLeft(Unsafe.Add(ref words, 3), 7), Unsafe.Add(ref words, 10));
	}

	// TT1, which takes the place of D, and P0(TT2) in nextH, for word = W[j] and mixed = W[j] ^ W[j+4].
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static TVector Round(TVector a, TVector b, TVector c, TVector d, TVector e, TVector f, TVector g, TVector h, TVector word, TVector mixed, ref readonly uint constant, bool late, out TVector nextH)
	{
		// e arrives last, so SS1 adds it to the rest of its sum, and TT2 adds SS1 last.
		TVector a12 = TLanes.RotateLeft(a, 12);
		TVector ss1 = TLanes.RotateLeft(TLanes.Add(e, TLanes.Add(a12, TLanes.Create(constant))), 7);
		TVector gg = late ? TLanes.Choose(e, f, g) : TLanes.Xor(e, f, g);
		TVector ff = late ? TLanes.Majority(a, b, c) : TLanes.Xor(a, b, c);
		nextH = TLanes.P0(TLanes.Add(TLanes.Add(gg, TLanes.Add(h, word)), ss1));
		return TLanes.Add(TLanes.Xor(ss1, a12), TLanes.Add(ff, TLanes.Add(d, mixed)));
	}
}
