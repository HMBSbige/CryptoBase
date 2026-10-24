namespace CryptoBase.Hashes.Sha3;

internal static partial class KeccakP1600
{
	internal static bool IsAvx512Supported => Vector512.IsHardwareAccelerated && Avx512F.IsSupported;

	// Zen 4 and 256-bit-datapath Zen 5 halve the row kernel's shuffle throughput; Lane128 has no shuffles.
	internal static readonly bool PreferAvx512 = IsAvx512Supported && !CpuIdUtils.IsAmdWith256BitDatapath();

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void PermuteLane128(ref InlineArray25<ulong> state)
	{
		Debug.Assert(KeccakP1600Lane128.IsSupported);

		KeccakP1600Interleaved.Permute<Vector128<ulong>, KeccakP1600Lane128>(ref state[0]);
	}

	// XORs each whole block of source into the state and permutes it, and returns the number of bytes absorbed.
	internal static int AbsorbLane128<TRate>(ref InlineArray25<ulong> state, ReadOnlySpan<byte> source) where TRate : IKeccakRate
	{
		Debug.Assert(KeccakP1600Lane128.IsSupported);
		Debug.Assert(source.Length >= TRate.RateInBytes);

		int blocks = source.Length / TRate.RateInBytes;
		ref ulong block = ref Unsafe.As<byte, ulong>(ref MemoryMarshal.GetReference(source));
		KeccakP1600Interleaved.Permute<Vector128<ulong>, KeccakP1600Lane128, KeccakP1600AbsorbBlocks<TRate>>(ref state[0], ref block, blocks);
		return blocks * TRate.RateInBytes;
	}

	// Permutes the state and writes its first rate bytes for each whole block that fits in destination, and returns the number of bytes written; the state then holds the last block written.
	internal static int SqueezeLane128<TRate>(ref InlineArray25<ulong> state, Span<byte> destination) where TRate : IKeccakRate
	{
		Debug.Assert(KeccakP1600Lane128.IsSupported);
		Debug.Assert(destination.Length >= TRate.RateInBytes);

		int blocks = destination.Length / TRate.RateInBytes;
		ref ulong block = ref Unsafe.As<byte, ulong>(ref MemoryMarshal.GetReference(destination));
		KeccakP1600Interleaved.Permute<Vector128<ulong>, KeccakP1600Lane128, KeccakP1600SqueezeBlocks<TRate>>(ref state[0], ref block, blocks);
		return blocks * TRate.RateInBytes;
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static void PermuteAvx512(ref InlineArray25<ulong> state)
	{
		Debug.Assert(IsAvx512Supported);

		LoadRows(ref state, out Vector512<ulong> a0, out Vector512<ulong> a1, out Vector512<ulong> a2, out Vector512<ulong> a3, out Vector512<ulong> a4);
		PermuteRows(ref a0, ref a1, ref a2, ref a3, ref a4);
		StoreRows(ref state, a0, a1, a2, a3, a4);
	}

	// XORs each whole block of source into the state and permutes it, and returns the number of bytes absorbed.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static unsafe int AbsorbAvx512<TRate>(ref InlineArray25<ulong> state, ReadOnlySpan<byte> source) where TRate : IKeccakRate
	{
		Debug.Assert(IsAvx512Supported);
		Debug.Assert(source.Length >= TRate.RateInBytes);

		int blocks = source.Length / TRate.RateInBytes;
		LoadRows(ref state, out Vector512<ulong> a0, out Vector512<ulong> a1, out Vector512<ulong> a2, out Vector512<ulong> a3, out Vector512<ulong> a4);

		fixed (byte* input = source)
		{
			ulong* block = (ulong*)input;

			for (int i = 0; i < blocks; ++i)
			{
				a0 ^= LoadBlockRow<TRate>(block, 0);
				a1 ^= LoadBlockRow<TRate>(block, 1);
				a2 ^= LoadBlockRow<TRate>(block, 2);
				a3 ^= LoadBlockRow<TRate>(block, 3);
				a4 ^= LoadBlockRow<TRate>(block, 4);
				PermuteRows(ref a0, ref a1, ref a2, ref a3, ref a4);
				block += TRate.RateInBytes / sizeof(ulong);
			}
		}

		StoreRows(ref state, a0, a1, a2, a3, a4);
		return blocks * TRate.RateInBytes;
	}

	// Permutes the state and writes its first rate bytes for each whole block that fits in destination, and returns the number of bytes written; the state then holds the last block written.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static unsafe int SqueezeAvx512<TRate>(ref InlineArray25<ulong> state, Span<byte> destination) where TRate : IKeccakRate
	{
		Debug.Assert(IsAvx512Supported);
		Debug.Assert(destination.Length >= TRate.RateInBytes);

		int blocks = destination.Length / TRate.RateInBytes;
		LoadRows(ref state, out Vector512<ulong> a0, out Vector512<ulong> a1, out Vector512<ulong> a2, out Vector512<ulong> a3, out Vector512<ulong> a4);

		fixed (byte* output = destination)
		{
			ulong* block = (ulong*)output;

			for (int i = 0; i < blocks; ++i)
			{
				PermuteRows(ref a0, ref a1, ref a2, ref a3, ref a4);
				StoreBlockRow<TRate>(block, 0, a0);
				StoreBlockRow<TRate>(block, 1, a1);
				StoreBlockRow<TRate>(block, 2, a2);
				StoreBlockRow<TRate>(block, 3, a3);
				StoreBlockRow<TRate>(block, 4, a4);
				block += TRate.RateInBytes / sizeof(ulong);
			}
		}

		StoreRows(ref state, a0, a1, a2, a3, a4);
		return blocks * TRate.RateInBytes;
	}

	// Lanes 5y to 5y + 4 of a block, as far as it has them, in the low elements; as in PermuteRows, the upper three may hold anything. A masked load reads only those lanes where a full vector would read past the block, so the last block of source cannot fault.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static unsafe Vector512<ulong> LoadBlockRow<TRate>(ulong* block, int row) where TRate : IKeccakRate
	{
		int lanes = TRate.RateInBytes / sizeof(ulong) - 5 * row;

		if (lanes <= 0)
		{
			return Vector512<ulong>.Zero;
		}

		if (lanes >= Vector512<ulong>.Count)
		{
			return Vector512.Load(block + 5 * row);
		}

		Vector512<ulong> mask = Vector512.LessThan(Vector512<ulong>.Indices, Vector512.Create((ulong)Math.Min(lanes, 5)));
		return Avx512F.MaskLoad(block + 5 * row, mask, Vector512<ulong>.Zero);
	}

	// Writes lanes 5y to 5y + 4 of a block, as far as the block has them. A full vector is stored only where its upper three elements land on lanes that the next row overwrites; elsewhere a masked store writes only the row's lanes, so nothing lands past the block, and the last block cannot fault on the bytes after destination.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static unsafe void StoreBlockRow<TRate>(ulong* block, int row, Vector512<ulong> value) where TRate : IKeccakRate
	{
		int lanes = TRate.RateInBytes / sizeof(ulong) - 5 * row;

		if (lanes <= 0)
		{
			return;
		}

		if (lanes >= Vector512<ulong>.Count)
		{
			value.Store(block + 5 * row);
			return;
		}

		Vector512<ulong> mask = Vector512.LessThan(Vector512<ulong>.Indices, Vector512.Create((ulong)Math.Min(lanes, 5)));
		Avx512F.MaskStore(block + 5 * row, mask, value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void LoadRows(ref InlineArray25<ulong> state, out Vector512<ulong> a0, out Vector512<ulong> a1, out Vector512<ulong> a2, out Vector512<ulong> a3, out Vector512<ulong> a4)
	{
		ref ulong lanes = ref state[0];
		a0 = Vector512.LoadUnsafe(ref lanes);
		a1 = Vector512.LoadUnsafe(ref lanes, 5);
		a2 = Vector512.LoadUnsafe(ref lanes, 10);
		a3 = Vector512.LoadUnsafe(ref lanes, 15);
		// A full vector at row 4 would read past the state, so the load starts three lanes earlier and a permute moves row 4 into place.
		a4 = Avx512F.PermuteVar8x64(Vector512.LoadUnsafe(ref lanes, 17), Vector512.Create(3UL, 4, 5, 6, 7, 0, 1, 2));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void StoreRows(ref InlineArray25<ulong> state, Vector512<ulong> a0, Vector512<ulong> a1, Vector512<ulong> a2, Vector512<ulong> a3, Vector512<ulong> a4)
	{
		// Each store overwrites the upper elements of the one before. The last starts where LoadRows reads row 4, three lanes early, and fills those lanes from row 3, so that nothing is written past the state.
		ref ulong lanes = ref state[0];
		a0.StoreUnsafe(ref lanes);
		a1.StoreUnsafe(ref lanes, 5);
		a2.StoreUnsafe(ref lanes, 10);
		a3.StoreUnsafe(ref lanes, 15);
		Avx512F.PermuteVar8x64x2(a3, Vector512.Create(2UL, 3, 4, 8, 9, 10, 11, 12), a4).StoreUnsafe(ref lanes, 17);
	}

	// One state in five 512-bit vectors: row y holds plane y, lanes A[0..4, y], in its low five elements, and the three upper elements carry garbage that never reaches the low five. π sends lane (x, y) to row 2x + 3y, so diagonal x - y = k becomes row 2k with lane x' at element x' + k. The diagonals still hold lane x at element x, so they are blended from the rows while θ computes the column parities, then take θ and ρ; the rotations within a vector that then put each diagonal in row order also supply the neighbours χ needs.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PermuteRows(ref Vector512<ulong> row0, ref Vector512<ulong> row1, ref Vector512<ulong> row2, ref Vector512<ulong> row3, ref Vector512<ulong> row4)
	{
		// Element x of a shuffle by plusK takes element x + k mod 5.
		Vector512<ulong> plus1 = Vector512.Create(1UL, 2, 3, 4, 0, 5, 6, 7);
		Vector512<ulong> plus2 = Vector512.Create(2UL, 3, 4, 0, 1, 5, 6, 7);
		Vector512<ulong> plus3 = Vector512.Create(3UL, 4, 0, 1, 2, 5, 6, 7);
		Vector512<ulong> plus4 = Vector512.Create(4UL, 0, 1, 2, 3, 5, 6, 7);
		Vector512<ulong> element0 = Vector512.Create(ulong.MaxValue, 0, 0, 0, 0, 0, 0, 0);
		Vector512<ulong> elements01 = Vector512.Create(ulong.MaxValue, ulong.MaxValue, 0, 0, 0, 0, 0, 0);
		Vector512<ulong> element2 = Vector512.Create(0, 0, ulong.MaxValue, 0, 0, 0, 0, 0);
		Vector512<ulong> element4 = Vector512.Create(0, 0, 0, 0, ulong.MaxValue, 0, 0, 0);
		// The ρ offsets of diagonal k, whose element x holds lane A[x, x - k].
		Vector512<ulong> rho0 = Vector512.Create(0UL, 44, 43, 21, 14, 0, 0, 0);
		Vector512<ulong> rho1 = Vector512.Create(18UL, 1, 6, 25, 8, 0, 0, 0);
		Vector512<ulong> rho2 = Vector512.Create(41UL, 2, 62, 55, 39, 0, 0, 0);
		Vector512<ulong> rho3 = Vector512.Create(3UL, 45, 61, 28, 20, 0, 0, 0);
		Vector512<ulong> rho4 = Vector512.Create(36UL, 10, 15, 56, 27, 0, 0, 0);

		Vector512<ulong> a0 = row0;
		Vector512<ulong> a1 = row1;
		Vector512<ulong> a2 = row2;
		Vector512<ulong> a3 = row3;
		Vector512<ulong> a4 = row4;
		ref ulong roundConstants = ref MemoryMarshal.GetReference(KeccakP1600Constants.RoundConstants);

		for (nuint round = 0; round < KeccakP1600Constants.Rounds; ++round)
		{
			// θ: element x of parityLeft and parityRight is C[x - 1] and ROT(C[x + 1], 1).
			Vector512<ulong> parity = Avx512F.TernaryLogic(Avx512F.TernaryLogic(a0, a1, a2, 0x96), a3, a4, 0x96);
			Vector512<ulong> parityLeft = Avx512F.PermuteVar8x64(parity, plus4);
			Vector512<ulong> parityRight = Avx512F.RotateLeft(Avx512F.PermuteVar8x64(parity, plus1), 1);

			// Element x of diagonal k comes from row x - k.
			Vector512<ulong> d0 = Blend(element4, a4, Blend(elements01, Blend(element0, a0, a1), Blend(element2, a2, a3)));
			Vector512<ulong> d1 = Blend(element4, a3, Blend(elements01, Blend(element0, a4, a0), Blend(element2, a1, a2)));
			Vector512<ulong> d2 = Blend(element4, a2, Blend(elements01, Blend(element0, a3, a4), Blend(element2, a0, a1)));
			Vector512<ulong> d3 = Blend(element4, a1, Blend(elements01, Blend(element0, a2, a3), Blend(element2, a4, a0)));
			Vector512<ulong> d4 = Blend(element4, a0, Blend(elements01, Blend(element0, a1, a2), Blend(element2, a3, a4)));

			d0 = Avx512F.RotateLeftVariable(Avx512F.TernaryLogic(d0, parityLeft, parityRight, 0x96), rho0);
			d1 = Avx512F.RotateLeftVariable(Avx512F.TernaryLogic(d1, parityLeft, parityRight, 0x96), rho1);
			d2 = Avx512F.RotateLeftVariable(Avx512F.TernaryLogic(d2, parityLeft, parityRight, 0x96), rho2);
			d3 = Avx512F.RotateLeftVariable(Avx512F.TernaryLogic(d3, parityLeft, parityRight, 0x96), rho3);
			d4 = Avx512F.RotateLeftVariable(Avx512F.TernaryLogic(d4, parityLeft, parityRight, 0x96), rho4);

			// χ and ι: row 2k is diagonal k shuffled by plusK, and its lanes x + 1 and x + 2 are the same diagonal shuffled by plusK+1 and plusK+2. 0xD2 is 0xF0 ^ (~0xCC & 0xAA).
			a0 = Avx512F.TernaryLogic(d0 ^ Vector512.CreateScalar(Unsafe.Add(ref roundConstants, round)), Avx512F.PermuteVar8x64(d0, plus1), Avx512F.PermuteVar8x64(d0, plus2), 0xD2);
			a2 = Avx512F.TernaryLogic(Avx512F.PermuteVar8x64(d1, plus1), Avx512F.PermuteVar8x64(d1, plus2), Avx512F.PermuteVar8x64(d1, plus3), 0xD2);
			a4 = Avx512F.TernaryLogic(Avx512F.PermuteVar8x64(d2, plus2), Avx512F.PermuteVar8x64(d2, plus3), Avx512F.PermuteVar8x64(d2, plus4), 0xD2);
			a1 = Avx512F.TernaryLogic(Avx512F.PermuteVar8x64(d3, plus3), Avx512F.PermuteVar8x64(d3, plus4), d3, 0xD2);
			a3 = Avx512F.TernaryLogic(Avx512F.PermuteVar8x64(d4, plus4), d4, Avx512F.PermuteVar8x64(d4, plus1), 0xD2);
		}

		row0 = a0;
		row1 = a1;
		row2 = a2;
		row3 = a3;
		row4 = a4;
	}

	// With constant masks, the JIT emits VPBLENDMQ under mask registers it loads once, whereas ConditionalSelect becomes a destructive VPTERNLOGQ that needs a register copy for each blend.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> Blend(Vector512<ulong> mask, Vector512<ulong> ifSet, Vector512<ulong> ifClear)
	{
		return Avx512F.BlendVariable(ifClear, ifSet, mask);
	}
}
