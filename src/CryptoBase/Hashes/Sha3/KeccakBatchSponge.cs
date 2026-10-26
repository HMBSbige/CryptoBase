namespace CryptoBase.Hashes.Sha3;

// Up to eight sponges with one rate that absorb equal-length inputs and squeeze in lockstep, permuted together by an interleaved kernel, for the many short SHAKE streams that ML-KEM and ML-DSA expand their matrices and vectors from. The Count inputs or outputs of a call lie back to back in one buffer, each a Count-th of its length.
internal struct KeccakBatchSponge<TRate> where TRate : IKeccakRate
{
	// The lengths of the prefix that the seeded Reset takes.
	internal const int ShortPrefixLength = 32;
	internal const int LongPrefixLength = 64;

	private const byte LastPaddingBit = 0x80;

	// Room for the widest kernel, in the layout of IKeccakP1600Kernel: word _lanes * i + j is lane i of stream j. Row i, lane i of every stream, is one vector to the kernel.
	// ReSharper disable once UnassignedField.Compiler
	private InlineArray25<InlineArray8<ulong>> _state;

	// The Lanes of the kernel chosen in Reset; lanes from Count up to it are permuted but unused, or hold guests during Permute.
	private int _lanes;

	// Bytes of the current block absorbed or squeezed so far, the same in every stream.
	private int _position;

	internal int Count { get; private set; }

	internal bool IsSqueezing { get; private set; }

	internal readonly int FreeLanes => _lanes - Count;

	// Takes as many of the remaining streams as KeccakP1600Batch assigns to one kernel, Count says how many, and leaves up to guests lanes free for Permute where the kernel has room. Guests never cost a stream: a guest only saves a permutation, while a stream left over can cost a batch.
	internal void ResetWithGuests(int streams, int guests)
	{
		Debug.Assert(guests >= 0);

		Reset(streams, KeccakP1600Batch.ChooseLanes(streams + guests));
	}

	internal void Reset(int streams, int lanes)
	{
		Debug.Assert(streams > 0);
		Debug.Assert(lanes is 1 or 2 or 4 or 8);

		MemoryMarshal.CreateSpan(ref _state[0][0], KeccakP1600Constants.LaneCount * lanes).Clear();
		_lanes = lanes;
		_position = 0;
		Count = Math.Min(streams, lanes);
		IsSqueezing = false;
	}

	// As ResetWithGuests, then Absorb and Pad of prefix ‖ suffixes[j] for stream j, the suffix suffixLength bytes little-endian, written straight into the state.
	internal void ResetWithGuests(int streams, int guests, ReadOnlySpan<byte> prefix, ReadOnlySpan<ushort> suffixes, int suffixLength, byte domainSeparator)
	{
		Debug.Assert(guests >= 0);

		Reset(streams, KeccakP1600Batch.ChooseLanes(streams + guests), prefix, suffixes, suffixLength, domainSeparator);
	}

	// The prefix takes rows 0 to 3, or 0 to 7 when it is 64 bytes long, and the next row each suffix with the domain separator. The free lanes are filled too, as for Pad.
	[SkipLocalsInit]
	internal void Reset(int streams, int lanes, ReadOnlySpan<byte> prefix, ReadOnlySpan<ushort> suffixes, int suffixLength, byte domainSeparator)
	{
		Debug.Assert(prefix.Length is ShortPrefixLength or LongPrefixLength);

		if (prefix.Length is LongPrefixLength)
		{
			Reset(streams, lanes, prefix, suffixes, suffixLength, domainSeparator, LongPrefixLength / sizeof(ulong));
		}
		else
		{
			Reset(streams, lanes, prefix, suffixes, suffixLength, domainSeparator, ShortPrefixLength / sizeof(ulong));
		}
	}

	// Inlined into each branch above, so that suffixRowIndex is a constant.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void Reset(int streams, int lanes, ReadOnlySpan<byte> prefix, ReadOnlySpan<ushort> suffixes, int suffixLength, byte domainSeparator, int suffixRowIndex)
	{
		int lastRow = TRate.RateInBytes / sizeof(ulong) - 1;

		Debug.Assert(streams > 0);
		Debug.Assert(lanes is 1 or 2 or 4 or 8);
		Debug.Assert(prefix.Length == suffixRowIndex * sizeof(ulong));
		Debug.Assert(suffixLength is 1 or 2);
		Debug.Assert(domainSeparator is not 0 and < LastPaddingBit);
		Debug.Assert(suffixRowIndex < lastRow);

		int count = Math.Min(streams, lanes);
		Debug.Assert(suffixes.Length >= count);

		ref ulong state = ref _state[0][0];
		ref byte seed = ref MemoryMarshal.GetReference(prefix);
		FillRow(ref state, lanes, Unsafe.ReadUnaligned<ulong>(ref seed));
		FillRow(ref Unsafe.Add(ref state, lanes), lanes, Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref seed, 8)));
		FillRow(ref Unsafe.Add(ref state, 2 * lanes), lanes, Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref seed, 16)));
		FillRow(ref Unsafe.Add(ref state, 3 * lanes), lanes, Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref seed, 24)));

		if (suffixRowIndex > ShortPrefixLength / sizeof(ulong))
		{
			FillRow(ref Unsafe.Add(ref state, 4 * lanes), lanes, Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref seed, 32)));
			FillRow(ref Unsafe.Add(ref state, 5 * lanes), lanes, Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref seed, 40)));
			FillRow(ref Unsafe.Add(ref state, 6 * lanes), lanes, Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref seed, 48)));
			FillRow(ref Unsafe.Add(ref state, 7 * lanes), lanes, Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref seed, 56)));
		}

		ref ulong suffixRow = ref Unsafe.Add(ref state, suffixRowIndex * lanes);
		ref ushort suffix = ref MemoryMarshal.GetReference(suffixes);
		ulong padding = (ulong)domainSeparator << 8 * suffixLength;
		FillRow(ref suffixRow, lanes, padding);

		for (int j = 0; j < count; ++j)
		{
			Debug.Assert(Unsafe.Add(ref suffix, j) >> 8 * suffixLength is 0);

			Unsafe.Add(ref suffixRow, j) = Unsafe.Add(ref suffix, j) | padding;
		}

		MemoryMarshal.CreateSpan(ref Unsafe.Add(ref state, (suffixRowIndex + 1) * lanes), (lastRow - suffixRowIndex - 1) * lanes).Clear();
		FillRow(ref Unsafe.Add(ref state, lastRow * lanes), lanes, (ulong)LastPaddingBit << 56);
		MemoryMarshal.CreateSpan(ref Unsafe.Add(ref state, (lastRow + 1) * lanes), (KeccakP1600Constants.LaneCount - lastRow - 1) * lanes).Clear();

		_lanes = lanes;
		_position = TRate.RateInBytes;
		Count = count;
		IsSqueezing = true;
	}

	[SkipLocalsInit]
	internal void Absorb(ReadOnlySpan<byte> inputs)
	{
		Debug.Assert(!IsSqueezing);
		Debug.Assert(inputs.Length % Count is 0);

		int length = inputs.Length / Count;
		int offset = 0;
		int position = _position;

		for (int blockLength = TRate.RateInBytes - position; length - offset >= blockLength; blockLength = TRate.RateInBytes)
		{
			XorStreams(inputs, length, offset, position, blockLength);
			Permute();
			offset += blockLength;
			position = 0;
		}

		XorStreams(inputs, length, offset, position, length - offset);
		_position = position + length - offset;
	}

	// Below 0x80, the domain separator leaves room for the last padding bit in the current block even when one byte remains. Streams from Count up to _lanes are padded too, which is harmless: only ExtractLane and CopyStreams read the state back, and both stop at Count, and a guest overwrites its lane. The permutation is left to Squeeze, or to Permute to share.
	[SkipLocalsInit]
	internal void Pad(byte domainSeparator)
	{
		Debug.Assert(!IsSqueezing);
		Debug.Assert(domainSeparator is not 0 and < LastPaddingBit);
		Debug.Assert(_position < TRate.RateInBytes);

		ref ulong state = ref _state[0][0];
		XorRow(ref Unsafe.Add(ref state, (_position >> 3) * _lanes), _lanes, (ulong)domainSeparator << 8 * (_position & 7));
		XorRow(ref Unsafe.Add(ref state, (TRate.RateInBytes / sizeof(ulong) - 1) * _lanes), _lanes, (ulong)LastPaddingBit << 56);
		_position = TRate.RateInBytes;
		IsSqueezing = true;
	}

	// Runs the pending permutation with guests (KeccakSponge.AbsorbBlock) in the free lanes; those beyond them are permuted alone.
	internal void Permute<TGuest>(Span<KeccakSponge<TGuest>> guests) where TGuest : IKeccakRate
	{
		Debug.Assert(IsSqueezing && _position == TRate.RateInBytes);

		int lanes = _lanes;
		int hosted = Math.Min(guests.Length, FreeLanes);
		ref ulong free = ref Unsafe.Add(ref _state[0][0], Count);

		for (int i = 0; i < hosted; ++i)
		{
			guests[i].ExportState(ref Unsafe.Add(ref free, i), lanes);
		}

		Permute();

		for (int i = 0; i < hosted; ++i)
		{
			guests[i].ImportPermutedState(ref Unsafe.Add(ref free, i), lanes);
		}

		for (int i = hosted; i < guests.Length; ++i)
		{
			guests[i].Permute();
		}

		_position = 0;
	}

	internal void Squeeze(Span<byte> outputs)
	{
		Squeeze(outputs, 0, outputs.Length / Count);
	}

	// Squeezes length bytes of every stream into its part of outputs from offset on, so that each permutation can go through Permute.
	[SkipLocalsInit]
	internal void Squeeze(Span<byte> outputs, int offset, int length)
	{
		Debug.Assert(IsSqueezing);
		Debug.Assert(outputs.Length % Count is 0);

		int stride = outputs.Length / Count;
		int end = offset + length;
		int position = _position;
		Debug.Assert(offset >= 0 && length >= 0 && end <= stride);

		for (int available = TRate.RateInBytes - position; end - offset > available; available = TRate.RateInBytes)
		{
			CopyStreams(outputs, stride, offset, position, available);
			Permute();
			offset += available;
			position = 0;
		}

		CopyStreams(outputs, stride, offset, position, end - offset);
		_position = position + end - offset;
	}

	[SkipLocalsInit]
	internal readonly KeccakSponge<TRate> ExtractLane(int lane)
	{
		Debug.Assert((uint)lane < (uint)Count);

		Unsafe.SkipInit(out InlineArray25<ulong> state);
		ref ulong source = ref Unsafe.Add(ref Unsafe.AsRef(in _state[0][0]), lane);

		for (int i = 0; i < KeccakP1600Constants.LaneCount; ++i)
		{
			state[i] = Unsafe.Add(ref source, i * _lanes);
		}

		return new KeccakSponge<TRate>(in state, _position, IsSqueezing);
	}

	private void Permute()
	{
		KeccakP1600Batch.Permute(_lanes, ref _state[0][0]);
	}

	private void XorStreams(ReadOnlySpan<byte> inputs, int length, int offset, int position, int count)
	{
		ref ulong state = ref _state[0][0];
		ref byte input = ref Unsafe.Add(ref MemoryMarshal.GetReference(inputs), offset);
		int lanes = _lanes;
		int streams = Count;
		int head = Math.Min(-position & 7, count);
		int words = (count - head) / sizeof(ulong);

		XorBytes(ref state, lanes, streams, position, ref input, length, head);
		position += head;
		input = ref Unsafe.Add(ref input, head);
		ref ulong word = ref Unsafe.Add(ref state, position / sizeof(ulong) * lanes);

		nint stride = length;
		int i = 0;

		if (Avx512F.IsSupported && lanes is 8 && streams is 8)
		{
			for (; i <= words - 4; i += 4)
			{
				XorWords4x8(ref word, ref input, stride);
				word = ref Unsafe.Add(ref word, 4 * 8);
				input = ref Unsafe.Add(ref input, 4 * sizeof(ulong));
			}
		}
		else if (Avx2.IsSupported && lanes is 4 && streams is 4)
		{
			for (; i <= words - 4; i += 4)
			{
				XorWords4x4(ref word, ref input, stride);
				word = ref Unsafe.Add(ref word, 4 * 4);
				input = ref Unsafe.Add(ref input, 4 * sizeof(ulong));
			}
		}

		for (; i < words; ++i)
		{
			ref byte source = ref input;

			for (int j = 0; j < streams; ++j)
			{
				Unsafe.Add(ref word, j) ^= Unsafe.ReadUnaligned<ulong>(ref source);
				source = ref Unsafe.Add(ref source, length);
			}

			word = ref Unsafe.Add(ref word, lanes);
			input = ref Unsafe.Add(ref input, sizeof(ulong));
		}

		XorBytes(ref state, lanes, streams, position + words * sizeof(ulong), ref input, length, count - head - words * sizeof(ulong));
	}

	private readonly void CopyStreams(Span<byte> outputs, int length, int offset, int position, int count)
	{
		ref ulong state = ref Unsafe.AsRef(in _state[0][0]);
		ref byte output = ref Unsafe.Add(ref MemoryMarshal.GetReference(outputs), offset);
		int lanes = _lanes;
		int streams = Count;
		int head = Math.Min(-position & 7, count);
		int words = (count - head) / sizeof(ulong);

		CopyBytes(ref state, lanes, streams, position, ref output, length, head);
		position += head;
		output = ref Unsafe.Add(ref output, head);
		ref ulong word = ref Unsafe.Add(ref state, position / sizeof(ulong) * lanes);

		nint stride = length;
		nint stride3 = 3 * stride;
		int i = 0;

		if (Avx512F.IsSupported && lanes is 8)
		{
			for (; i <= words - 8; i += 8)
			{
				CopyWords8x8(ref word, ref output, stride, streams);
				word = ref Unsafe.Add(ref word, 8 * 8);
				output = ref Unsafe.Add(ref output, 8 * sizeof(ulong));
			}
		}
		else if (Avx2.IsSupported && lanes is 4)
		{
			for (; i <= words - 4; i += 4)
			{
				CopyWords4x4(ref word, ref output, stride, streams);
				word = ref Unsafe.Add(ref word, 4 * 4);
				output = ref Unsafe.Add(ref output, 4 * sizeof(ulong));
			}
		}

		for (; i < words; ++i)
		{
			ref byte destination = ref output;
			int j = 0;

			for (; j <= streams - 4; j += 4)
			{
				Unsafe.WriteUnaligned(ref destination, Unsafe.Add(ref word, j));
				Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination, stride), Unsafe.Add(ref word, j + 1));
				Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination, 2 * stride), Unsafe.Add(ref word, j + 2));
				Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination, stride3), Unsafe.Add(ref word, j + 3));
				destination = ref Unsafe.Add(ref destination, 4 * stride);
			}

			for (; j < streams; ++j)
			{
				Unsafe.WriteUnaligned(ref destination, Unsafe.Add(ref word, j));
				destination = ref Unsafe.Add(ref destination, stride);
			}

			word = ref Unsafe.Add(ref word, lanes);
			output = ref Unsafe.Add(ref output, sizeof(ulong));
		}

		CopyBytes(ref state, lanes, streams, position + words * sizeof(ulong), ref output, length, count - head - words * sizeof(ulong));
	}

	// Stores the first streams lanes only; the rest are free or hold guests.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void CopyWords8x8(ref ulong word, ref byte output, nint stride, int streams)
	{
		Vector512<ulong> r0 = Vector512.LoadUnsafe(ref word);
		Vector512<ulong> r1 = Vector512.LoadUnsafe(ref word, 8);
		Vector512<ulong> r2 = Vector512.LoadUnsafe(ref word, 16);
		Vector512<ulong> r3 = Vector512.LoadUnsafe(ref word, 24);
		Vector512<ulong> r4 = Vector512.LoadUnsafe(ref word, 32);
		Vector512<ulong> r5 = Vector512.LoadUnsafe(ref word, 40);
		Vector512<ulong> r6 = Vector512.LoadUnsafe(ref word, 48);
		Vector512<ulong> r7 = Vector512.LoadUnsafe(ref word, 56);

		// Three rounds of two-source shuffles gather the words of each stream in twos, fours and eights: t0 holds words 0 and 1 of streams 0, 2, 4 and 6, and u0 words 0 to 3 of streams 0 and 4.
		Vector512<ulong> t0 = Avx512F.UnpackLow(r0, r1);
		Vector512<ulong> t1 = Avx512F.UnpackHigh(r0, r1);
		Vector512<ulong> t2 = Avx512F.UnpackLow(r2, r3);
		Vector512<ulong> t3 = Avx512F.UnpackHigh(r2, r3);
		Vector512<ulong> t4 = Avx512F.UnpackLow(r4, r5);
		Vector512<ulong> t5 = Avx512F.UnpackHigh(r4, r5);
		Vector512<ulong> t6 = Avx512F.UnpackLow(r6, r7);
		Vector512<ulong> t7 = Avx512F.UnpackHigh(r6, r7);

		Vector512<ulong> evenPairs = Vector512.Create(0UL, 1, 8, 9, 4, 5, 12, 13);
		Vector512<ulong> oddPairs = Vector512.Create(2UL, 3, 10, 11, 6, 7, 14, 15);
		Vector512<ulong> u0 = Avx512F.PermuteVar8x64x2(t0, evenPairs, t2);
		Vector512<ulong> u1 = Avx512F.PermuteVar8x64x2(t1, evenPairs, t3);
		Vector512<ulong> u2 = Avx512F.PermuteVar8x64x2(t0, oddPairs, t2);
		Vector512<ulong> u3 = Avx512F.PermuteVar8x64x2(t1, oddPairs, t3);
		Vector512<ulong> u4 = Avx512F.PermuteVar8x64x2(t4, evenPairs, t6);
		Vector512<ulong> u5 = Avx512F.PermuteVar8x64x2(t5, evenPairs, t7);
		Vector512<ulong> u6 = Avx512F.PermuteVar8x64x2(t4, oddPairs, t6);
		Vector512<ulong> u7 = Avx512F.PermuteVar8x64x2(t5, oddPairs, t7);

		Vector512<ulong> lowHalves = Vector512.Create(0UL, 1, 2, 3, 8, 9, 10, 11);
		Vector512<ulong> highHalves = Vector512.Create(4UL, 5, 6, 7, 12, 13, 14, 15);
		ref ulong destination = ref Unsafe.As<byte, ulong>(ref output);
		Avx512F.PermuteVar8x64x2(u0, lowHalves, u4).StoreUnsafe(ref destination);
		StoreRow(Avx512F.PermuteVar8x64x2(u1, lowHalves, u5), ref destination, stride, 1, streams);
		StoreRow(Avx512F.PermuteVar8x64x2(u2, lowHalves, u6), ref destination, stride, 2, streams);
		StoreRow(Avx512F.PermuteVar8x64x2(u3, lowHalves, u7), ref destination, stride, 3, streams);
		StoreRow(Avx512F.PermuteVar8x64x2(u0, highHalves, u4), ref destination, stride, 4, streams);
		StoreRow(Avx512F.PermuteVar8x64x2(u1, highHalves, u5), ref destination, stride, 5, streams);
		StoreRow(Avx512F.PermuteVar8x64x2(u2, highHalves, u6), ref destination, stride, 6, streams);
		StoreRow(Avx512F.PermuteVar8x64x2(u3, highHalves, u7), ref destination, stride, 7, streams);
	}

	// As CopyWords8x8, with four words of four lanes.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void CopyWords4x4(ref ulong word, ref byte output, nint stride, int streams)
	{
		Vector256<ulong> r0 = Vector256.LoadUnsafe(ref word);
		Vector256<ulong> r1 = Vector256.LoadUnsafe(ref word, 4);
		Vector256<ulong> r2 = Vector256.LoadUnsafe(ref word, 8);
		Vector256<ulong> r3 = Vector256.LoadUnsafe(ref word, 12);

		Vector256<ulong> t0 = Avx2.UnpackLow(r0, r1);
		Vector256<ulong> t1 = Avx2.UnpackHigh(r0, r1);
		Vector256<ulong> t2 = Avx2.UnpackLow(r2, r3);
		Vector256<ulong> t3 = Avx2.UnpackHigh(r2, r3);

		ref ulong destination = ref Unsafe.As<byte, ulong>(ref output);
		Avx2.Permute2x128(t0, t2, 0x20).StoreUnsafe(ref destination);
		StoreRow(Avx2.Permute2x128(t1, t3, 0x20), ref destination, stride, 1, streams);
		StoreRow(Avx2.Permute2x128(t0, t2, 0x31), ref destination, stride, 2, streams);
		StoreRow(Avx2.Permute2x128(t1, t3, 0x31), ref destination, stride, 3, streams);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void StoreRow(Vector512<ulong> row, ref ulong destination, nint stride, int stream, int streams)
	{
		if (stream < streams)
		{
			row.StoreUnsafe(ref Unsafe.AddByteOffset(ref destination, stream * stride));
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void StoreRow(Vector256<ulong> row, ref ulong destination, nint stride, int stream, int streams)
	{
		if (stream < streams)
		{
			row.StoreUnsafe(ref Unsafe.AddByteOffset(ref destination, stream * stride));
		}
	}

	// XORs four words of each of eight streams into four rows, loading two streams per vector: with streams 0 and 2 in v0 and 1 and 3 in v1, the unpacks leave a word of streams 0 and 1, or 2 and 3, in each 128-bit quarter, and one shuffle of quarters per row gathers the four pairs of a word.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void XorWords4x8(ref ulong word, ref byte input, nint stride)
	{
		ref ulong source = ref Unsafe.As<byte, ulong>(ref input);
		Vector512<ulong> v0 = Vector256.LoadUnsafe(ref source).ToVector512Unsafe().WithUpper(Vector256.LoadUnsafe(ref Unsafe.AddByteOffset(ref source, 2 * stride)));
		Vector512<ulong> v1 = Vector256.LoadUnsafe(ref Unsafe.AddByteOffset(ref source, stride)).ToVector512Unsafe().WithUpper(Vector256.LoadUnsafe(ref Unsafe.AddByteOffset(ref source, 3 * stride)));
		Vector512<ulong> v2 = Vector256.LoadUnsafe(ref Unsafe.AddByteOffset(ref source, 4 * stride)).ToVector512Unsafe().WithUpper(Vector256.LoadUnsafe(ref Unsafe.AddByteOffset(ref source, 6 * stride)));
		Vector512<ulong> v3 = Vector256.LoadUnsafe(ref Unsafe.AddByteOffset(ref source, 5 * stride)).ToVector512Unsafe().WithUpper(Vector256.LoadUnsafe(ref Unsafe.AddByteOffset(ref source, 7 * stride)));

		Vector512<ulong> t0 = Avx512F.UnpackLow(v0, v1);
		Vector512<ulong> t1 = Avx512F.UnpackHigh(v0, v1);
		Vector512<ulong> t2 = Avx512F.UnpackLow(v2, v3);
		Vector512<ulong> t3 = Avx512F.UnpackHigh(v2, v3);

		(Vector512.LoadUnsafe(ref word) ^ Avx512F.Shuffle4x128(t0, t2, 0x88)).StoreUnsafe(ref word);
		(Vector512.LoadUnsafe(ref word, 8) ^ Avx512F.Shuffle4x128(t1, t3, 0x88)).StoreUnsafe(ref word, 8);
		(Vector512.LoadUnsafe(ref word, 16) ^ Avx512F.Shuffle4x128(t0, t2, 0xDD)).StoreUnsafe(ref word, 16);
		(Vector512.LoadUnsafe(ref word, 24) ^ Avx512F.Shuffle4x128(t1, t3, 0xDD)).StoreUnsafe(ref word, 24);
	}

	// The shuffles of CopyWords4x4, as a transposition is its own inverse.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void XorWords4x4(ref ulong word, ref byte input, nint stride)
	{
		ref ulong source = ref Unsafe.As<byte, ulong>(ref input);
		Vector256<ulong> r0 = Vector256.LoadUnsafe(ref source);
		Vector256<ulong> r1 = Vector256.LoadUnsafe(ref Unsafe.AddByteOffset(ref source, stride));
		Vector256<ulong> r2 = Vector256.LoadUnsafe(ref Unsafe.AddByteOffset(ref source, 2 * stride));
		Vector256<ulong> r3 = Vector256.LoadUnsafe(ref Unsafe.AddByteOffset(ref source, 3 * stride));

		Vector256<ulong> t0 = Avx2.UnpackLow(r0, r1);
		Vector256<ulong> t1 = Avx2.UnpackHigh(r0, r1);
		Vector256<ulong> t2 = Avx2.UnpackLow(r2, r3);
		Vector256<ulong> t3 = Avx2.UnpackHigh(r2, r3);

		(Vector256.LoadUnsafe(ref word) ^ Avx2.Permute2x128(t0, t2, 0x20)).StoreUnsafe(ref word);
		(Vector256.LoadUnsafe(ref word, 4) ^ Avx2.Permute2x128(t1, t3, 0x20)).StoreUnsafe(ref word, 4);
		(Vector256.LoadUnsafe(ref word, 8) ^ Avx2.Permute2x128(t0, t2, 0x31)).StoreUnsafe(ref word, 8);
		(Vector256.LoadUnsafe(ref word, 12) ^ Avx2.Permute2x128(t1, t3, 0x31)).StoreUnsafe(ref word, 12);
	}

	private static void XorRow(ref ulong row, int lanes, ulong value)
	{
		switch (lanes)
		{
			case 8:
			{
				(Vector512.LoadUnsafe(ref row) ^ Vector512.Create(value)).StoreUnsafe(ref row);
				break;
			}
			case 4:
			{
				(Vector256.LoadUnsafe(ref row) ^ Vector256.Create(value)).StoreUnsafe(ref row);
				break;
			}
			case 2:
			{
				(Vector128.LoadUnsafe(ref row) ^ Vector128.Create(value)).StoreUnsafe(ref row);
				break;
			}
			default:
			{
				row ^= value;
				break;
			}
		}
	}

	private static void FillRow(ref ulong row, int lanes, ulong value)
	{
		switch (lanes)
		{
			case 8:
			{
				Vector512.Create(value).StoreUnsafe(ref row);
				break;
			}
			case 4:
			{
				Vector256.Create(value).StoreUnsafe(ref row);
				break;
			}
			case 2:
			{
				Vector128.Create(value).StoreUnsafe(ref row);
				break;
			}
			default:
			{
				row = value;
				break;
			}
		}
	}

	// Bytes in the outer loop, as count is mostly 0.
	private static void XorBytes(ref ulong state, int lanes, int streams, int position, ref byte input, int length, int count)
	{
		for (int k = 0; k < count; ++k)
		{
			for (int j = 0; j < streams; ++j)
			{
				ByteAt(ref Unsafe.Add(ref state, j), lanes, position + k) ^= Unsafe.Add(ref input, j * length + k);
			}
		}
	}

	private static void CopyBytes(ref ulong state, int lanes, int streams, int position, ref byte output, int length, int count)
	{
		for (int k = 0; k < count; ++k)
		{
			for (int j = 0; j < streams; ++j)
			{
				Unsafe.Add(ref output, j * length + k) = ByteAt(ref Unsafe.Add(ref state, j), lanes, position + k);
			}
		}
	}

	// As in KeccakSponge, byte k of a lane is its k-th least significant byte, which assumes a little-endian platform.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ref byte ByteAt(ref ulong lanes, int stride, int position)
	{
		return ref Unsafe.Add(ref Unsafe.As<ulong, byte>(ref Unsafe.Add(ref lanes, (position >> 3) * stride)), position & 7);
	}
}
