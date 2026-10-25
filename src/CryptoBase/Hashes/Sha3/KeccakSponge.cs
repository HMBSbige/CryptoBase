namespace CryptoBase.Hashes.Sha3;

// The sponge construction of FIPS 202, Sec. 4 and 5, over Keccak-p[1600, 24] with byte-aligned input and output. The state itself buffers partial blocks, so whole input blocks are XORed in without copying.
internal struct KeccakSponge<TRate> where TRate : IKeccakRate
{
	private const byte LastPaddingBit = 0x80;

	private InlineArray25<ulong> _state;

	// Bytes of the current block absorbed so far, or squeezed so far; always below the rate while absorbing.
	private int _position;

	internal bool IsSqueezing { get; private set; }

	// Lets KeccakBatchSponge hand one of its streams over to go on alone.
	internal KeccakSponge(in InlineArray25<ulong> state, int position, bool isSqueezing)
	{
		_state = state;
		_position = position;
		IsSqueezing = isSqueezing;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal void Reset()
	{
		this = default;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal void Absorb(ReadOnlySpan<byte> source)
	{
		Debug.Assert(!IsSqueezing);

		int position = _position;
		int bytesNeeded = TRate.RateInBytes - position;

		if (source.Length < bytesNeeded)
		{
			XorBytes(position, source);
			_position = position + source.Length;
			return;
		}

		AbsorbBlocks(source, position, bytesNeeded);
	}

	[SkipLocalsInit]
	private void AbsorbBlocks(ReadOnlySpan<byte> source, int position, int bytesNeeded)
	{
		if (position is not 0)
		{
			XorBytes(position, source.Slice(0, bytesNeeded));
			KeccakP1600.Permute(ref _state);
			source = source.Slice(bytesNeeded);
		}

		if (KeccakP1600.PreferAvx512 && source.Length >= TRate.RateInBytes)
		{
			source = source.Slice(KeccakP1600.AbsorbAvx512<TRate>(ref _state, source));
		}
		else if (KeccakP1600Lane128.IsSupported && source.Length >= TRate.RateInBytes)
		{
			source = source.Slice(KeccakP1600.AbsorbLane128<TRate>(ref _state, source));
		}

		while (source.Length >= TRate.RateInBytes)
		{
			XorBlock(ref _state[0], ref MemoryMarshal.GetReference(source));
			KeccakP1600.Permute(ref _state);
			source = source.Slice(TRate.RateInBytes);
		}

		if (!source.IsEmpty)
		{
			XorBytes(0, source);
		}

		_position = source.Length;
	}

	// Ends a partial block as though zeros filled the rest, as bytepad does (SP 800-185, Sec. 2.3.3): XORing zeros leaves the state unchanged, so only the permutation remains. At a block boundary there is nothing to fill.
	internal void FinishBlock()
	{
		Debug.Assert(!IsSqueezing);

		if (_position is not 0)
		{
			KeccakP1600.Permute(ref _state);
			_position = 0;
		}
	}

	// Absorbs the length low-order bytes of bytes, least significant first, as Sp800_185Encoding packs them. The bytes past the length are zero and the state extends more than a word past the rate, so a block that the bytes do not fill takes them in one XOR.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal void AbsorbWord(ulong bytes, int length)
	{
		Debug.Assert(!IsSqueezing);
		Debug.Assert(length is > 0 and < sizeof(ulong) ? bytes >> length * 8 is 0 : length is sizeof(ulong));

		int position = _position;
		int bytesNeeded = TRate.RateInBytes - position;

		if (length < bytesNeeded)
		{
			ref byte state = ref Unsafe.Add(ref Unsafe.As<ulong, byte>(ref _state[0]), position);
			Unsafe.WriteUnaligned(ref state, Unsafe.ReadUnaligned<ulong>(ref state) ^ bytes);
			_position = position + length;
			return;
		}

		AbsorbWordBlocks(bytes, length, position, bytesNeeded);
	}

	// Since the length is below the rate, the bytes end the block, and any rest starts the next one.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private void AbsorbWordBlocks(ulong bytes, int length, int position, int bytesNeeded)
	{
		AbsorbBlocks(MemoryMarshal.AsBytes(new ReadOnlySpan<ulong>(in bytes)).Slice(0, length), position, bytesNeeded);
	}

	// Absorbs source, pads it and squeezes destination, starting from the zero state. All input is absorbed before any output is written, so the two may overlap.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void HashData(ReadOnlySpan<byte> source, Span<byte> destination, byte domainSeparator)
	{
		if (source.Length < TRate.RateInBytes && destination.Length <= TRate.RateInBytes)
		{
			HashBlock(source, destination, domainSeparator);
			return;
		}

		Unsafe.SkipInit(out KeccakSponge<TRate> sponge);
		sponge.Reset();
		sponge.Absorb(source);
		sponge.Pad(domainSeparator);
		sponge.Squeeze(destination);
	}

	// With one block in and one out, the state is zero apart from the input and its padding, so the input is copied in rather than XORed, and the output read straight after the one permutation.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void HashBlock(ReadOnlySpan<byte> source, Span<byte> destination, byte domainSeparator)
	{
		Debug.Assert(source.Length < TRate.RateInBytes);
		Debug.Assert(destination.Length <= TRate.RateInBytes);
		Debug.Assert(domainSeparator is not 0 and < LastPaddingBit);

		InlineArray25<ulong> state = default;
		Span<byte> bytes = state.AsSpan();
		source.CopyTo(bytes);
		ref byte block = ref MemoryMarshal.GetReference(bytes);
		Unsafe.Add(ref block, source.Length) = domainSeparator;
		Unsafe.Add(ref block, TRate.RateInBytes - 1) |= LastPaddingBit;
		KeccakP1600.Permute(ref state);
		bytes.Slice(0, destination.Length).CopyTo(destination);
	}

	internal void Pad(byte domainSeparator)
	{
		Debug.Assert(!IsSqueezing);
		Debug.Assert(_position < TRate.RateInBytes);

		XorPadding(_position, domainSeparator);
		KeccakP1600.Permute(ref _state);
		_position = 0;
		IsSqueezing = true;
	}

	// Absorbs up to the end of the block, padding if source ends first, and returns the bytes absorbed. The permutation is left to the caller, so that it can run beside other states.
	internal int AbsorbBlock(ReadOnlySpan<byte> source, byte domainSeparator)
	{
		Debug.Assert(!IsSqueezing);
		Debug.Assert(_position < TRate.RateInBytes);

		int position = _position;
		int count = Math.Min(source.Length, TRate.RateInBytes - position);
		XorBytes(position, source.Slice(0, count));
		position += count;

		if (position < TRate.RateInBytes)
		{
			XorPadding(position, domainSeparator);
			IsSqueezing = true;
		}

		_position = TRate.RateInBytes;
		return count;
	}

	// After AbsorbBlock, or once a whole block has been squeezed.
	internal readonly bool AwaitsPermutation => _position == TRate.RateInBytes;

	internal void Permute()
	{
		Debug.Assert(AwaitsPermutation);

		KeccakP1600.Permute(ref _state);
		_position = 0;
	}

	// Every stride-th word, as the interleaved kernels lay out a batch.
	internal readonly void ExportState(ref ulong lanes, int stride)
	{
		Debug.Assert(AwaitsPermutation);

		for (int i = 0; i < KeccakP1600Constants.LaneCount; ++i)
		{
			Unsafe.Add(ref lanes, i * stride) = _state[i];
		}
	}

	internal void ImportPermutedState(ref ulong lanes, int stride)
	{
		Debug.Assert(AwaitsPermutation);

		for (int i = 0; i < KeccakP1600Constants.LaneCount; ++i)
		{
			_state[i] = Unsafe.Add(ref lanes, i * stride);
		}

		_position = 0;
	}

	// Output continues across calls; the permutation runs only when more output is requested than the current block holds.
	[SkipLocalsInit]
	internal void Squeeze(Span<byte> destination)
	{
		Debug.Assert(IsSqueezing);

		Span<byte> state = _state.AsSpan();
		int position = _position;
		int available = TRate.RateInBytes - position;

		while (destination.Length > available)
		{
			state.Slice(position, available).CopyTo(destination);
			destination = destination.Slice(available);

			// Passing one byte less leaves the last block, whole or not, to the permutation below, so that the state ends holding it either way.
			if (KeccakP1600.PreferAvx512 && destination.Length > TRate.RateInBytes)
			{
				destination = destination.Slice(KeccakP1600.SqueezeAvx512<TRate>(ref _state, destination.Slice(0, destination.Length - 1)));
			}
			else if (KeccakP1600Lane128.IsSupported && destination.Length > TRate.RateInBytes)
			{
				destination = destination.Slice(KeccakP1600.SqueezeLane128<TRate>(ref _state, destination.Slice(0, destination.Length - 1)));
			}

			KeccakP1600.Permute(ref _state);
			position = 0;
			available = TRate.RateInBytes;
		}

		state.Slice(position, destination.Length).CopyTo(destination);
		_position = position + destination.Length;
	}

	// Below 0x80, the domain separator leaves room for the last padding bit in the current block even when one byte remains.
	private void XorPadding(int position, byte domainSeparator)
	{
		Debug.Assert(domainSeparator is not 0 and < LastPaddingBit);

		ref byte state = ref Unsafe.As<ulong, byte>(ref _state[0]);
		Unsafe.Add(ref state, position) ^= domainSeparator;
		Unsafe.Add(ref state, TRate.RateInBytes - 1) ^= LastPaddingBit;
	}

	private void XorBytes(int position, ReadOnlySpan<byte> source)
	{
		Debug.Assert(position + source.Length <= TRate.RateInBytes);

		Span<byte> state = MemoryMarshal.CreateSpan(ref Unsafe.Add(ref Unsafe.As<ulong, byte>(ref _state[0]), position), source.Length);
		FastUtils.Xor(state, source, state, source.Length);
	}

	// RyuJIT leaves this constant-count loop rolled, hence the four lanes per iteration.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void XorBlock(ref ulong state, ref byte block)
	{
		int remainingLanes = TRate.RateInBytes / sizeof(ulong);

		for (; remainingLanes >= 4; remainingLanes -= 4)
		{
			state ^= Unsafe.ReadUnaligned<ulong>(ref block);
			Unsafe.Add(ref state, 1) ^= Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref block, 8));
			Unsafe.Add(ref state, 2) ^= Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref block, 16));
			Unsafe.Add(ref state, 3) ^= Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref block, 24));
			state = ref Unsafe.Add(ref state, 4);
			block = ref Unsafe.Add(ref block, 4 * sizeof(ulong));
		}

		for (; remainingLanes > 0; --remainingLanes)
		{
			state ^= Unsafe.ReadUnaligned<ulong>(ref block);
			state = ref Unsafe.Add(ref state, 1);
			block = ref Unsafe.Add(ref block, sizeof(ulong));
		}
	}
}
