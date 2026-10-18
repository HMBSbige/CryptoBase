namespace CryptoBase.Hashes.Sha3;

// The sponge construction of FIPS 202, Sec. 4 and 5, over Keccak-p[1600, 24] with byte-aligned input and output.
// The state itself buffers partial blocks, so whole input blocks are XORed in without copying.
internal struct KeccakSponge<TRate> where TRate : IKeccakRate
{
	private const byte LastPaddingBit = 0x80;

	private InlineArray25<ulong> _state;

	// Bytes of the current block absorbed so far, or squeezed so far; always below the rate while absorbing.
	private int _position;

	internal bool IsSqueezing { get; private set; }

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

	private void AbsorbBlocks(ReadOnlySpan<byte> source, int position, int bytesNeeded)
	{
		if (position is not 0)
		{
			XorBytes(position, source.Slice(0, bytesNeeded));
			KeccakP1600.Permute(ref _state);
			source = source.Slice(bytesNeeded);
		}

		if (KeccakP1600.IsAvx512Supported && source.Length >= TRate.RateInBytes)
		{
			source = source.Slice(KeccakP1600.AbsorbAvx512<TRate>(ref _state, source));
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

	// Below 0x80, the domain separator leaves room for the last padding bit in the current block even when one byte remains.
	internal void Pad(byte domainSeparator)
	{
		Debug.Assert(!IsSqueezing);
		Debug.Assert(domainSeparator is not 0 and < LastPaddingBit);
		Debug.Assert(_position < TRate.RateInBytes);

		ref byte state = ref Unsafe.As<ulong, byte>(ref _state[0]);
		Unsafe.Add(ref state, _position) ^= domainSeparator;
		Unsafe.Add(ref state, TRate.RateInBytes - 1) ^= LastPaddingBit;
		KeccakP1600.Permute(ref _state);
		_position = 0;
		IsSqueezing = true;
	}

	// Output continues across calls; the permutation runs only when more output is requested than the current block holds.
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
			KeccakP1600.Permute(ref _state);
			position = 0;
			available = TRate.RateInBytes;
		}

		state.Slice(position, destination.Length).CopyTo(destination);
		_position = position + destination.Length;
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
