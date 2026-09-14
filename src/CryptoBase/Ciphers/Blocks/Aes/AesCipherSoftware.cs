namespace CryptoBase.Ciphers.Blocks.Aes;

internal partial struct AesCipherSoftware : IDisposable
{
	private readonly int _rounds;
	private InlineArray15<InlineArray8<ulong>> _roundKeys;

	private AesCipherSoftware(ReadOnlySpan<byte> key)
	{
		_rounds = key.Length switch
		{
			16 => 10,
			24 => 12,
			32 => 14,
			_ => ThrowHelper.ThrowArgumentOutOfRangeException<int>(nameof(key), "Key length must be 16/24/32 bytes")
		};

		Span<uint> words = stackalloc uint[60];
		int nk = key.Length / sizeof(uint);
		int wordCount = (_rounds + 1) * 4;

		for (int i = 0; i < nk; ++i)
		{
			words[i] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(i * sizeof(uint)));
		}

		for (int i = nk; i < wordCount; ++i)
		{
			uint t = words[i - 1];

			if (i % nk is 0)
			{
				t = SubWord(t).RotateRight(8) ^ AesCipher.Rcon[i / nk];
			}
			else if (nk is 8 && i % nk is 4)
			{
				t = SubWord(t);
			}

			words[i] = words[i - nk] ^ t;
		}

		for (int round = 0; round <= _rounds; ++round)
		{
			ref InlineArray8<ulong> roundKey = ref _roundKeys[round];
			ulong low = Interleave(words[round * 4], words[round * 4 + 2]);
			ulong high = Interleave(words[round * 4 + 1], words[round * 4 + 3]);

			for (int block = 0; block < 4; ++block)
			{
				roundKey[block] = low;
				roundKey[block + 4] = high;
			}

			Transpose(ref roundKey);

			if (round != _rounds)
			{
				ShiftRows(ref roundKey, 4 - round & 3);
			}

			if (round > 0)
			{
				// Fold the S-box's omitted NOTs into the round key.
				SubBytesNots(ref roundKey);
			}
		}

		words.ZeroMemory();
	}

	public static AesCipherSoftware Create(ReadOnlySpan<byte> key)
	{
		return new AesCipherSoftware(key);
	}

	public void Dispose()
	{
		_roundKeys.ZeroMemory();
	}

	// Four blocks share eight scalar bit planes. Round layouts cycle every four rounds.
	public readonly void EncryptBlocks(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ref byte input = ref source.GetReference();
		ref byte output = ref destination.GetReference();
		int remaining = source.Length;
		int rounds = _rounds;
		InlineArray8<ulong> state = default;

		while (remaining > 0)
		{
			int length = Math.Min(remaining, 64);
			Load(ref state, ref input, length);
			ref readonly InlineArray8<ulong> key = ref _roundKeys[0];
			AddRoundKey(ref state, in key);

			for (int round = 1; round < rounds; round += 2)
			{
				state = SubBytes(in state);
				key = ref Unsafe.Add(ref Unsafe.AsRef(in key), 1);
				state = (round & 2) is 0 ? MixColumns(state, in key, 1) : MixColumns(state, in key, 3);

				if (round + 1 == rounds)
				{
					break;
				}

				state = SubBytes(in state);
				key = ref Unsafe.Add(ref Unsafe.AsRef(in key), 1);

				state = (round & 2) is 0 ? MixColumns(state, in key, 2) : MixColumns(state, in key, 0);
			}

			if (rounds is not 12)
			{
				ShiftRowsTwo(ref state);
			}

			state = SubBytes(in state);
			key = ref Unsafe.Add(ref Unsafe.AsRef(in key), 1);
			AddRoundKey(ref state, in key);
			Store(ref state, ref output, length);
			input = ref Unsafe.Add(ref input, length);
			output = ref Unsafe.Add(ref output, length);
			remaining -= length;
		}

		state.ZeroMemory();
	}

	public readonly void DecryptBlocks(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ref byte input = ref source.GetReference();
		ref byte output = ref destination.GetReference();
		int remaining = source.Length;
		int rounds = _rounds;
		ref readonly InlineArray8<ulong> finalKey = ref Unsafe.Add(ref Unsafe.AsRef(in _roundKeys[0]), rounds);
		InlineArray8<ulong> state = default;

		while (remaining > 0)
		{
			int length = Math.Min(remaining, 64);
			Load(ref state, ref input, length);
			ref readonly InlineArray8<ulong> key = ref finalKey;
			AddRoundKey(ref state, in key);
			state = InverseSubBytes(in state);

			if (rounds is not 12)
			{
				ShiftRowsTwo(ref state);
			}

			for (int round = rounds - 1; round > 0; round -= 2)
			{
				key = ref Unsafe.Subtract(ref Unsafe.AsRef(in key), 1);

				state = (round & 2) is 0 ? InverseMixColumns(in state, in key, 1) : InverseMixColumns(in state, in key, 3);

				state = InverseSubBytes(in state);

				if (round is 1)
				{
					break;
				}

				key = ref Unsafe.Subtract(ref Unsafe.AsRef(in key), 1);

				state = (round & 2) is 0 ? InverseMixColumns(in state, in key, 0) : InverseMixColumns(in state, in key, 2);

				state = InverseSubBytes(in state);
			}

			AddRoundKey(ref state, in _roundKeys[0]);
			Store(ref state, ref output, length);
			input = ref Unsafe.Add(ref input, length);
			output = ref Unsafe.Add(ref output, length);
			remaining -= length;
		}

		state.ZeroMemory();
	}

	private static uint SubWord(uint value)
	{
		InlineArray8<ulong> state = default;
		((Span<ulong>)state).Fill(value | (ulong)value << 32);
		Transpose(ref state);
		state = SubBytes(in state);
		SubBytesNots(ref state);
		Transpose(ref state);
		uint result = (uint)state[0];
		state.ZeroMemory();
		return result;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void AddRoundKey(ref InlineArray8<ulong> state, in InlineArray8<ulong> key)
	{
		ReadOnlySpan<ulong> words = key;
		state[0] ^= words[0];
		state[1] ^= words[1];
		state[2] ^= words[2];
		state[3] ^= words[3];
		state[4] ^= words[4];
		state[5] ^= words[5];
		state[6] ^= words[6];
		state[7] ^= words[7];
	}
}
