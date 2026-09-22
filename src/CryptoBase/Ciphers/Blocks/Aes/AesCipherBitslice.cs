namespace CryptoBase.Ciphers.Blocks.Aes;

internal partial struct AesCipherBitslice : IDisposable
{
	public static bool IsSupported => Sse2.IsSupported;

	internal const int BatchSize = 128;

	private readonly int _rounds;
	private InlineArray15<InlineArray8<Vector128<byte>>> _roundKeys;

	private AesCipherBitslice(ReadOnlySpan<byte> key)
	{
		Span<uint> words = stackalloc uint[60];
		_rounds = AesCipherSoftware.ExpandKey(key, words);

		InitializeRoundKeys(words);

		words.ZeroMemory();
	}

	private AesCipherBitslice(ReadOnlySpan<uint> words, int rounds)
	{
		_rounds = rounds;
		InitializeRoundKeys(words);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void InitializeRoundKeys(ReadOnlySpan<uint> words)
	{
		for (int round = 0; round <= _rounds; ++round)
		{
			ref InlineArray8<Vector128<byte>> roundKey = ref _roundKeys[round];
			Vector128<byte> keyBytes = Vector128.Create(words[round * 4], words[round * 4 + 1], words[round * 4 + 2], words[round * 4 + 3]).AsByte();
			((Span<Vector128<byte>>)roundKey).Fill(TransposeBytes(keyBytes));
			Transpose(ref roundKey);

			if (round > 0)
			{
				SubBytesNots(ref roundKey);
			}
		}
	}

	public static AesCipherBitslice Create(ReadOnlySpan<byte> key)
	{
		return new AesCipherBitslice(key);
	}

	public static AesCipherBitslice Create(ReadOnlySpan<uint> words, int rounds)
	{
		return new AesCipherBitslice(words, rounds);
	}

	public void Dispose()
	{
		_roundKeys.ZeroMemory();
	}

	public readonly void EncryptBlocks(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ref byte input = ref source.GetReference();
		ref byte output = ref destination.GetReference();
		int remaining = source.Length;
		int rounds = _rounds;

		while (remaining > 0)
		{
			int length = Math.Min(remaining, BatchSize);
			EncryptBatch(ref input, ref output, length, rounds);
			input = ref Unsafe.Add(ref input, length);
			output = ref Unsafe.Add(ref output, length);
			remaining -= length;
		}
	}

	public readonly void DecryptBlocks(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ref byte input = ref source.GetReference();
		ref byte output = ref destination.GetReference();
		int remaining = source.Length;
		int rounds = _rounds;

		while (remaining > 0)
		{
			int length = Math.Min(remaining, BatchSize);
			DecryptBatch(ref input, ref output, length, rounds);
			input = ref Unsafe.Add(ref input, length);
			output = ref Unsafe.Add(ref output, length);
			remaining -= length;
		}
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private readonly void EncryptBatch(ref byte input, ref byte output, int length, int rounds)
	{
		InlineArray8<Vector128<byte>> state = default;
		Load(ref state, ref input, length);
		EncryptState(ref state, rounds);
		Store(ref state, ref output, length);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private readonly void DecryptBatch(ref byte input, ref byte output, int length, int rounds)
	{
		InlineArray8<Vector128<byte>> state = default;
		Load(ref state, ref input, length);
		DecryptState(ref state, rounds);
		Store(ref state, ref output, length);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private readonly void EncryptState(ref InlineArray8<Vector128<byte>> state, int rounds)
	{
		Vector128<byte> q0 = state[0];
		Vector128<byte> q1 = state[1];
		Vector128<byte> q2 = state[2];
		Vector128<byte> q3 = state[3];
		Vector128<byte> q4 = state[4];
		Vector128<byte> q5 = state[5];
		Vector128<byte> q6 = state[6];
		Vector128<byte> q7 = state[7];
		ref readonly InlineArray8<Vector128<byte>> key = ref _roundKeys[0];
		AddRoundKey(ref q0, ref q1, ref q2, ref q3, ref q4, ref q5, ref q6, ref q7, in key);

		for (int round = 1; round < rounds; ++round)
		{
			SubBytesAndShiftRows(ref q0, ref q1, ref q2, ref q3, ref q4, ref q5, ref q6, ref q7);
			MixColumns(ref q0, ref q1, ref q2, ref q3, ref q4, ref q5, ref q6, ref q7);
			key = ref Unsafe.Add(ref Unsafe.AsRef(in key), 1);
			AddRoundKey(ref q0, ref q1, ref q2, ref q3, ref q4, ref q5, ref q6, ref q7, in key);
		}

		SubBytesAndShiftRows(ref q0, ref q1, ref q2, ref q3, ref q4, ref q5, ref q6, ref q7);
		key = ref Unsafe.Add(ref Unsafe.AsRef(in key), 1);
		AddRoundKey(ref q0, ref q1, ref q2, ref q3, ref q4, ref q5, ref q6, ref q7, in key);
		state[0] = q0;
		state[1] = q1;
		state[2] = q2;
		state[3] = q3;
		state[4] = q4;
		state[5] = q5;
		state[6] = q6;
		state[7] = q7;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private readonly void DecryptState(ref InlineArray8<Vector128<byte>> state, int rounds)
	{
		Vector128<byte> q0 = state[0];
		Vector128<byte> q1 = state[1];
		Vector128<byte> q2 = state[2];
		Vector128<byte> q3 = state[3];
		Vector128<byte> q4 = state[4];
		Vector128<byte> q5 = state[5];
		Vector128<byte> q6 = state[6];
		Vector128<byte> q7 = state[7];
		ref readonly InlineArray8<Vector128<byte>> key = ref Unsafe.Add(ref Unsafe.AsRef(in _roundKeys[0]), rounds);
		AddRoundKey(ref q0, ref q1, ref q2, ref q3, ref q4, ref q5, ref q6, ref q7, in key);
		ShiftRows(ref q0, ref q1, ref q2, ref q3, ref q4, ref q5, ref q6, ref q7, true);
		InverseSubBytes(ref q0, ref q1, ref q2, ref q3, ref q4, ref q5, ref q6, ref q7);

		for (int round = rounds - 1; round > 0; --round)
		{
			key = ref Unsafe.Subtract(ref Unsafe.AsRef(in key), 1);
			AddRoundKey(ref q0, ref q1, ref q2, ref q3, ref q4, ref q5, ref q6, ref q7, in key);
			InverseMixColumns(ref q0, ref q1, ref q2, ref q3, ref q4, ref q5, ref q6, ref q7);
			ShiftRows(ref q0, ref q1, ref q2, ref q3, ref q4, ref q5, ref q6, ref q7, true);
			InverseSubBytes(ref q0, ref q1, ref q2, ref q3, ref q4, ref q5, ref q6, ref q7);
		}

		AddRoundKey(ref q0, ref q1, ref q2, ref q3, ref q4, ref q5, ref q6, ref q7, in _roundKeys[0]);
		state[0] = q0;
		state[1] = q1;
		state[2] = q2;
		state[3] = q3;
		state[4] = q4;
		state[5] = q5;
		state[6] = q6;
		state[7] = q7;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void SubBytesAndShiftRows(ref Vector128<byte> q0, ref Vector128<byte> q1, ref Vector128<byte> q2, ref Vector128<byte> q3, ref Vector128<byte> q4, ref Vector128<byte> q5, ref Vector128<byte> q6, ref Vector128<byte> q7)
	{
		if (Ssse3.IsSupported)
		{
			ShiftRows(ref q0, ref q1, ref q2, ref q3, ref q4, ref q5, ref q6, ref q7, false);
			SubBytes(ref q0, ref q1, ref q2, ref q3, ref q4, ref q5, ref q6, ref q7);
		}
		else
		{
			SubBytes(ref q0, ref q1, ref q2, ref q3, ref q4, ref q5, ref q6, ref q7);
			ShiftRows(ref q0, ref q1, ref q2, ref q3, ref q4, ref q5, ref q6, ref q7, false);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void AddRoundKey(ref Vector128<byte> q0, ref Vector128<byte> q1, ref Vector128<byte> q2, ref Vector128<byte> q3, ref Vector128<byte> q4, ref Vector128<byte> q5, ref Vector128<byte> q6, ref Vector128<byte> q7, in InlineArray8<Vector128<byte>> key)
	{
		q0 ^= key[0];
		q1 ^= key[1];
		q2 ^= key[2];
		q3 ^= key[3];
		q4 ^= key[4];
		q5 ^= key[5];
		q6 ^= key[6];
		q7 ^= key[7];
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ShiftRows(ref Vector128<byte> q0, ref Vector128<byte> q1, ref Vector128<byte> q2, ref Vector128<byte> q3, ref Vector128<byte> q4, ref Vector128<byte> q5, ref Vector128<byte> q6, ref Vector128<byte> q7, bool inverse)
	{
		q0 = ShiftRows(q0, inverse);
		q1 = ShiftRows(q1, inverse);
		q2 = ShiftRows(q2, inverse);
		q3 = ShiftRows(q3, inverse);
		q4 = ShiftRows(q4, inverse);
		q5 = ShiftRows(q5, inverse);
		q6 = ShiftRows(q6, inverse);
		q7 = ShiftRows(q7, inverse);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void MixColumns(ref Vector128<byte> q0, ref Vector128<byte> q1, ref Vector128<byte> q2, ref Vector128<byte> q3, ref Vector128<byte> q4, ref Vector128<byte> q5, ref Vector128<byte> q6, ref Vector128<byte> q7)
	{
		Vector128<byte> rotated = q7.AsUInt32().RotateWordsLeft(1).AsByte();
		Vector128<byte> u7 = q7 ^ rotated;
		q7 = rotated;

		rotated = q0.AsUInt32().RotateWordsLeft(1).AsByte();
		Vector128<byte> previous = q0 ^ rotated;
		q0 = rotated ^ previous.AsUInt32().RotateWordsLeft(2).AsByte() ^ u7;

		rotated = q1.AsUInt32().RotateWordsLeft(1).AsByte();
		Vector128<byte> current = q1 ^ rotated;
		q1 = rotated ^ current.AsUInt32().RotateWordsLeft(2).AsByte() ^ previous ^ u7;
		previous = current;

		rotated = q2.AsUInt32().RotateWordsLeft(1).AsByte();
		current = q2 ^ rotated;
		q2 = rotated ^ current.AsUInt32().RotateWordsLeft(2).AsByte() ^ previous;
		previous = current;

		rotated = q3.AsUInt32().RotateWordsLeft(1).AsByte();
		current = q3 ^ rotated;
		q3 = rotated ^ current.AsUInt32().RotateWordsLeft(2).AsByte() ^ previous ^ u7;
		previous = current;

		rotated = q4.AsUInt32().RotateWordsLeft(1).AsByte();
		current = q4 ^ rotated;
		q4 = rotated ^ current.AsUInt32().RotateWordsLeft(2).AsByte() ^ previous ^ u7;
		previous = current;

		rotated = q5.AsUInt32().RotateWordsLeft(1).AsByte();
		current = q5 ^ rotated;
		q5 = rotated ^ current.AsUInt32().RotateWordsLeft(2).AsByte() ^ previous;
		previous = current;

		rotated = q6.AsUInt32().RotateWordsLeft(1).AsByte();
		current = q6 ^ rotated;
		q6 = rotated ^ current.AsUInt32().RotateWordsLeft(2).AsByte() ^ previous;
		q7 ^= u7.AsUInt32().RotateWordsLeft(2).AsByte() ^ current;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void InverseMixColumns(ref Vector128<byte> q0, ref Vector128<byte> q1, ref Vector128<byte> q2, ref Vector128<byte> q3, ref Vector128<byte> q4, ref Vector128<byte> q5, ref Vector128<byte> q6, ref Vector128<byte> q7)
	{
		Vector128<byte> u6 = q6 ^ q6.AsUInt32().RotateWordsLeft(2).AsByte();
		Vector128<byte> u7 = q7 ^ q7.AsUInt32().RotateWordsLeft(2).AsByte();
		Vector128<byte> u0 = q0 ^ q0.AsUInt32().RotateWordsLeft(2).AsByte();
		q0 ^= u6;
		Vector128<byte> u1 = q1 ^ q1.AsUInt32().RotateWordsLeft(2).AsByte();
		q1 ^= u7 ^ u6;
		Vector128<byte> u2 = q2 ^ q2.AsUInt32().RotateWordsLeft(2).AsByte();
		q2 ^= u0 ^ u7;
		Vector128<byte> u3 = q3 ^ q3.AsUInt32().RotateWordsLeft(2).AsByte();
		q3 ^= u1 ^ u6;
		Vector128<byte> u4 = q4 ^ q4.AsUInt32().RotateWordsLeft(2).AsByte();
		q4 ^= u2 ^ u7 ^ u6;
		Vector128<byte> u5 = q5 ^ q5.AsUInt32().RotateWordsLeft(2).AsByte();
		q5 ^= u3 ^ u7;
		q6 ^= u4;
		q7 ^= u5;
		MixColumns(ref q0, ref q1, ref q2, ref q3, ref q4, ref q5, ref q6, ref q7);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Load(ref InlineArray8<Vector128<byte>> state, ref byte source, int length)
	{
		LoadLayout(ref state, ref source, length);
		Transpose(ref state);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void LoadLayout(ref InlineArray8<Vector128<byte>> state, ref byte source, int length)
	{
		state[0] = TransposeBytes(Vector128.LoadUnsafe(ref source));

		if (length >= 32)
		{
			state[1] = TransposeBytes(Vector128.LoadUnsafe(ref source, 16));
		}

		if (length >= 48)
		{
			state[2] = TransposeBytes(Vector128.LoadUnsafe(ref source, 32));
		}

		if (length >= 64)
		{
			state[3] = TransposeBytes(Vector128.LoadUnsafe(ref source, 48));
		}

		if (length >= 80)
		{
			state[4] = TransposeBytes(Vector128.LoadUnsafe(ref source, 64));
		}

		if (length >= 96)
		{
			state[5] = TransposeBytes(Vector128.LoadUnsafe(ref source, 80));
		}

		if (length >= 112)
		{
			state[6] = TransposeBytes(Vector128.LoadUnsafe(ref source, 96));
		}

		if (length >= 128)
		{
			state[7] = TransposeBytes(Vector128.LoadUnsafe(ref source, 112));
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Store(ref InlineArray8<Vector128<byte>> state, ref byte destination, int length)
	{
		Transpose(ref state);
		TransposeBytes(state[0]).StoreUnsafe(ref destination);

		if (length >= 32)
		{
			TransposeBytes(state[1]).StoreUnsafe(ref destination, 16);
		}

		if (length >= 48)
		{
			TransposeBytes(state[2]).StoreUnsafe(ref destination, 32);
		}

		if (length >= 64)
		{
			TransposeBytes(state[3]).StoreUnsafe(ref destination, 48);
		}

		if (length >= 80)
		{
			TransposeBytes(state[4]).StoreUnsafe(ref destination, 64);
		}

		if (length >= 96)
		{
			TransposeBytes(state[5]).StoreUnsafe(ref destination, 80);
		}

		if (length >= 112)
		{
			TransposeBytes(state[6]).StoreUnsafe(ref destination, 96);
		}

		if (length >= 128)
		{
			TransposeBytes(state[7]).StoreUnsafe(ref destination, 112);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Transpose(ref InlineArray8<Vector128<byte>> state)
	{
		Vector128<byte> q0 = state[0];
		Vector128<byte> q1 = state[1];
		Vector128<byte> q2 = state[2];
		Vector128<byte> q3 = state[3];
		Vector128<byte> q4 = state[4];
		Vector128<byte> q5 = state[5];
		Vector128<byte> q6 = state[6];
		Vector128<byte> q7 = state[7];

		Swap(ref q1, ref q0, 1, Vector128.Create((byte)0x55));
		Swap(ref q3, ref q2, 1, Vector128.Create((byte)0x55));
		Swap(ref q5, ref q4, 1, Vector128.Create((byte)0x55));
		Swap(ref q7, ref q6, 1, Vector128.Create((byte)0x55));
		Swap(ref q2, ref q0, 2, Vector128.Create((byte)0x33));
		Swap(ref q3, ref q1, 2, Vector128.Create((byte)0x33));
		Swap(ref q6, ref q4, 2, Vector128.Create((byte)0x33));
		Swap(ref q7, ref q5, 2, Vector128.Create((byte)0x33));
		Swap(ref q4, ref q0, 4, Vector128.Create((byte)0x0F));
		Swap(ref q5, ref q1, 4, Vector128.Create((byte)0x0F));
		Swap(ref q6, ref q2, 4, Vector128.Create((byte)0x0F));
		Swap(ref q7, ref q3, 4, Vector128.Create((byte)0x0F));

		state[0] = q0;
		state[1] = q1;
		state[2] = q2;
		state[3] = q3;
		state[4] = q4;
		state[5] = q5;
		state[6] = q6;
		state[7] = q7;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Swap(ref Vector128<byte> low, ref Vector128<byte> high, int shift, Vector128<byte> mask)
	{
		Vector128<byte> delta = (low ^ (high.AsUInt64() >>> shift).AsByte()) & mask;
		low ^= delta;
		high ^= (delta.AsUInt64() << shift).AsByte();
	}

	// The 4x4 byte transpose is its own inverse.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> TransposeBytes(Vector128<byte> value)
	{
		if (Ssse3.IsSupported)
		{
			return Ssse3.Shuffle(value, Vector128.Create(0x0D0905010C080400UL, 0x0F0B07030E0A0602UL).AsByte());
		}

		value = Sse2.UnpackLow(value, Sse2.ShiftRightLogical128BitLane(value, 8));
		return Sse2.UnpackLow(value, Sse2.ShiftRightLogical128BitLane(value, 8));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> ShiftRows(Vector128<byte> value, bool inverse)
	{
		if (Ssse3.IsSupported)
		{
			Vector128<byte> mask = inverse
				? Vector128.Create(0x0605040703020100UL, 0x0C0F0E0D09080B0AUL).AsByte()
				: Vector128.Create(0x0407060503020100UL, 0x0E0D0C0F09080B0AUL).AsByte();
			return Ssse3.Shuffle(value, mask);
		}

		Vector128<uint> rows = Sse2.ShuffleHigh(value.AsUInt16(), 0b10_11_00_01).AsUInt32();
		Vector128<uint> rotated = inverse ? rows.RotateLeftUInt32(8) : rows.RotateLeftUInt32(24);
		Vector128<uint> oddRows = Vector128.Create(0xFFFFFFFF00000000UL).AsUInt32();
		return (~oddRows & rows | rotated & oddRows).AsByte();
	}
}
