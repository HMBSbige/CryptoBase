namespace CryptoBase.Ciphers.Blocks.Aes;

internal partial struct AesCipherBitslice
{
	public readonly void TransformWithMask(ReadOnlySpan<byte> source, ReadOnlySpan<byte> mask, Span<byte> destination, bool decrypt, bool xorInput)
	{
		if (decrypt)
		{
			DecryptWithMask(source, mask, destination, xorInput);
		}
		else
		{
			EncryptWithMask(source, mask, destination, xorInput);
		}
	}

	private readonly void EncryptWithMask(ReadOnlySpan<byte> source, ReadOnlySpan<byte> mask, Span<byte> destination, bool xorInput)
	{
		ref byte input = ref source.GetReference();
		ref byte xor = ref mask.GetReference();
		ref byte output = ref destination.GetReference();
		int remaining = source.Length;
		int rounds = _rounds;

		while (remaining > 0)
		{
			int length = Math.Min(remaining, BatchSize);
			EncryptBatchWithMask(ref input, ref xor, ref output, length, rounds, xorInput);
			input = ref Unsafe.Add(ref input, length);
			xor = ref Unsafe.Add(ref xor, length);
			output = ref Unsafe.Add(ref output, length);
			remaining -= length;
		}
	}

	private readonly void DecryptWithMask(ReadOnlySpan<byte> source, ReadOnlySpan<byte> mask, Span<byte> destination, bool xorInput)
	{
		ref byte input = ref source.GetReference();
		ref byte xor = ref mask.GetReference();
		ref byte output = ref destination.GetReference();
		int remaining = source.Length;
		int rounds = _rounds;

		while (remaining > 0)
		{
			int length = Math.Min(remaining, BatchSize);
			DecryptBatchWithMask(ref input, ref xor, ref output, length, rounds, xorInput);
			input = ref Unsafe.Add(ref input, length);
			xor = ref Unsafe.Add(ref xor, length);
			output = ref Unsafe.Add(ref output, length);
			remaining -= length;
		}
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private readonly void EncryptBatchWithMask(ref byte input, ref byte xor, ref byte output, int length, int rounds, bool xorInput)
	{
		InlineArray8<Vector128<byte>> state = default;

		if (xorInput)
		{
			LoadLayoutWithMask(ref state, ref input, ref xor, length);
		}
		else
		{
			LoadLayout(ref state, ref input, length);
		}

		Transpose(ref state);
		EncryptState(ref state, rounds);
		StoreWithMask(ref state, ref xor, ref output, length);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private readonly void DecryptBatchWithMask(ref byte input, ref byte xor, ref byte output, int length, int rounds, bool xorInput)
	{
		InlineArray8<Vector128<byte>> state = default;

		if (xorInput)
		{
			LoadLayoutWithMask(ref state, ref input, ref xor, length);
		}
		else
		{
			LoadLayout(ref state, ref input, length);
		}

		Transpose(ref state);
		DecryptState(ref state, rounds);
		StoreWithMask(ref state, ref xor, ref output, length);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void LoadLayoutWithMask(ref InlineArray8<Vector128<byte>> state, ref byte source, ref byte mask, int length)
	{
		state[0] = TransposeBytes(Vector128.LoadUnsafe(ref source) ^ Vector128.LoadUnsafe(ref mask));

		if (length >= 32)
		{
			state[1] = TransposeBytes(Vector128.LoadUnsafe(ref source, 16) ^ Vector128.LoadUnsafe(ref mask, 16));
		}

		if (length >= 48)
		{
			state[2] = TransposeBytes(Vector128.LoadUnsafe(ref source, 32) ^ Vector128.LoadUnsafe(ref mask, 32));
		}

		if (length >= 64)
		{
			state[3] = TransposeBytes(Vector128.LoadUnsafe(ref source, 48) ^ Vector128.LoadUnsafe(ref mask, 48));
		}

		if (length >= 80)
		{
			state[4] = TransposeBytes(Vector128.LoadUnsafe(ref source, 64) ^ Vector128.LoadUnsafe(ref mask, 64));
		}

		if (length >= 96)
		{
			state[5] = TransposeBytes(Vector128.LoadUnsafe(ref source, 80) ^ Vector128.LoadUnsafe(ref mask, 80));
		}

		if (length >= 112)
		{
			state[6] = TransposeBytes(Vector128.LoadUnsafe(ref source, 96) ^ Vector128.LoadUnsafe(ref mask, 96));
		}

		if (length >= 128)
		{
			state[7] = TransposeBytes(Vector128.LoadUnsafe(ref source, 112) ^ Vector128.LoadUnsafe(ref mask, 112));
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void StoreWithMask(ref InlineArray8<Vector128<byte>> state, ref byte mask, ref byte destination, int length)
	{
		Transpose(ref state);
		(TransposeBytes(state[0]) ^ Vector128.LoadUnsafe(ref mask)).StoreUnsafe(ref destination);

		if (length >= 32)
		{
			(TransposeBytes(state[1]) ^ Vector128.LoadUnsafe(ref mask, 16)).StoreUnsafe(ref destination, 16);
		}

		if (length >= 48)
		{
			(TransposeBytes(state[2]) ^ Vector128.LoadUnsafe(ref mask, 32)).StoreUnsafe(ref destination, 32);
		}

		if (length >= 64)
		{
			(TransposeBytes(state[3]) ^ Vector128.LoadUnsafe(ref mask, 48)).StoreUnsafe(ref destination, 48);
		}

		if (length >= 80)
		{
			(TransposeBytes(state[4]) ^ Vector128.LoadUnsafe(ref mask, 64)).StoreUnsafe(ref destination, 64);
		}

		if (length >= 96)
		{
			(TransposeBytes(state[5]) ^ Vector128.LoadUnsafe(ref mask, 80)).StoreUnsafe(ref destination, 80);
		}

		if (length >= 112)
		{
			(TransposeBytes(state[6]) ^ Vector128.LoadUnsafe(ref mask, 96)).StoreUnsafe(ref destination, 96);
		}

		if (length >= 128)
		{
			(TransposeBytes(state[7]) ^ Vector128.LoadUnsafe(ref mask, 112)).StoreUnsafe(ref destination, 112);
		}
	}
}
