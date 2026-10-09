namespace CryptoBase.Ciphers.Blocks.Aes;

internal partial struct AesCipherBitslice
{
	public readonly void TransformWithPolicy<TPolicy, TOperation>(ref TPolicy policy, ReadOnlySpan<byte> source, Span<byte> destination) where TPolicy : struct, IAesModePolicy, allows ref struct where TOperation : struct, IAesOperation
	{
		ref byte input = ref MemoryMarshal.GetReference(source);
		ref byte output = ref MemoryMarshal.GetReference(destination);

		for (int offset = 0; offset < source.Length; offset += BatchSize)
		{
			int length = Math.Min(source.Length - offset, BatchSize);
			TOperation.ApplyBatch(in this, ref policy, ref input, ref output, (nuint)offset, length, _rounds);
		}
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	internal readonly void EncryptBatch<TPolicy>(ref TPolicy policy, ref byte input, ref byte output, nuint offset, int length, int rounds) where TPolicy : struct, IAesModePolicy, allows ref struct
	{
		InlineArray8<Vector128<byte>> state = default;
		LoadLayout(ref state, ref policy, ref input, offset, length);
		Transpose(ref state);
		EncryptState(ref state, rounds);
		Store(ref state, ref policy, ref input, ref output, offset, length);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	internal readonly void DecryptBatch<TPolicy>(ref TPolicy policy, ref byte input, ref byte output, nuint offset, int length, int rounds) where TPolicy : struct, IAesModePolicy, allows ref struct
	{
		InlineArray8<Vector128<byte>> state = default;
		LoadLayout(ref state, ref policy, ref input, offset, length);
		Transpose(ref state);
		DecryptState(ref state, rounds);
		Store(ref state, ref policy, ref input, ref output, offset, length);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void LoadLayout<TPolicy>(ref InlineArray8<Vector128<byte>> state, ref TPolicy policy, ref byte input, nuint offset, int length) where TPolicy : struct, IAesModePolicy, allows ref struct
	{
		state[0] = TransposeBytes(policy.Prepare1(ref input, offset));

		if (length >= 32)
		{
			state[1] = TransposeBytes(policy.Prepare1(ref input, offset + 16));
		}

		if (length >= 48)
		{
			state[2] = TransposeBytes(policy.Prepare1(ref input, offset + 32));
		}

		if (length >= 64)
		{
			state[3] = TransposeBytes(policy.Prepare1(ref input, offset + 48));
		}

		if (length >= 80)
		{
			state[4] = TransposeBytes(policy.Prepare1(ref input, offset + 64));
		}

		if (length >= 96)
		{
			state[5] = TransposeBytes(policy.Prepare1(ref input, offset + 80));
		}

		if (length >= 112)
		{
			state[6] = TransposeBytes(policy.Prepare1(ref input, offset + 96));
		}

		if (length >= 128)
		{
			state[7] = TransposeBytes(policy.Prepare1(ref input, offset + 112));
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Store<TPolicy>(ref InlineArray8<Vector128<byte>> state, ref TPolicy policy, ref byte input, ref byte output, nuint offset, int length) where TPolicy : struct, IAesModePolicy, allows ref struct
	{
		Transpose(ref state);
		policy.Finish1(ref input, ref output, offset, TransposeBytes(state[0]));

		if (length >= 32)
		{
			policy.Finish1(ref input, ref output, offset + 16, TransposeBytes(state[1]));
		}

		if (length >= 48)
		{
			policy.Finish1(ref input, ref output, offset + 32, TransposeBytes(state[2]));
		}

		if (length >= 64)
		{
			policy.Finish1(ref input, ref output, offset + 48, TransposeBytes(state[3]));
		}

		if (length >= 80)
		{
			policy.Finish1(ref input, ref output, offset + 64, TransposeBytes(state[4]));
		}

		if (length >= 96)
		{
			policy.Finish1(ref input, ref output, offset + 80, TransposeBytes(state[5]));
		}

		if (length >= 112)
		{
			policy.Finish1(ref input, ref output, offset + 96, TransposeBytes(state[6]));
		}

		if (length >= 128)
		{
			policy.Finish1(ref input, ref output, offset + 112, TransposeBytes(state[7]));
		}
	}
}
