namespace CryptoBase.Ciphers.Streams;

/// <summary>
/// Provides the original ChaCha20 stream cipher with a 64-bit nonce and counter.
/// </summary>
public class ChaCha20OriginalCipher : SnuffleCipher
{
	/// <summary>The required nonce size, in bytes.</summary>
	public const int IVSize = 8;

	/// <summary>
	/// Initializes a new instance with the specified key and nonce.
	/// </summary>
	/// <param name="key">The 128- or 256-bit key.</param>
	/// <param name="iv">The 64-bit nonce.</param>
	public ChaCha20OriginalCipher(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		Init(key, iv);
		SetCounter(0);
	}

	private protected ChaCha20OriginalCipher()
	{
	}

	private void Init(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(iv.Length, IVSize, nameof(iv));

		ReadOnlySpan<uint> keySpan = MemoryMarshal.Cast<byte, uint>(key);
		int keyLength = key.Length;

		Span<uint> state = StateSpan;

		switch (keyLength)
		{
			case 16:
			{
				state[0] = Sigma16[0];
				state[1] = Sigma16[1];
				state[2] = Sigma16[2];
				state[3] = Sigma16[3];
				state[8] = keySpan[0];
				state[9] = keySpan[1];
				state[10] = keySpan[2];
				state[11] = keySpan[3];
				break;
			}
			case 32:
			{
				state[0] = Sigma32[0];
				state[1] = Sigma32[1];
				state[2] = Sigma32[2];
				state[3] = Sigma32[3];
				state[8] = keySpan[4];
				state[9] = keySpan[5];
				state[10] = keySpan[6];
				state[11] = keySpan[7];
				break;
			}
			default:
			{
				ThrowHelper.ThrowArgumentOutOfRangeException<int>(nameof(key));
				return;
			}
		}

		state[4] = keySpan[0];
		state[5] = keySpan[1];
		state[6] = keySpan[2];
		state[7] = keySpan[3];

		ReadOnlySpan<uint> ivSpan = MemoryMarshal.Cast<byte, uint>(iv);
		state[14] = ivSpan[0];
		state[15] = ivSpan[1];
	}

	/// <inheritdoc />
	protected override int UpdateBlocks(in Span<uint> stateSpan, in Span<byte> keyStream, in ReadOnlySpan<byte> source, in Span<byte> destination)
	{
		int processed = 0;
		int length = source.Length;

		if (Avx512F.IsSupported)
		{
			if (length >= 2048)
			{
				int offset = ChaCha20Utils.ChaChaCoreOriginalSoa2048Avx512(Rounds, stateSpan, source.Slice(processed), destination.Slice(processed));
				processed += offset;
				length -= offset;
			}

			if (length >= 1024)
			{
				int offset = ChaCha20Utils.ChaChaCoreOriginalSoa1024Avx512(Rounds, stateSpan, source.Slice(processed), destination.Slice(processed));
				processed += offset;
				length -= offset;
			}
		}

		if (Avx2.IsSupported)
		{
			if (length >= 512)
			{
				int offset = ChaCha20Utils.ChaChaCoreOriginal512(Rounds, stateSpan, source.Slice(processed), destination.Slice(processed));
				processed += offset;
				length -= offset;
			}
		}

		if (Sse2.IsSupported)
		{
			if (length >= 256)
			{
				int offset = ChaCha20Utils.ChaChaCoreOriginal256(Rounds, stateSpan, source.Slice(processed), destination.Slice(processed));
				processed += offset;
				length -= offset;
			}

			while (length >= 64)
			{
				ChaCha20Utils.ChaChaCoreOriginal64(Rounds, stateSpan, source.Slice(processed), destination.Slice(processed));

				processed += 64;
				length -= 64;
			}
		}

		if (length >= BlockSize)
		{
			processed += base.UpdateBlocks(stateSpan, keyStream, source.Slice(processed), destination.Slice(processed));
		}

		return processed;
	}

	/// <inheritdoc />
	protected override void UpdateKeyStream()
	{
		if (Sse2.IsSupported)
		{
			ChaCha20Utils.UpdateKeyStream(StateSpan, KeyStreamSpan, Rounds);
		}
		else
		{
			ChaCha20Utils.UpdateKeyStream(Rounds, StateSpan, KeyStreamSpan);
		}
	}

	/// <summary>
	/// Writes the Poly1305 one-time key from the current ChaCha20 block without
	/// advancing the counter or retaining a partially consumed key-stream block.
	/// The counter must be 0 on entry, and the caller must set it to 1 before
	/// processing the message.
	/// </summary>
	internal void DerivePoly1305Key(Span<byte> destination)
	{
		Debug.Assert(destination.Length is 32);
		Debug.Assert(ChaCha20Utils.GetCounterOriginal(ref StateRef) is 0);

		Span<byte> keyStream = KeyStreamSpan;

		if (Sse2.IsSupported)
		{
			ChaCha20Utils.UpdateKeyStream(StateSpan, keyStream, Rounds);
		}
		else
		{
			ChaCha20Utils.UpdateKeyStream(Rounds, StateSpan, keyStream);
		}

		Unsafe.CopyBlockUnaligned(ref destination.GetReference(), ref keyStream.GetReference(), 32);
	}

	/// <summary>Sets the block counter and resets the byte offset within the block to zero.</summary>
	/// <param name="counter">The counter value for the next 64-byte keystream block.</param>
	public void SetCounter(ulong counter)
	{
		CounterRemaining = MaxCounter - counter;
		Index = 0;
		ChaCha20Utils.GetCounterOriginal(ref StateRef) = counter;
	}

	/// <inheritdoc />
	protected override void IncrementCounter(Span<uint> state)
	{
		++ChaCha20Utils.GetCounterOriginal(ref state.GetReference());
	}
}
