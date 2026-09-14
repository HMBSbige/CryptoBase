namespace CryptoBase.Ciphers.Streams;

/// <summary>
/// https://datatracker.ietf.org/doc/html/rfc8439
/// </summary>
public class ChaCha20Cipher : SnuffleCipher
{
	/// <summary>The required key size, in bytes.</summary>
	public const int KeySize = 32;

	/// <summary>The required nonce size, in bytes.</summary>
	public const int IVSize = 12;

	/// <inheritdoc />
	protected override ulong MaxCounter => uint.MaxValue;

	/// <summary>
	/// Initializes a new instance with the specified key and nonce.
	/// </summary>
	/// <param name="key">The 256-bit key.</param>
	/// <param name="iv">The 96-bit nonce.</param>
	public ChaCha20Cipher(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		Init(key, iv);
	}

	private void Init(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, KeySize, nameof(key));
		ArgumentOutOfRangeException.ThrowIfNotEqual(iv.Length, IVSize, nameof(iv));

		Span<uint> state = StateSpan;
		state[0] = Sigma32[0];
		state[1] = Sigma32[1];
		state[2] = Sigma32[2];
		state[3] = Sigma32[3];

		ReadOnlySpan<uint> keySpan = MemoryMarshal.Cast<byte, uint>(key);
		keySpan.CopyTo(state.Slice(4));

		InitializeNonce(iv);
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
				int offset = ChaCha20Utils.ChaChaCoreSoa2048Avx512(Rounds, stateSpan, source.Slice(processed), destination.Slice(processed));

				processed += offset;
				length -= offset;
			}

			if (length >= 1024)
			{
				int offset = ChaCha20Utils.ChaChaCoreSoa1024Avx512(Rounds, stateSpan, source.Slice(processed), destination.Slice(processed));

				processed += offset;
				length -= offset;
			}
		}

		if (Avx2.IsSupported)
		{
			if (length >= 512)
			{
				int offset = ChaCha20Utils.ChaChaCore512(Rounds, stateSpan, source.Slice(processed), destination.Slice(processed));
				processed += offset;
				length -= offset;
			}
		}

		if (Sse2.IsSupported)
		{
			if (length >= 256)
			{
				int offset = ChaCha20Utils.ChaChaCore256(Rounds, stateSpan, source.Slice(processed), destination.Slice(processed));
				processed += offset;
				length -= offset;
			}

			while (length >= 64)
			{
				ChaCha20Utils.ChaChaCore64(Rounds, stateSpan, source.Slice(processed), destination.Slice(processed));

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
		Debug.Assert(ChaCha20Utils.GetCounter(ref StateRef) is 0);

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

	/// <inheritdoc />
	protected override void IncrementCounter(Span<uint> state)
	{
		++ChaCha20Utils.GetCounter(ref state.GetReference());
	}

	/// <summary>Initializes the nonce and resets the block counter to zero.</summary>
	internal void InitializeNonce(ReadOnlySpan<byte> nonce)
	{
		Debug.Assert(nonce.Length is IVSize);

		ReadOnlySpan<uint> ivSpan = MemoryMarshal.Cast<byte, uint>(nonce);
		Span<uint> state = StateSpan;
		state[13] = ivSpan[0];
		state[14] = ivSpan[1];
		state[15] = ivSpan[2];
		SetCounter(0);
	}

	/// <summary>Sets the block counter and resets the byte offset within the block to zero.</summary>
	/// <param name="counter">The counter value for the next 64-byte keystream block.</param>
	public void SetCounter(uint counter)
	{
		CounterRemaining = MaxCounter - counter;
		Index = 0;
		ChaCha20Utils.GetCounter(ref StateRef) = counter;
	}
}
