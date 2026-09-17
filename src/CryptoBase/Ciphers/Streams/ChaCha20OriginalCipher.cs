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
		return ChaCha20Utils.XorBlocks(stateSpan, source, destination);
	}

	/// <inheritdoc />
	protected override void UpdateKeyStream()
	{
		ChaCha20Utils.UpdateKeyStream(Rounds, StateSpan, KeyStreamSpan);
	}

	/// <summary>Derives the Poly1305 key from block 0 without advancing stream state; the caller must set the counter to 1 before processing the message.</summary>
	internal void DerivePoly1305Key(Span<byte> destination)
	{
		Debug.Assert(destination.Length is 32);
		Debug.Assert(ChaCha20Utils.GetCounterOriginal(ref StateRef) is 0);

		ChaCha20Utils.DerivePoly1305Key(StateSpan, KeyStreamSpan, destination);
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
