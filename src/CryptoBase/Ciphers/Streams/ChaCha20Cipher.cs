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
		Debug.Assert(ChaCha20Utils.GetCounter(ref StateRef) is 0);

		ChaCha20Utils.DerivePoly1305Key(StateSpan, KeyStreamSpan, destination);
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
