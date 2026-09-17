namespace CryptoBase.Ciphers.Streams;

/// <summary>
/// Provides an XChaCha20 stream cipher with a 192-bit nonce.
/// </summary>
public class XChaCha20Cipher : ChaCha20OriginalCipher
{
	/// <summary>The required key size, in bytes.</summary>
	public const int KeySize = 32;

	/// <summary>The required nonce size, in bytes.</summary>
	public new const int IVSize = 24;

	private Vector256<byte> _key;

	/// <summary>
	/// Initializes a new instance with the specified key and nonce.
	/// </summary>
	/// <param name="key">The 256-bit key.</param>
	/// <param name="iv">The 192-bit nonce.</param>
	public XChaCha20Cipher(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, KeySize, nameof(key));
		ArgumentOutOfRangeException.ThrowIfNotEqual(iv.Length, IVSize, nameof(iv));

		_key = Vector256.LoadUnsafe(ref key.GetReference());

		InitializeNonce(iv);
	}

	/// <summary>Initializes the nonce and resets the block counter to zero.</summary>
	internal void InitializeNonce(ReadOnlySpan<byte> nonce)
	{
		Debug.Assert(nonce.Length is IVSize);

		Span<uint> state = StateSpan;
		ReadOnlySpan<uint> keySpan = MemoryMarshal.Cast<byte, uint>(_key.AsSpan());
		ReadOnlySpan<uint> ivSpan = MemoryMarshal.Cast<byte, uint>(nonce);

		Sigma32.CopyTo(state);
		keySpan.CopyTo(state.Slice(4));
		ivSpan.Slice(0, 4).CopyTo(state.Slice(12));

		ChaCha20Utils.ChaChaRound(Rounds, state);

		state.Slice(12).CopyTo(state.Slice(8));
		state.Slice(0, 4).CopyTo(state.Slice(4));
		Sigma32.CopyTo(state);

		state[14] = ivSpan[4];
		state[15] = ivSpan[5];
		SetCounter(0);
	}

	/// <inheritdoc />
	public override void Dispose()
	{
		_key.ZeroMemory();
		base.Dispose();
		GC.SuppressFinalize(this);
	}
}
