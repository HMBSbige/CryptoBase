namespace CryptoBase.Ciphers.Streams;

/// <summary>
/// Provides an XSalsa20 stream cipher with a 192-bit nonce.
/// </summary>
public class XSalsa20Cipher : Salsa20Cipher
{
	/// <summary>The required key size, in bytes.</summary>
	public const int KeySize = 32;

	/// <summary>The required nonce size, in bytes.</summary>
	public new const int IVSize = 24;

	/// <summary>
	/// Initializes a new instance with the specified key and nonce.
	/// </summary>
	/// <param name="key">The 256-bit key.</param>
	/// <param name="iv">The 192-bit nonce.</param>
	public XSalsa20Cipher(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, KeySize, nameof(key));
		ArgumentOutOfRangeException.ThrowIfNotEqual(iv.Length, IVSize, nameof(iv));

		Span<uint> state = StateSpan;
		state[0] = Sigma32[0];
		state[5] = Sigma32[1];
		state[10] = Sigma32[2];
		state[15] = Sigma32[3];
		Salsa20Utils.DeriveXSalsa20Key(ref StateRef, ref MemoryMarshal.GetReference(key), ref MemoryMarshal.GetReference(iv));
		MemoryMarshal.Cast<byte, uint>(iv.Slice(16, 8)).CopyTo(state.Slice(6));
		SetCounter(0);
	}
}
