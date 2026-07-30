namespace CryptoBase.SymmetricCryptos.AEADCryptos;

/// <summary>
/// Provides ChaCha20-Poly1305 authenticated encryption using <see cref="ChaCha20Poly1305"/> with 12-byte nonces and 16-byte tags.
/// </summary>
/// <param name="key">The 32-byte key.</param>
public sealed class DefaultChaCha20Poly1305Crypto(ReadOnlySpan<byte> key) : IAEADCrypto
{
	/// <summary>
	/// Gets whether ChaCha20-Poly1305 is supported on the current platform.
	/// </summary>
	public static bool IsSupported => ChaCha20Poly1305.IsSupported;

	/// <inheritdoc />
	public string Name => @"ChaCha20-Poly1305";

	private readonly ChaCha20Poly1305 _internalCrypto = new(key);

	/// <inheritdoc />
	public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData = default)
	{
		_internalCrypto.Encrypt(nonce, source, destination, tag, associatedData);
	}

	/// <inheritdoc />
	public void Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, ReadOnlySpan<byte> tag, Span<byte> destination, ReadOnlySpan<byte> associatedData = default)
	{
		_internalCrypto.Decrypt(nonce, source, tag, destination, associatedData);
	}

	/// <inheritdoc />
	public void Dispose()
	{
		_internalCrypto.Dispose();
	}
}
