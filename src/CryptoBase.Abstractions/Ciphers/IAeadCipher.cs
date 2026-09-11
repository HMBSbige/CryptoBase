namespace CryptoBase.Abstractions.Ciphers;

/// <summary>
/// Defines authenticated encryption with associated data.
/// </summary>
public interface IAeadCipher<out TSelf> : IDisposable where TSelf : IAeadCipher<TSelf>, allows ref struct
{
	/// <summary>
	/// Gets the nonce size, in bytes.
	/// </summary>
	static abstract int NonceSizeInBytes { get; }

	/// <summary>
	/// Gets the authentication tag size, in bytes.
	/// </summary>
	static abstract int TagSizeInBytes { get; }

	/// <summary>
	/// Creates an instance initialized with <paramref name="key" />.
	/// </summary>
	static abstract TSelf Create(scoped ReadOnlySpan<byte> key);

	/// <summary>
	/// Encrypts <paramref name="plaintext" /> into <paramref name="ciphertext" /> and writes the authentication tag to <paramref name="tag" />.
	/// </summary>
	void Encrypt(scoped ReadOnlySpan<byte> nonce, scoped ReadOnlySpan<byte> plaintext, scoped Span<byte> ciphertext, scoped Span<byte> tag, scoped ReadOnlySpan<byte> associatedData = default);

	/// <summary>
	/// Authenticates <paramref name="ciphertext" /> and decrypts it into <paramref name="plaintext" />.
	/// </summary>
	/// <returns><see langword="false" /> on authentication failure, clearing the ciphertext-length output prefix; <see langword="true" /> on success.</returns>
	bool TryDecrypt(scoped ReadOnlySpan<byte> nonce, scoped ReadOnlySpan<byte> ciphertext, scoped ReadOnlySpan<byte> tag, scoped Span<byte> plaintext, scoped ReadOnlySpan<byte> associatedData = default);
}
