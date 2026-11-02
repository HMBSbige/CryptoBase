namespace CryptoBase.Abstractions.Ciphers;

/// <summary>
/// Defines authenticated encryption with associated data.
/// </summary>
/// <remarks>Disposal erases the key and is idempotent; subsequent instance operations other than disposal throw <see cref="ObjectDisposedException" />.</remarks>
public interface IAeadCipher<out TSelf> : IDisposable where TSelf : IAeadCipher<TSelf>, allows ref struct
{
	/// <summary>
	/// Gets the nonce size, in bytes.
	/// </summary>
	static abstract int NonceSize { get; }

	/// <summary>
	/// Gets the authentication tag size, in bytes.
	/// </summary>
	static abstract int TagSize { get; }

	/// <summary>
	/// Creates an instance initialized with <paramref name="key" />.
	/// </summary>
	static abstract TSelf Create(scoped ReadOnlySpan<byte> key);

	/// <summary>
	/// Encrypts <paramref name="plaintext" /> into <paramref name="ciphertext" /> and writes the authentication tag to <paramref name="tag" />.
	/// </summary>
	/// <remarks>If <paramref name="plaintext" /> and <paramref name="ciphertext" /> overlap, they must start at the same byte. <paramref name="tag" /> must not overlap the part of <paramref name="ciphertext" /> that receives output, which <paramref name="associatedData" /> may overlap.</remarks>
	void Encrypt(scoped ReadOnlySpan<byte> nonce, scoped ReadOnlySpan<byte> plaintext, scoped Span<byte> ciphertext, scoped Span<byte> tag, scoped ReadOnlySpan<byte> associatedData = default);

	/// <summary>
	/// Authenticates <paramref name="ciphertext" /> and decrypts it into <paramref name="plaintext" />.
	/// </summary>
	/// <remarks>If <paramref name="ciphertext" /> and <paramref name="plaintext" /> overlap, they must start at the same byte. <paramref name="tag" /> must not overlap the part of <paramref name="plaintext" /> that receives output, which <paramref name="associatedData" /> may overlap.</remarks>
	/// <returns><see langword="false" /> on authentication failure, clearing the ciphertext-length output prefix; <see langword="true" /> on success.</returns>
	bool TryDecrypt(scoped ReadOnlySpan<byte> nonce, scoped ReadOnlySpan<byte> ciphertext, scoped ReadOnlySpan<byte> tag, scoped Span<byte> plaintext, scoped ReadOnlySpan<byte> associatedData = default);
}
