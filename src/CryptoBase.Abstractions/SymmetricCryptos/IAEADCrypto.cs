namespace CryptoBase.Abstractions.SymmetricCryptos;

/// <summary>
/// Defines authenticated encryption with associated data operations.
/// </summary>
public interface IAEADCrypto : ISymmetricCrypto
{
	/// <summary>
	/// Encrypts plaintext and produces an authentication tag.
	/// </summary>
	/// <param name="nonce">A nonce that must be unique for each encryption with the same key.</param>
	/// <param name="source">The plaintext.</param>
	/// <param name="destination">The ciphertext destination.</param>
	/// <param name="tag">The authentication tag destination.</param>
	/// <param name="associatedData">The data to authenticate without encrypting.</param>
	void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, Span<byte> destination, Span<byte> tag, ReadOnlySpan<byte> associatedData = default);

	/// <summary>
	/// Authenticates and decrypts ciphertext.
	/// </summary>
	/// <param name="nonce">The nonce used for encryption.</param>
	/// <param name="source">The ciphertext.</param>
	/// <param name="tag">The authentication tag.</param>
	/// <param name="destination">The plaintext destination.</param>
	/// <param name="associatedData">The associated data supplied during encryption.</param>
	void Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, ReadOnlySpan<byte> tag, Span<byte> destination, ReadOnlySpan<byte> associatedData = default);
}
