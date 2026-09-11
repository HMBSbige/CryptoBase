namespace CryptoBase.Abstractions.SymmetricCryptos;

/// <summary>
/// Defines authenticated encryption with associated data operations.
/// </summary>
public interface IAeadCrypto : ISymmetricCrypto
{
	/// <summary>
	/// Gets the required nonce size, in bytes.
	/// </summary>
	int NonceSizeInBytes { get; }

	/// <summary>
	/// Gets the authentication tag size, in bytes.
	/// </summary>
	int TagSizeInBytes { get; }

	/// <summary>
	/// Gets the exact ciphertext size for a plaintext size when the authentication tag is stored separately.
	/// </summary>
	/// <param name="plaintextSizeInBytes">The plaintext size, in bytes.</param>
	/// <returns>The required ciphertext size, in bytes.</returns>
	int GetCiphertextSizeInBytes(int plaintextSizeInBytes)
	{
		ArgumentOutOfRangeException.ThrowIfNegative(plaintextSizeInBytes);
		return plaintextSizeInBytes;
	}

	/// <summary>
	/// Gets the exact plaintext size for a ciphertext size when the authentication tag is stored separately.
	/// </summary>
	/// <param name="ciphertextSizeInBytes">The ciphertext size, in bytes.</param>
	/// <returns>The required plaintext size, in bytes.</returns>
	int GetPlaintextSizeInBytes(int ciphertextSizeInBytes)
	{
		ArgumentOutOfRangeException.ThrowIfNegative(ciphertextSizeInBytes);
		return ciphertextSizeInBytes;
	}

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
	/// <remarks>
	/// Authentication is completed before plaintext is exposed. If authentication fails,
	/// <paramref name="destination" /> is not modified and
	/// <see cref="System.Security.Cryptography.AuthenticationTagMismatchException" /> is thrown.
	/// </remarks>
	void Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, ReadOnlySpan<byte> tag, Span<byte> destination, ReadOnlySpan<byte> associatedData = default);
}
