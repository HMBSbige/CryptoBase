namespace CryptoBase.Abstractions.SymmetricCryptos;

/// <summary>
/// Defines one-shot encryption and decryption for a block cipher mode.
/// </summary>
public interface IBlockModeOneShot : ISymmetricCrypto
{
	/// <summary>
	/// Gets the block size, in bytes.
	/// </summary>
	int BlockSize { get; }

	/// <summary>
	/// Gets the maximum output length for the specified input length.
	/// </summary>
	/// <param name="inputLength">The input length, in bytes.</param>
	/// <returns>The maximum output length, in bytes.</returns>
	int GetMaxByteCount(int inputLength);

	/// <summary>
	/// Encrypts the input with the specified initialization vector.
	/// </summary>
	/// <param name="iv">The initialization vector.</param>
	/// <param name="input">The plaintext.</param>
	/// <param name="output">The ciphertext destination.</param>
	void Encrypt(in ReadOnlySpan<byte> iv, in ReadOnlySpan<byte> input, in Span<byte> output);

	/// <summary>
	/// Decrypts the input with the specified initialization vector.
	/// </summary>
	/// <param name="iv">The initialization vector.</param>
	/// <param name="input">The ciphertext.</param>
	/// <param name="output">The plaintext destination.</param>
	void Decrypt(in ReadOnlySpan<byte> iv, in ReadOnlySpan<byte> input, in Span<byte> output);
}
