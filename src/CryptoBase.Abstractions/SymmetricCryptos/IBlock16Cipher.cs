namespace CryptoBase.Abstractions.SymmetricCryptos;

/// <summary>
/// Defines a cipher with a 16-byte block size.
/// </summary>
/// <typeparam name="TSelf">The concrete cipher type.</typeparam>
public interface IBlock16Cipher<out TSelf> : ISymmetricCrypto where TSelf : IBlock16Cipher<TSelf>
{
	/// <summary>
	/// Gets whether the cipher is supported on the current platform.
	/// </summary>
	static abstract bool IsSupported { get; }

	/// <summary>
	/// Gets the supported hardware-accelerated block operations.
	/// </summary>
	static abstract BlockCipherHardwareAcceleration HardwareAcceleration { get; }

	/// <summary>
	/// Creates a cipher with the specified key.
	/// </summary>
	/// <param name="key">The key.</param>
	/// <returns>A new cipher instance.</returns>
	static abstract TSelf Create(in ReadOnlySpan<byte> key);

	/// <summary>
	/// Encrypts a 16-byte buffer.
	/// </summary>
	/// <param name="source">The plaintext buffer.</param>
	/// <returns>The encrypted buffer.</returns>
	VectorBuffer16 Encrypt(VectorBuffer16 source);

	/// <summary>
	/// Decrypts a 16-byte buffer.
	/// </summary>
	/// <param name="source">The ciphertext buffer.</param>
	/// <returns>The decrypted buffer.</returns>
	VectorBuffer16 Decrypt(VectorBuffer16 source);

	/// <summary>
	/// Encrypts a 32-byte buffer.
	/// </summary>
	/// <param name="source">The plaintext buffer.</param>
	/// <returns>The encrypted buffer.</returns>
	VectorBuffer32 Encrypt(in VectorBuffer32 source);

	/// <summary>
	/// Decrypts a 32-byte buffer.
	/// </summary>
	/// <param name="source">The ciphertext buffer.</param>
	/// <returns>The decrypted buffer.</returns>
	VectorBuffer32 Decrypt(in VectorBuffer32 source);

	/// <summary>
	/// Encrypts a 64-byte buffer.
	/// </summary>
	/// <param name="source">The plaintext buffer.</param>
	/// <returns>The encrypted buffer.</returns>
	VectorBuffer64 Encrypt(in VectorBuffer64 source);

	/// <summary>
	/// Decrypts a 64-byte buffer.
	/// </summary>
	/// <param name="source">The ciphertext buffer.</param>
	/// <returns>The decrypted buffer.</returns>
	VectorBuffer64 Decrypt(in VectorBuffer64 source);

	/// <summary>
	/// Encrypts a 128-byte buffer.
	/// </summary>
	/// <param name="source">The plaintext buffer.</param>
	/// <returns>The encrypted buffer.</returns>
	VectorBuffer128 Encrypt(in VectorBuffer128 source);

	/// <summary>
	/// Decrypts a 128-byte buffer.
	/// </summary>
	/// <param name="source">The ciphertext buffer.</param>
	/// <returns>The decrypted buffer.</returns>
	VectorBuffer128 Decrypt(in VectorBuffer128 source);

	/// <summary>
	/// Encrypts a 128-byte buffer with 256-bit vectors.
	/// </summary>
	/// <param name="source">The plaintext buffer.</param>
	/// <returns>The encrypted buffer.</returns>
	/// <exception cref="NotSupportedException">The operation is not supported by this implementation.</exception>
	VectorBuffer128 EncryptV256(in VectorBuffer128 source);

	/// <summary>
	/// Decrypts a 128-byte buffer with 256-bit vectors.
	/// </summary>
	/// <param name="source">The ciphertext buffer.</param>
	/// <returns>The decrypted buffer.</returns>
	/// <exception cref="NotSupportedException">The operation is not supported by this implementation.</exception>
	VectorBuffer128 DecryptV256(in VectorBuffer128 source);

	/// <summary>
	/// Encrypts a 256-byte buffer with 256-bit vectors.
	/// </summary>
	/// <param name="source">The plaintext buffer.</param>
	/// <returns>The encrypted buffer.</returns>
	/// <exception cref="NotSupportedException">The operation is not supported by this implementation.</exception>
	VectorBuffer256 EncryptV256(in VectorBuffer256 source);

	/// <summary>
	/// Decrypts a 256-byte buffer with 256-bit vectors.
	/// </summary>
	/// <param name="source">The ciphertext buffer.</param>
	/// <returns>The decrypted buffer.</returns>
	/// <exception cref="NotSupportedException">The operation is not supported by this implementation.</exception>
	VectorBuffer256 DecryptV256(in VectorBuffer256 source);

	/// <summary>
	/// Encrypts a 256-byte buffer with 512-bit vectors.
	/// </summary>
	/// <param name="source">The plaintext buffer.</param>
	/// <returns>The encrypted buffer.</returns>
	/// <exception cref="NotSupportedException">The operation is not supported by this implementation.</exception>
	VectorBuffer256 EncryptV512(in VectorBuffer256 source);

	/// <summary>
	/// Decrypts a 256-byte buffer with 512-bit vectors.
	/// </summary>
	/// <param name="source">The ciphertext buffer.</param>
	/// <returns>The decrypted buffer.</returns>
	/// <exception cref="NotSupportedException">The operation is not supported by this implementation.</exception>
	VectorBuffer256 DecryptV512(in VectorBuffer256 source);

	/// <summary>
	/// Encrypts a 512-byte buffer with 512-bit vectors.
	/// </summary>
	/// <param name="source">The plaintext buffer.</param>
	/// <returns>The encrypted buffer.</returns>
	/// <exception cref="NotSupportedException">The operation is not supported by this implementation.</exception>
	VectorBuffer512 EncryptV512(in VectorBuffer512 source);

	/// <summary>
	/// Decrypts a 512-byte buffer with 512-bit vectors.
	/// </summary>
	/// <param name="source">The ciphertext buffer.</param>
	/// <returns>The decrypted buffer.</returns>
	/// <exception cref="NotSupportedException">The operation is not supported by this implementation.</exception>
	VectorBuffer512 DecryptV512(in VectorBuffer512 source);
}
