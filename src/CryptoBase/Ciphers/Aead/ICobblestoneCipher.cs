namespace CryptoBase.Ciphers.Aead;

/// <summary>
/// Supplies what <see cref="Cobblestone{TCipher}" /> needs from an instantiation of c2sp.org/chunked-encryption over AES-GCM, and declares the one-shot API that each instantiation exposes.
/// </summary>
internal interface ICobblestoneCipher<out TSelf> : IChunkedCipher<TSelf> where TSelf : class, ICobblestoneCipher<TSelf>
{
	/// <summary>
	/// Gets the HKDF-Expand info up to the salt: the version prefix, the IANA name of the AEAD and a zero byte.
	/// </summary>
	static abstract ReadOnlySpan<byte> InfoPrefix { get; }

	/// <summary>
	/// Creates an instance that takes ownership of <paramref name="keys" />.
	/// </summary>
	static abstract TSelf Create(CobblestoneKeys keys);

	// The one-shot API, declared here so that the instantiations keep the same signatures and tests can call it generically.
	static abstract long GetCiphertextLength(long plaintextLength);

	static abstract bool TryGetPlaintextLength(long ciphertextLength, out long plaintextLength);

	static abstract void Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, ReadOnlySpan<byte> context = default);

	static abstract bool TryDecrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext, ReadOnlySpan<byte> context = default);
}
