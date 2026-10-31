namespace CryptoBase.Signatures.Ecdsa;

// The types implement the signing and verification members here explicitly: they are for tests, which choose the additional data or sign and verify a hash directly.
internal interface IEcdsa<out TSelf> : ISignatureKey<TSelf> where TSelf : class, IEcdsa<TSelf>
{
	static abstract int PrivateKeyLength { get; }

	static abstract int PublicKeyLength { get; }

	static abstract TSelf GenerateKey();

	static abstract TSelf ImportPrivateKey(ReadOnlySpan<byte> source);

	static abstract TSelf ImportPublicKey(ReadOnlySpan<byte> source);

	int ExportPrivateKey(Span<byte> destination);

	int ExportPublicKey(Span<byte> destination);

	// Empty additionalData makes signing deterministic.
	int Sign(SignatureAlgorithm algorithm, ReadOnlySpan<byte> message, ReadOnlySpan<byte> additionalData, Span<byte> destination);

	// hash may have any length; the HMAC with the hash of algorithm derives the nonce.
	int SignHash(SignatureAlgorithm algorithm, ReadOnlySpan<byte> hash, ReadOnlySpan<byte> additionalData, Span<byte> destination);

	bool VerifyHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature);
}
