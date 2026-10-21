namespace CryptoBase.Signatures.MLDsa;

// The members that MLDsa44, MLDsa65 and MLDsa87 share beyond ISignatureKey, so that code can be generic over the parameter set.
internal interface IMLDsa<TSelf> : ISignatureKey<TSelf> where TSelf : class, IMLDsa<TSelf>
{
	static abstract int PrivateSeedLength { get; }

	static abstract int PrivateKeyLength { get; }

	static abstract int PublicKeyLength { get; }

	static abstract int SignatureLength { get; }

	static abstract int MuLength { get; }

	static abstract int MaxContextLength { get; }

	bool HasPrivateSeed { get; }

	static abstract TSelf GenerateKey();

	static abstract TSelf ImportPrivateSeed(ReadOnlySpan<byte> source);

	static abstract TSelf ImportPrivateKey(ReadOnlySpan<byte> source);

	static abstract TSelf ImportPublicKey(ReadOnlySpan<byte> source);

	int ExportPrivateSeed(Span<byte> destination);

	int ExportPrivateKey(Span<byte> destination);

	int ExportPublicKey(Span<byte> destination);

	int Sign(ReadOnlySpan<byte> message, Span<byte> destination, ReadOnlySpan<byte> context = default);

	bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> context = default);

	int SignPreHash(ReadOnlySpan<byte> hash, Span<byte> destination, string hashAlgorithmOid, ReadOnlySpan<byte> context = default);

	bool VerifyPreHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature, string hashAlgorithmOid, ReadOnlySpan<byte> context = default);

	int SignMu(ReadOnlySpan<byte> mu, Span<byte> destination);

	bool VerifyMu(ReadOnlySpan<byte> mu, ReadOnlySpan<byte> signature);
}
