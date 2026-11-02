namespace CryptoBase.KeyAgreements;

// A Diffie–Hellman key as a DHKEM (RFC 9180, Section 4.1) uses it: a private key and its public key, a public key alone, or nothing. Keep an implementation in one writable location and do not copy it, and call its members only through writable locations: a call through a readonly one copies the key where nothing erases it.
internal interface IDiffieHellmanKey<TSelf> where TSelf : struct, IDiffieHellmanKey<TSelf>
{
	// Nsk, the length of a serialized private key.
	static abstract int PrivateKeyLength { get; }

	// Npk, the length of a serialized public key.
	static abstract int PublicKeyLength { get; }

	// Ndh, the length of a shared secret.
	static abstract int SharedSecretLength { get; }

	// Selects the DeriveKeyPair of RFC 9180, Section 7.1.3: one expansion with the label "sk" where every PrivateKeyLength-byte string is a private key, and otherwise candidates, their first byte masked with PrivateKeyMask, until one is.
	static abstract bool IsEveryPrivateKeyValid { get; }

	static abstract byte PrivateKeyMask { get; }

	bool HasPrivateKey { get; }

	// Set whenever HasPrivateKey is.
	bool HasPublicKey { get; }

	// On failure, the key is cleared.
	bool TryImportPrivateKey(ReadOnlySpan<byte> source);

	// Accepts only public keys with which DH succeeds for every private key, so that DeriveSharedSecret and GenerateEphemeral cannot fail. On failure, the key is cleared.
	bool TryImportPublicKey(ReadOnlySpan<byte> source);

	int ExportPrivateKey(Span<byte> destination);

	int ExportPublicKey(Span<byte> destination);

	// DH of the private key and a serialized public key. Returns false, leaving sharedSecret unchanged, if peerPublicKey fails the public checks; the result depends only on peerPublicKey.
	bool TryDeriveSharedSecret(ReadOnlySpan<byte> peerPublicKey, Span<byte> sharedSecret);

	// DH(privateKey, publicKey), for a privateKey that holds a private key.
	static abstract void DeriveSharedSecret(in TSelf privateKey, in TSelf publicKey, Span<byte> destination);

	// Draws an ephemeral key pair and writes its public key and DH(ephemeral, publicKey). If drawing fails, neither buffer is written.
	static abstract void GenerateEphemeral(in TSelf publicKey, Span<byte> ephemeralPublicKey, Span<byte> sharedSecret);

	void Clear();
}
