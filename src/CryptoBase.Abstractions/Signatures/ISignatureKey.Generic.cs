namespace CryptoBase.Abstractions.Signatures;

/// <summary>
/// Defines a signature key that can be imported from its DER encodings.
/// </summary>
/// <typeparam name="TSelf">The implementing type.</typeparam>
public interface ISignatureKey<out TSelf> : ISignatureKey where TSelf : class, ISignatureKey<TSelf>
{
	/// <summary>
	/// Imports a public key from a DER-encoded X.509 SubjectPublicKeyInfo (RFC 5280).
	/// </summary>
	/// <param name="source">The SubjectPublicKeyInfo, with nothing after it.</param>
	/// <returns>An instance that holds only the public key.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> is not valid DER, is for a different algorithm, or holds an invalid key.</exception>
	static abstract TSelf ImportSubjectPublicKeyInfo(ReadOnlySpan<byte> source);

	/// <summary>
	/// Imports a private key from a DER-encoded PKCS #8 PrivateKeyInfo or OneAsymmetricKey (RFC 5958).
	/// </summary>
	/// <remarks>The key is validated before use; implementation-owned key material is erased if it is invalid.</remarks>
	/// <param name="source">The PrivateKeyInfo, with nothing after it.</param>
	/// <returns>An instance that holds the private key and the public key.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> is not valid DER, is for a different algorithm, or holds an invalid key.</exception>
	static abstract TSelf ImportPkcs8PrivateKey(ReadOnlySpan<byte> source);
}
