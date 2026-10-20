namespace CryptoBase.Abstractions.Signatures;

/// <summary>
/// Defines a signing key pair, or the verification key alone, that a TLS or X.509 implementation can hold without
/// knowing the algorithm at compile time.
/// </summary>
/// <remarks>
/// <para>
/// A key signs and verifies with the signature schemes that <see cref="Supports" /> accepts. A message is passed whole and unhashed, such as the
/// content that a TLS 1.3 CertificateVerify covers, the parameters that a TLS 1.2 ServerKeyExchange covers, or an X.509 TBSCertificate;
/// the scheme fixes any hashing, padding and encoding. Signing takes randomness from the system where the scheme is randomized.
/// A signature that is invalid, including one of the wrong length, verifies as <see langword="false" /> rather than throwing.
/// </para>
/// <para>
/// Outputs have lengths the instance reports, as a maximum for signatures: a longer destination receives the output at its start, and a shorter
/// one throws before anything is written. Disposal erases the key material and is idempotent; subsequent instance operations other than disposal
/// throw <see cref="ObjectDisposedException" />.
/// </para>
/// </remarks>
public interface ISignatureKey : IDisposable
{
	/// <summary>
	/// Gets a value that indicates whether the instance holds the private key, and so can sign.
	/// </summary>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	bool HasPrivateKey { get; }

	/// <summary>
	/// Gets the length of the SubjectPublicKeyInfo that <see cref="ExportSubjectPublicKeyInfo" /> writes, in bytes.
	/// </summary>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	int SubjectPublicKeyInfoLength { get; }

	/// <summary>
	/// Gets the length of the PKCS #8 private key that <see cref="ExportPkcs8PrivateKey" /> writes, in bytes.
	/// </summary>
	/// <exception cref="InvalidOperationException">The instance does not hold the private key.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	int Pkcs8PrivateKeyLength { get; }

	/// <summary>
	/// Determines whether the key can sign and verify with <paramref name="scheme" />.
	/// </summary>
	/// <param name="scheme">The signature scheme, which need not be a defined value.</param>
	/// <returns><see langword="true" /> if the key can use <paramref name="scheme" />; otherwise, <see langword="false" />.</returns>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	bool Supports(SignatureScheme scheme);

	/// <summary>
	/// Gets the length of the longest signature that the key writes with <paramref name="scheme" />.
	/// </summary>
	/// <param name="scheme">The signature scheme.</param>
	/// <returns>The maximum signature length, in bytes.</returns>
	/// <exception cref="ArgumentException">The key does not support <paramref name="scheme" />.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	int GetMaxSignatureLength(SignatureScheme scheme);

	/// <summary>
	/// Signs <paramref name="message" /> with <paramref name="scheme" />.
	/// </summary>
	/// <remarks>On failure, <paramref name="destination" /> remains unchanged.</remarks>
	/// <param name="scheme">The signature scheme.</param>
	/// <param name="message">The whole message, which the scheme hashes if it hashes at all.</param>
	/// <param name="destination">The buffer that receives the signature, at least <see cref="GetMaxSignatureLength" /> bytes long.</param>
	/// <returns>The length of the signature, in bytes.</returns>
	/// <exception cref="ArgumentException">The key does not support <paramref name="scheme" />, or <paramref name="destination" /> is too short.</exception>
	/// <exception cref="InvalidOperationException">The instance does not hold the private key.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	int Sign(SignatureScheme scheme, ReadOnlySpan<byte> message, Span<byte> destination);

	/// <summary>
	/// Verifies that <paramref name="signature" /> is a signature of <paramref name="message" /> with <paramref name="scheme" />.
	/// </summary>
	/// <param name="scheme">The signature scheme.</param>
	/// <param name="message">The whole message, which the scheme hashes if it hashes at all.</param>
	/// <param name="signature">The signature.</param>
	/// <returns><see langword="true" /> if the signature is valid; otherwise, <see langword="false" />.</returns>
	/// <exception cref="ArgumentException">The key does not support <paramref name="scheme" />.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	bool Verify(SignatureScheme scheme, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature);

	/// <summary>
	/// Writes the public key as a DER-encoded X.509 SubjectPublicKeyInfo (RFC 5280).
	/// </summary>
	/// <remarks>On failure, <paramref name="destination" /> remains unchanged.</remarks>
	/// <param name="destination">The output buffer.</param>
	/// <returns>The value of <see cref="SubjectPublicKeyInfoLength" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="destination" /> is too short.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	int ExportSubjectPublicKeyInfo(Span<byte> destination);

	/// <summary>
	/// Writes the private key as a DER-encoded PKCS #8 PrivateKeyInfo (RFC 5958).
	/// </summary>
	/// <remarks>On failure, <paramref name="destination" /> remains unchanged.</remarks>
	/// <param name="destination">The output buffer.</param>
	/// <returns>The value of <see cref="Pkcs8PrivateKeyLength" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="destination" /> is too short.</exception>
	/// <exception cref="InvalidOperationException">The instance does not hold the private key.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	int ExportPkcs8PrivateKey(Span<byte> destination);
}
