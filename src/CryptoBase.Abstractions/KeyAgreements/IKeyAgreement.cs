namespace CryptoBase.Abstractions.KeyAgreements;

/// <summary>
/// Defines a key-agreement key pair.
/// </summary>
/// <remarks>
/// <para>
/// Every instance holds a private key and its public key.
/// </para>
/// <para>
/// Outputs have fixed lengths: a longer destination receives that many bytes at its start, and a shorter one throws before anything is written. Disposal erases the key material and is idempotent; subsequent instance operations other than disposal throw <see cref="ObjectDisposedException" />.
/// </para>
/// </remarks>
/// <typeparam name="TSelf">The implementing type.</typeparam>
public interface IKeyAgreement<out TSelf> : IDisposable where TSelf : class, IKeyAgreement<TSelf>
{
	/// <summary>
	/// Gets the length of the private key, in bytes.
	/// </summary>
	static abstract int PrivateKeyLength { get; }

	/// <summary>
	/// Gets the length of the public key, in bytes.
	/// </summary>
	static abstract int PublicKeyLength { get; }

	/// <summary>
	/// Gets the length of the shared secret, in bytes.
	/// </summary>
	static abstract int SharedSecretLength { get; }

	/// <summary>
	/// Generates a new random key pair.
	/// </summary>
	/// <returns>An instance that holds the private key and the public key.</returns>
	static abstract TSelf GenerateKey();

	/// <summary>
	/// Imports a private key and derives its public key.
	/// </summary>
	/// <remarks>
	/// Implementation-owned key material is erased if the key is invalid. Some algorithms reject some values of the right length; for example, an elliptic curve private key must lie in [1, n − 1]. <see cref="ExportPrivateKey" /> writes the same bytes back.
	/// </remarks>
	/// <param name="source">The private key, exactly <see cref="PrivateKeyLength" /> bytes long.</param>
	/// <returns>An instance that holds the private key and the public key.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> has the wrong length or is not a valid private key.</exception>
	static abstract TSelf ImportPrivateKey(ReadOnlySpan<byte> source);

	/// <summary>
	/// Writes the private key.
	/// </summary>
	/// <remarks>On failure, <paramref name="destination" /> remains unchanged.</remarks>
	/// <param name="destination">The output buffer.</param>
	/// <returns>The value of <see cref="PrivateKeyLength" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="destination" /> is too short.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	int ExportPrivateKey(Span<byte> destination);

	/// <summary>
	/// Writes the public key.
	/// </summary>
	/// <remarks>On failure, <paramref name="destination" /> remains unchanged.</remarks>
	/// <param name="destination">The output buffer.</param>
	/// <returns>The value of <see cref="PublicKeyLength" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="destination" /> is too short.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	int ExportPublicKey(Span<byte> destination);

	/// <summary>
	/// Derives the shared secret from the private key and <paramref name="peerPublicKey" />.
	/// </summary>
	/// <remarks>
	/// <para>
	/// The method returns <see langword="false" /> if <paramref name="peerPublicKey" /> does not have exactly <see cref="PublicKeyLength" /> bytes or fails a public check of the algorithm, for example because it is not a point on the curve or gives a degenerate result with every private key. The result depends only on <paramref name="peerPublicKey" />, never on the private key.
	/// </para>
	/// <para>
	/// The shared secret is not uniformly random: derive keys from it with a key derivation function. It need not bind the public keys, so a protocol that relies on that binding must include both public keys in its key derivation or transcript.
	/// </para>
	/// <para>
	/// The exceptions take precedence: they are thrown even if <paramref name="peerPublicKey" /> is also unusable. <paramref name="peerPublicKey" /> may overlap <paramref name="sharedSecret" />. If the method returns <see langword="false" /> or throws, <paramref name="sharedSecret" /> remains unchanged.
	/// </para>
	/// </remarks>
	/// <param name="peerPublicKey">The public key of the other party.</param>
	/// <param name="sharedSecret">The buffer that receives the shared secret.</param>
	/// <returns><see langword="false" /> if <paramref name="peerPublicKey" /> fails the public checks; otherwise, <see langword="true" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="sharedSecret" /> is too short.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	bool TryDeriveSharedSecret(ReadOnlySpan<byte> peerPublicKey, Span<byte> sharedSecret);
}
