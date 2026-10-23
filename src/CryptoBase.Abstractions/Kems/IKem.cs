namespace CryptoBase.Abstractions.Kems;

/// <summary>
/// Defines a key-encapsulation mechanism (KEM) key pair, or the encapsulation key alone.
/// </summary>
/// <remarks>
/// <para>
/// An instance holds the key it was generated or imported with. An instance from <see cref="GenerateKey" /> or <see cref="ImportPrivateSeed" />
/// holds the private seed and the decapsulation key; one from <see cref="ImportDecapsulationKey" /> holds the decapsulation key but not the seed;
/// one from <see cref="ImportEncapsulationKey" /> can only encapsulate. Every instance holds the encapsulation key.
/// </para>
/// <para>
/// Outputs have fixed lengths: a longer destination receives that many bytes at its start, and a shorter one throws before anything is written.
/// Disposal erases the key material and is idempotent; subsequent instance operations other than disposal throw <see cref="ObjectDisposedException" />.
/// </para>
/// </remarks>
/// <typeparam name="TSelf">The implementing type.</typeparam>
public interface IKem<out TSelf> : IDisposable where TSelf : class, IKem<TSelf>
{
	/// <summary>
	/// Gets the length of the encapsulation key, in bytes.
	/// </summary>
	static abstract int EncapsulationKeyLength { get; }

	/// <summary>
	/// Gets the length of the decapsulation key, in bytes.
	/// </summary>
	static abstract int DecapsulationKeyLength { get; }

	/// <summary>
	/// Gets the length of the private seed from which the key pair derives, in bytes.
	/// </summary>
	static abstract int PrivateSeedLength { get; }

	/// <summary>
	/// Gets the length of a ciphertext, in bytes.
	/// </summary>
	static abstract int CiphertextLength { get; }

	/// <summary>
	/// Gets the length of the shared secret, in bytes.
	/// </summary>
	static abstract int SharedSecretLength { get; }

	/// <summary>
	/// Generates a key pair from a new random private seed.
	/// </summary>
	/// <returns>An instance that holds the private seed, the decapsulation key and the encapsulation key.</returns>
	static abstract TSelf GenerateKey();

	/// <summary>
	/// Derives a key pair from <paramref name="source" />.
	/// </summary>
	/// <remarks>
	/// The derivation is deterministic: the same seed always gives the same key pair. Some algorithms reject some seeds of the right length; for
	/// example, a hybrid KEM requires the elliptic curve private key in the seed to lie in [1, n − 1].
	/// </remarks>
	/// <param name="source">The private seed, exactly <see cref="PrivateSeedLength" /> bytes long.</param>
	/// <returns>An instance that holds the private seed, the decapsulation key and the encapsulation key.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> has the wrong length or is not a valid private seed.</exception>
	static abstract TSelf ImportPrivateSeed(ReadOnlySpan<byte> source);

	/// <summary>
	/// Imports a decapsulation key.
	/// </summary>
	/// <remarks>The key is validated before use; implementation-owned key material is erased if it is invalid.</remarks>
	/// <param name="source">The decapsulation key, exactly <see cref="DecapsulationKeyLength" /> bytes long.</param>
	/// <returns>An instance that holds the decapsulation key and the encapsulation key, but not the private seed.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> has the wrong length or is not a valid decapsulation key.</exception>
	static abstract TSelf ImportDecapsulationKey(ReadOnlySpan<byte> source);

	/// <summary>
	/// Imports an encapsulation key.
	/// </summary>
	/// <remarks>The key is validated in full, so once it is imported, <see cref="Encapsulate" /> cannot fail because of its contents.</remarks>
	/// <param name="source">The encapsulation key, exactly <see cref="EncapsulationKeyLength" /> bytes long.</param>
	/// <returns>An instance that holds only the encapsulation key.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> has the wrong length or is not a valid encapsulation key.</exception>
	static abstract TSelf ImportEncapsulationKey(ReadOnlySpan<byte> source);

	/// <summary>
	/// Gets a value that indicates whether the instance holds the private seed.
	/// </summary>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	bool HasPrivateSeed { get; }

	/// <summary>
	/// Gets a value that indicates whether the instance holds the decapsulation key.
	/// </summary>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	bool HasDecapsulationKey { get; }

	/// <summary>
	/// Writes the private seed.
	/// </summary>
	/// <remarks>On failure, <paramref name="destination" /> remains unchanged.</remarks>
	/// <param name="destination">The output buffer.</param>
	/// <returns>The value of <see cref="PrivateSeedLength" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="destination" /> is too short.</exception>
	/// <exception cref="InvalidOperationException">The instance does not hold the private seed.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	int ExportPrivateSeed(Span<byte> destination);

	/// <summary>
	/// Writes the decapsulation key.
	/// </summary>
	/// <remarks>On failure, <paramref name="destination" /> remains unchanged.</remarks>
	/// <param name="destination">The output buffer.</param>
	/// <returns>The value of <see cref="DecapsulationKeyLength" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="destination" /> is too short.</exception>
	/// <exception cref="InvalidOperationException">The instance does not hold the decapsulation key.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	int ExportDecapsulationKey(Span<byte> destination);

	/// <summary>
	/// Writes the encapsulation key.
	/// </summary>
	/// <remarks>On failure, <paramref name="destination" /> remains unchanged.</remarks>
	/// <param name="destination">The output buffer.</param>
	/// <returns>The value of <see cref="EncapsulationKeyLength" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="destination" /> is too short.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	int ExportEncapsulationKey(Span<byte> destination);

	/// <summary>
	/// Generates a new random shared secret and its encapsulation to the encapsulation key.
	/// </summary>
	/// <remarks>On failure, both buffers remain unchanged.</remarks>
	/// <param name="ciphertext">The buffer that receives the ciphertext to send to the holder of the decapsulation key.</param>
	/// <param name="sharedSecret">The buffer that receives the shared secret.</param>
	/// <exception cref="ArgumentException">
	/// <paramref name="ciphertext" /> or <paramref name="sharedSecret" /> is too short, or the parts of them that receive output overlap.
	/// </exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	void Encapsulate(Span<byte> ciphertext, Span<byte> sharedSecret);

	/// <summary>
	/// Recovers the shared secret from <paramref name="ciphertext" /> with the decapsulation key.
	/// </summary>
	/// <remarks>
	/// <para>
	/// The method returns <see langword="false" /> if <paramref name="ciphertext" /> does not have exactly <see cref="CiphertextLength" /> bytes or a
	/// publicly encoded value in it, such as an elliptic curve point, is invalid. The result depends only on the ciphertext and the encapsulation key,
	/// never on secret key material.
	/// </para>
	/// <para>
	/// <see langword="true" /> does not mean that <paramref name="ciphertext" /> was encapsulated to this key. The shared secret need not bind the
	/// ciphertext, so a protocol that relies on that binding must include the ciphertext in its key derivation or transcript. A KEM with implicit
	/// rejection writes, for a ciphertext that was not encapsulated to the key, a pseudorandom value derived from the decapsulation key and the
	/// ciphertext.
	/// </para>
	/// <para>
	/// The exceptions take precedence: they are thrown even if <paramref name="ciphertext" /> is also invalid. <paramref name="ciphertext" /> may overlap
	/// <paramref name="sharedSecret" />. If the method returns <see langword="false" /> or throws, <paramref name="sharedSecret" /> remains unchanged.
	/// </para>
	/// </remarks>
	/// <param name="ciphertext">The ciphertext.</param>
	/// <param name="sharedSecret">The buffer that receives the shared secret.</param>
	/// <returns><see langword="false" /> if <paramref name="ciphertext" /> fails the public checks; otherwise, <see langword="true" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="sharedSecret" /> is too short.</exception>
	/// <exception cref="InvalidOperationException">The instance does not hold the decapsulation key.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	bool TryDecapsulate(ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret);
}
