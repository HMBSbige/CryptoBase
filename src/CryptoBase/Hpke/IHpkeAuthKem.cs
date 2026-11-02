namespace CryptoBase.Hpke;

/// <summary>
/// Defines an HPKE KEM that authenticates the sender, with AuthEncap and AuthDecap of RFC 9180, Section 4.
/// </summary>
/// <remarks>
/// The methods follow the buffer rules of <see cref="IKem{TSelf}.Encapsulate" /> and <see cref="IKem{TSelf}.TryDecapsulate" />.
/// </remarks>
/// <typeparam name="TSelf">The implementing type.</typeparam>
public interface IHpkeAuthKem<TSelf> : IHpkeKem<TSelf> where TSelf : class, IHpkeAuthKem<TSelf>
{
	/// <summary>
	/// Generates a new random shared secret and its encapsulation to the encapsulation key, authenticated with the decapsulation key of <paramref name="sender" />.
	/// </summary>
	/// <remarks>On failure, both buffers remain unchanged.</remarks>
	/// <param name="sender">The sender's key pair, which must hold the decapsulation key.</param>
	/// <param name="ciphertext">The buffer that receives the ciphertext to send to the holder of the decapsulation key.</param>
	/// <param name="sharedSecret">The buffer that receives the shared secret.</param>
	/// <exception cref="ArgumentNullException"><paramref name="sender" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException">
	/// <paramref name="sender" /> does not hold the decapsulation key, <paramref name="ciphertext" /> or <paramref name="sharedSecret" /> is too short, or the parts of them that receive output overlap.
	/// </exception>
	/// <exception cref="ObjectDisposedException">The instance or <paramref name="sender" /> has been disposed.</exception>
	void AuthEncapsulate(TSelf sender, Span<byte> ciphertext, Span<byte> sharedSecret);

	/// <summary>
	/// Recovers the shared secret from <paramref name="ciphertext" /> with the decapsulation key, for a ciphertext authenticated with the encapsulation key of <paramref name="sender" />.
	/// </summary>
	/// <remarks>
	/// As with <see cref="IKem{TSelf}.TryDecapsulate" />, the method returns <see langword="false" /> only if <paramref name="ciphertext" /> fails the public checks, and <see langword="true" /> does not mean that it was encapsulated to this key by <paramref name="sender" />: a ciphertext from anyone else gives another shared secret. If the method returns <see langword="false" /> or throws, <paramref name="sharedSecret" /> remains unchanged.
	/// </remarks>
	/// <param name="ciphertext">The ciphertext.</param>
	/// <param name="sender">The sender's encapsulation key.</param>
	/// <param name="sharedSecret">The buffer that receives the shared secret.</param>
	/// <returns><see langword="false" /> if <paramref name="ciphertext" /> fails the public checks; otherwise, <see langword="true" />.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="sender" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException"><paramref name="sharedSecret" /> is too short.</exception>
	/// <exception cref="InvalidOperationException">The instance does not hold the decapsulation key.</exception>
	/// <exception cref="ObjectDisposedException">The instance or <paramref name="sender" /> has been disposed.</exception>
	bool TryAuthDecapsulate(ReadOnlySpan<byte> ciphertext, TSelf sender, Span<byte> sharedSecret);
}
