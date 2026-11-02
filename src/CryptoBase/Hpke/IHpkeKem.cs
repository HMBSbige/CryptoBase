namespace CryptoBase.Hpke;

/// <summary>
/// Defines a key-encapsulation mechanism (KEM) of HPKE (RFC 9180): an <see cref="IKem{TSelf}" /> with an HPKE identifier and a deterministic key derivation.
/// </summary>
/// <remarks>
/// <see cref="IKem{TSelf}.CiphertextLength" /> is the length of the encapsulated key, Nenc, and <see cref="IKem{TSelf}.SharedSecretLength" /> is Nsecret.
/// </remarks>
/// <typeparam name="TSelf">The implementing type.</typeparam>
public interface IHpkeKem<out TSelf> : IKem<TSelf> where TSelf : class, IHpkeKem<TSelf>
{
	/// <summary>
	/// Gets the identifier of the KEM in RFC 9180, Section 7.1.
	/// </summary>
	static abstract ushort KemId { get; }

	/// <summary>
	/// Derives a key pair from input keying material with DeriveKeyPair of RFC 9180, Section 7.1.3.
	/// </summary>
	/// <remarks>
	/// The derivation is deterministic: the same input keying material gives the same key pair.
	/// </remarks>
	/// <param name="inputKeyMaterial">The input keying material, of any length.</param>
	/// <returns>An instance that holds the decapsulation key and the encapsulation key, but not the private seed.</returns>
	static abstract TSelf DeriveKeyPair(ReadOnlySpan<byte> inputKeyMaterial);
}
