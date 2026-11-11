namespace CryptoBase.X509;

/// <summary>
/// Represents a ResponderID (RFC 6960, Sec. 4.2.1): the name of an OCSP responder, a <see cref="ByName" />, or the hash of its key, a <see cref="ByKey" />.
/// </summary>
/// <remarks>Instances are immutable, so they may be used concurrently.</remarks>
public closed class OcspResponderId
{
	/// <summary>
	/// Represents a ResponderID that names the responder.
	/// </summary>
	public sealed class ByName : OcspResponderId
	{
		internal ByName(ReadOnlyMemory<byte> name)
		{
			Name = name;
		}

		/// <summary>
		/// Gets the DER encoding of the responder's Name.
		/// </summary>
		public ReadOnlyMemory<byte> Name { get; }
	}

	/// <summary>
	/// Represents a ResponderID that holds the hash of the responder's key.
	/// </summary>
	public sealed class ByKey : OcspResponderId
	{
		internal ByKey(ReadOnlyMemory<byte> keyHash)
		{
			KeyHash = keyHash;
		}

		/// <summary>
		/// Gets the SHA-1 hash of the responder's public key, without the tag and length of its BIT STRING.
		/// </summary>
		public ReadOnlyMemory<byte> KeyHash { get; }
	}
}
