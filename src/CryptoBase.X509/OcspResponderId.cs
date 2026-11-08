namespace CryptoBase.X509;

/// <summary>
/// Represents a ResponderID (RFC 6960, Sec. 4.2.1): the name of an OCSP responder or the hash of its key.
/// </summary>
public sealed class OcspResponderId
{
	internal OcspResponderId(ReadOnlyMemory<byte>? byName, ReadOnlyMemory<byte>? byKey)
	{
		ByName = byName;
		ByKey = byKey;
	}

	/// <summary>
	/// Gets the DER encoding of the responder's Name, or <see langword="null" /> if the identifier is a hash.
	/// </summary>
	public ReadOnlyMemory<byte>? ByName { get; }

	/// <summary>
	/// Gets the SHA-1 hash of the responder's public key, without the tag and length of its BIT STRING, or <see langword="null" /> if the identifier is a name.
	/// </summary>
	public ReadOnlyMemory<byte>? ByKey { get; }
}
