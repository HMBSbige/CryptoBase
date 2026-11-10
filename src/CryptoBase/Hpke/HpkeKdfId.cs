namespace CryptoBase.Hpke;

/// <summary>
/// Specifies the key derivation function (KDF) of an HPKE suite, by its identifier in RFC 9180, Section 7.2.
/// </summary>
public enum HpkeKdfId : ushort
{
	/// <summary>HKDF-SHA256.</summary>
	HkdfSha256 = 0x0001,

	/// <summary>HKDF-SHA384.</summary>
	HkdfSha384 = 0x0002,

	/// <summary>HKDF-SHA512.</summary>
	HkdfSha512 = 0x0003
}
