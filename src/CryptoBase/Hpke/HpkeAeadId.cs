namespace CryptoBase.Hpke;

/// <summary>
/// Specifies the authenticated encryption with associated data (AEAD) of an HPKE suite, by its identifier in RFC 9180, Section 7.3.
/// </summary>
public enum HpkeAeadId : ushort
{
	/// <summary>AES-128-GCM.</summary>
	Aes128Gcm = 0x0001,

	/// <summary>AES-256-GCM.</summary>
	Aes256Gcm = 0x0002,

	/// <summary>ChaCha20-Poly1305.</summary>
	ChaCha20Poly1305 = 0x0003,

	/// <summary>No AEAD: the context only exports secrets.</summary>
	ExportOnly = 0xFFFF
}
