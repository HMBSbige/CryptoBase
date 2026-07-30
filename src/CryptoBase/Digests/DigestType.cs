namespace CryptoBase.Digests;

/// <summary>
/// Specifies a digest algorithm.
/// </summary>
public enum DigestType
{
	/// <summary>The SM3 hash algorithm.</summary>
	Sm3,

	/// <summary>The MD5 hash algorithm.</summary>
	Md5,

	/// <summary>The SHA-1 hash algorithm.</summary>
	Sha1,

	/// <summary>The SHA-224 hash algorithm.</summary>
	Sha224,

	/// <summary>The SHA-256 hash algorithm.</summary>
	Sha256,

	/// <summary>The SHA-384 hash algorithm.</summary>
	Sha384,

	/// <summary>The SHA-512 hash algorithm.</summary>
	Sha512,

	/// <summary>The CRC-32 checksum algorithm.</summary>
	Crc32,

	/// <summary>The CRC-32C checksum algorithm.</summary>
	Crc32C
}
