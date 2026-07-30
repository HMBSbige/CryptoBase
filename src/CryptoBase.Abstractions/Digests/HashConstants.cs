namespace CryptoBase.Abstractions.Digests;

/// <summary>
/// Provides digest lengths and block sizes in bytes.
/// </summary>
public static class HashConstants
{
	/// <summary>
	/// The MD5 digest length, in bytes.
	/// </summary>
	public const int Md5Length = 16;

	/// <summary>
	/// The SHA-1 digest length, in bytes.
	/// </summary>
	public const int Sha1Length = 20;

	/// <summary>
	/// The SM3 digest length, in bytes.
	/// </summary>
	public const int SM3Length = 32;

	/// <summary>
	/// The SHA-224 digest length, in bytes.
	/// </summary>
	public const int Sha224Length = 28;

	/// <summary>
	/// The SHA-256 digest length, in bytes.
	/// </summary>
	public const int Sha256Length = 32;

	/// <summary>
	/// The SHA-384 digest length, in bytes.
	/// </summary>
	public const int Sha384Length = 48;

	/// <summary>
	/// The SHA-512 digest length, in bytes.
	/// </summary>
	public const int Sha512Length = 64;

	/// <summary>
	/// The CRC-32 digest length, in bytes.
	/// </summary>
	public const int Crc32Length = 4;

	/// <summary>
	/// The MD5 block size, in bytes.
	/// </summary>
	public const int Md5BlockSize = 64;

	/// <summary>
	/// The SHA-1 block size, in bytes.
	/// </summary>
	public const int Sha1BlockSize = 64;

	/// <summary>
	/// The SM3 block size, in bytes.
	/// </summary>
	public const int SM3BlockSize = 64;

	/// <summary>
	/// The SHA-224 block size, in bytes.
	/// </summary>
	public const int Sha224BlockSize = 64;

	/// <summary>
	/// The SHA-256 block size, in bytes.
	/// </summary>
	public const int Sha256BlockSize = 64;

	/// <summary>
	/// The SHA-384 block size, in bytes.
	/// </summary>
	public const int Sha384BlockSize = 128;

	/// <summary>
	/// The SHA-512 block size, in bytes.
	/// </summary>
	public const int Sha512BlockSize = 128;

	/// <summary>
	/// The CRC-32 block size, in bytes.
	/// </summary>
	public const int Crc32BlockSize = 1;
}
