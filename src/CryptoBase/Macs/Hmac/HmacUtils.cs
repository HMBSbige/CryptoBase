using CryptoBase.Digests;

namespace CryptoBase.Macs.Hmac;

/// <summary>
/// Provides factory methods for HMAC instances.
/// </summary>
public static class HmacUtils
{
	/// <summary>
	/// Creates an HMAC instance with the specified key and hash implementation.
	/// </summary>
	public static IMac Create(ReadOnlySpan<byte> key, IHash hash)
	{
		return new HmacSF(key, hash);
	}

	/// <summary>
	/// Creates an HMAC instance with the specified key and hash algorithm.
	/// </summary>
	public static IMac Create(ReadOnlySpan<byte> key, HashAlgorithmName name)
	{
		return new DefaultHmac(key, name);
	}

	/// <summary>
	/// Creates an HMAC instance with the specified digest type and key.
	/// </summary>
	public static IMac Create(DigestType type, ReadOnlySpan<byte> key)
	{
		return type switch
		{
			DigestType.Md5 => Create(key, HashAlgorithmName.MD5),
			DigestType.Sha1 => Create(key, HashAlgorithmName.SHA1),
			DigestType.Sha256 => Create(key, HashAlgorithmName.SHA256),
			DigestType.Sha384 => Create(key, HashAlgorithmName.SHA384),
			DigestType.Sha512 => Create(key, HashAlgorithmName.SHA512),
			_ => Create(key, DigestUtils.Create(type))
		};
	}
}
