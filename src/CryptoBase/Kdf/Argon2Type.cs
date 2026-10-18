namespace CryptoBase.Kdf;

/// <summary>
/// Specifies the type of Argon2. Each value is the type y that RFC 9106 assigns to it.
/// </summary>
public enum Argon2Type
{
	/// <summary>
	/// Argon2d, whose memory accesses depend on the password, so it suits only applications without side-channel timing threats.
	/// </summary>
	Argon2d = 0,

	/// <summary>
	/// Argon2i, whose memory accesses never depend on the password.
	/// </summary>
	Argon2i = 1,

	/// <summary>
	/// Argon2id, which accesses memory like Argon2i for the first half of the first pass and like Argon2d afterwards. RFC 9106 makes it the primary variant.
	/// </summary>
	Argon2id = 2,
}
