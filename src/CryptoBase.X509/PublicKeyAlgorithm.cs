namespace CryptoBase.X509;

/// <summary>
/// Identifies the type of a public key, as <see cref="SubjectPublicKeyInfo.KeyAlgorithm" /> gives it: the algorithm and, for an EC key, the curve.
/// </summary>
public enum PublicKeyAlgorithm
{
	/// <summary>
	/// A key of another algorithm or curve, or with parameters that the importers of the package refuse.
	/// </summary>
	Unknown = 0,

	/// <summary>
	/// An RSA key under rsaEncryption (RFC 8017, Appendix A.1), which allows RSASSA-PKCS1-v1_5 and RSASSA-PSS.
	/// </summary>
	Rsa = 1,

	/// <summary>
	/// An RSA key under id-RSASSA-PSS (RFC 4055, Sec. 1.2), which allows RSASSA-PSS alone.
	/// </summary>
	RsaPss = 2,

	/// <summary>
	/// An EC key on the curve P-256, secp256r1 (RFC 5480, Sec. 2.1.1.1).
	/// </summary>
	EcdsaP256 = 3,

	/// <summary>
	/// An EC key on the curve P-384, secp384r1 (RFC 5480, Sec. 2.1.1.1).
	/// </summary>
	EcdsaP384 = 4,

	/// <summary>
	/// An EC key on the curve P-521, secp521r1 (RFC 5480, Sec. 2.1.1.1).
	/// </summary>
	EcdsaP521 = 5,

	/// <summary>
	/// An EC key on the curve of SM2, 1.2.156.10197.1.301 (GB/T 35275-2017).
	/// </summary>
	SM2 = 6,

	/// <summary>
	/// An Ed25519 key (RFC 8410).
	/// </summary>
	Ed25519 = 7,

	/// <summary>
	/// An Ed448 key (RFC 8410).
	/// </summary>
	Ed448 = 8,

	/// <summary>
	/// An ML-DSA-44 key (RFC 9881).
	/// </summary>
	MLDsa44 = 9,

	/// <summary>
	/// An ML-DSA-65 key (RFC 9881).
	/// </summary>
	MLDsa65 = 10,

	/// <summary>
	/// An ML-DSA-87 key (RFC 9881).
	/// </summary>
	MLDsa87 = 11
}
