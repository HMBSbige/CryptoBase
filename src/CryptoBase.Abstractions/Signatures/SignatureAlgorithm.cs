namespace CryptoBase.Abstractions.Signatures;

/// <summary>
/// Identifies a signature algorithm.
/// </summary>
public enum SignatureAlgorithm
{
	/// <summary>
	/// RSASSA-PKCS1-v1_5 with SHA-256.
	/// </summary>
	RsaPkcs1Sha256 = 1,

	/// <summary>
	/// RSASSA-PKCS1-v1_5 with SHA-384.
	/// </summary>
	RsaPkcs1Sha384 = 2,

	/// <summary>
	/// RSASSA-PKCS1-v1_5 with SHA-512.
	/// </summary>
	RsaPkcs1Sha512 = 3,

	/// <summary>
	/// RSASSA-PSS with SHA-256, MGF1 with SHA-256, and a 32-byte salt.
	/// </summary>
	RsaPssSha256 = 4,

	/// <summary>
	/// RSASSA-PSS with SHA-384, MGF1 with SHA-384, and a 48-byte salt.
	/// </summary>
	RsaPssSha384 = 5,

	/// <summary>
	/// RSASSA-PSS with SHA-512, MGF1 with SHA-512, and a 64-byte salt.
	/// </summary>
	RsaPssSha512 = 6,

	/// <summary>
	/// ECDSA with SHA-256, the signature DER-encoded.
	/// </summary>
	EcdsaSha256 = 7,

	/// <summary>
	/// ECDSA with SHA-384, the signature DER-encoded.
	/// </summary>
	EcdsaSha384 = 8,

	/// <summary>
	/// ECDSA with SHA-512, the signature DER-encoded.
	/// </summary>
	EcdsaSha512 = 9,

	/// <summary>
	/// Ed25519.
	/// </summary>
	Ed25519 = 10,

	/// <summary>
	/// Ed448 with an empty context.
	/// </summary>
	Ed448 = 11,

	/// <summary>
	/// ML-DSA-44 with an empty context.
	/// </summary>
	MLDsa44 = 12,

	/// <summary>
	/// ML-DSA-65 with an empty context.
	/// </summary>
	MLDsa65 = 13,

	/// <summary>
	/// ML-DSA-87 with an empty context.
	/// </summary>
	MLDsa87 = 14
}
