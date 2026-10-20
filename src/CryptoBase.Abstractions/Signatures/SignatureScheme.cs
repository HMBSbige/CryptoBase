namespace CryptoBase.Abstractions.Signatures;

/// <summary>
/// Identifies a signature algorithm by its TLS SignatureScheme code point.
/// </summary>
/// <remarks>
/// The values are those of the IANA TLS SignatureScheme registry (RFC 8446, Section 4.2.3); the ML-DSA values are those of draft-ietf-tls-mldsa.
/// Each scheme fixes the hashing, padding and encoding of a signature.
/// </remarks>
public enum SignatureScheme : ushort
{
	/// <summary>
	/// RSASSA-PKCS1-v1_5 with SHA-256 (rsa_pkcs1_sha256).
	/// </summary>
	RsaPkcs1Sha256 = 0x0401,

	/// <summary>
	/// RSASSA-PKCS1-v1_5 with SHA-384 (rsa_pkcs1_sha384).
	/// </summary>
	RsaPkcs1Sha384 = 0x0501,

	/// <summary>
	/// RSASSA-PKCS1-v1_5 with SHA-512 (rsa_pkcs1_sha512).
	/// </summary>
	RsaPkcs1Sha512 = 0x0601,

	/// <summary>
	/// ECDSA on the secp256r1 (P-256) curve with SHA-256 (ecdsa_secp256r1_sha256).
	/// </summary>
	EcdsaSecp256r1Sha256 = 0x0403,

	/// <summary>
	/// ECDSA on the secp384r1 (P-384) curve with SHA-384 (ecdsa_secp384r1_sha384).
	/// </summary>
	EcdsaSecp384r1Sha384 = 0x0503,

	/// <summary>
	/// ECDSA on the secp521r1 (P-521) curve with SHA-512 (ecdsa_secp521r1_sha512).
	/// </summary>
	EcdsaSecp521r1Sha512 = 0x0603,

	/// <summary>
	/// RSASSA-PSS with SHA-256 and a key of the rsaEncryption type (rsa_pss_rsae_sha256).
	/// </summary>
	RsaPssRsaeSha256 = 0x0804,

	/// <summary>
	/// RSASSA-PSS with SHA-384 and a key of the rsaEncryption type (rsa_pss_rsae_sha384).
	/// </summary>
	RsaPssRsaeSha384 = 0x0805,

	/// <summary>
	/// RSASSA-PSS with SHA-512 and a key of the rsaEncryption type (rsa_pss_rsae_sha512).
	/// </summary>
	RsaPssRsaeSha512 = 0x0806,

	/// <summary>
	/// EdDSA on edwards25519 (ed25519).
	/// </summary>
	Ed25519 = 0x0807,

	/// <summary>
	/// EdDSA on edwards448 (ed448).
	/// </summary>
	Ed448 = 0x0808,

	/// <summary>
	/// RSASSA-PSS with SHA-256 and a key of the RSASSA-PSS type (rsa_pss_pss_sha256).
	/// </summary>
	RsaPssPssSha256 = 0x0809,

	/// <summary>
	/// RSASSA-PSS with SHA-384 and a key of the RSASSA-PSS type (rsa_pss_pss_sha384).
	/// </summary>
	RsaPssPssSha384 = 0x080A,

	/// <summary>
	/// RSASSA-PSS with SHA-512 and a key of the RSASSA-PSS type (rsa_pss_pss_sha512).
	/// </summary>
	RsaPssPssSha512 = 0x080B,

	/// <summary>
	/// ML-DSA-44 of FIPS 204, pure and with an empty context (mldsa44).
	/// </summary>
	MLDsa44 = 0x0904,

	/// <summary>
	/// ML-DSA-65 of FIPS 204, pure and with an empty context (mldsa65).
	/// </summary>
	MLDsa65 = 0x0905,

	/// <summary>
	/// ML-DSA-87 of FIPS 204, pure and with an empty context (mldsa87).
	/// </summary>
	MLDsa87 = 0x0906
}
