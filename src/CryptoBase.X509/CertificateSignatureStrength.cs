namespace CryptoBase.X509;

/// <summary>
/// Classifies the algorithm of a certificate's signature, as <see cref="CertificateAlgorithmPolicy.GetSignatureStrength" /> gives it; each value is more severe than the one before.
/// </summary>
public enum CertificateSignatureStrength
{
	/// <summary>
	/// An algorithm that <see cref="AlgorithmIdentifier.TryGetSignatureAlgorithm" /> names, which the package verifies.
	/// </summary>
	Acceptable = 0,

	/// <summary>
	/// An algorithm that the package does not verify and does not know to be weak, such as ecdsa-with-Specified with SHA-256, or RSASSA-PSS with SHA-256 and another saltLength.
	/// </summary>
	Unsupported = 1,

	/// <summary>
	/// An algorithm with SHA-1 or SHA-224, or DSA.
	/// RSASSA-PSS without parameters, whose hashes default to SHA-1, is one of them.
	/// </summary>
	Weak = 2,

	/// <summary>
	/// An algorithm with MD2, MD4, MD5 or SHA-0, or RSASSA-PSS or ecdsa-with-Specified whose parameters do not decode.
	/// So is ecdsa-with-Specified without parameters.
	/// </summary>
	Forbidden = 3
}
