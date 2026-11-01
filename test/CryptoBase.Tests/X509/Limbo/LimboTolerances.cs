namespace CryptoBase.Tests.X509.Limbo;

// The x509-limbo testcases whose results TrustAnchorCertificateValidator differs from on purpose, each with the reason.
internal static class LimboTolerances
{
	private const string KeyIdentifierPresence = "RFC 5280 requires CAs to include the key identifiers, but path validation (Sec. 6) does not need them: the validator uses them only to order candidates, so that private CAs that omit them still validate.";
	private const string RootAuthorityKeyIdentifier = "CA/Browser Forum Baseline Requirements, Sec. 7.1.2.1.3, profile the authority key identifier of a root; a trust anchor is trusted as the caller gives it, and its own extensions other than those that the validator processes do not count.";
	private const string CommonName = "CA/Browser Forum Baseline Requirements, Sec. 7.1.4.3, govern how a CA encodes the subject's common name; the validator ignores the common name, as RFC 9525 does, and identifies the peer by its subject alternative names alone.";
	private const string CertificateAuthorityAsLeaf = "CA/Browser Forum Baseline Requirements, Sec. 7.1.2.7.8, forbid cA in a subscriber certificate, but RFC 5280 allows a CA certificate as the end of a path, and the validator does too, so that a self-signed certificate that the caller pins may assert cA; rfc5280::ca-as-leaf conforms.";

	// Testcases that the validator accepts although limbo expects a failure.
	public static readonly IReadOnlyDictionary<string, string> UnexpectedSuccesses = new Dictionary<string, string>(StringComparer.Ordinal)
	{
		["rfc5280::aki::leaf-missing-aki"] = KeyIdentifierPresence,
		["rfc5280::aki::intermediate-missing-aki"] = KeyIdentifierPresence,
		["rfc5280::ski::root-missing-ski"] = KeyIdentifierPresence,
		["rfc5280::ski::intermediate-missing-ski"] = KeyIdentifierPresence,
		["rfc5280::root-missing-basic-constraints"] = "A trust anchor needs no basic constraints extension, as a version 1 certificate has none: RFC 5280, Sec. 6.1.1, trusts its name and key, which the caller chose.",
		["rfc5280::root-non-critical-basic-constraints"] = "RFC 5280 requires CAs to mark basic constraints critical, but the validator processes the extension either way, so its criticality changes nothing for a trust anchor.",
		["rfc5280::leaf-ku-keycertsign"] = "The validator does not check the key usage of the peer's certificate, which ICertificateValidator leaves to the caller; keyCertSign without cA gives the certificate no power in a path, as an issuer must assert cA.",
		["rfc5280::san::noncritical-with-empty-subject"] = "RFC 5280, Sec. 4.2.1.6, requires a CA to mark the extension critical for an empty subject, so that a user that does not process it rejects the certificate; the validator processes it whatever its criticality.",
		["rfc5280::san::underscore-dns"] = "Host names may hold underscores, which names outside the Web PKI use, as SubjectAlternativeName.MatchesHostName accepts.",
		["webpki::aki::root-with-aki-missing-keyidentifier"] = RootAuthorityKeyIdentifier,
		["webpki::aki::root-with-aki-authoritycertissuer"] = RootAuthorityKeyIdentifier,
		["webpki::aki::root-with-aki-authoritycertserialnumber"] = RootAuthorityKeyIdentifier,
		["webpki::aki::root-with-aki-all-fields"] = RootAuthorityKeyIdentifier,
		["webpki::aki::root-with-aki-ski-mismatch"] = RootAuthorityKeyIdentifier,
		["webpki::cn::ipv4-hex-mismatch"] = CommonName,
		["webpki::cn::ipv4-leading-zeros-mismatch"] = CommonName,
		["webpki::cn::ipv6-uppercase-mismatch"] = CommonName,
		["webpki::cn::ipv6-uncompressed-mismatch"] = CommonName,
		["webpki::cn::ipv6-non-rfc5952-mismatch"] = CommonName,
		["webpki::cn::punycode-not-in-san"] = CommonName,
		["webpki::cn::utf8-vs-punycode-mismatch"] = CommonName,
		["webpki::cn::not-in-san"] = CommonName,
		["webpki::cn::case-mismatch"] = CommonName,
		["webpki::san::san-critical-with-nonempty-subject"] = "CA/Browser Forum Baseline Requirements, Sec. 7.1.2.7.12, forbid a critical subject alternative name extension beside a subject; the validator processes the extension whatever its criticality.",
		["webpki::malformed-aia"] = "CA/Browser Forum Baseline Requirements profile the authority information access extension; the validator retrieves nothing, and does not read a noncritical extension that it does not process.",
		["webpki::ee-basicconstraints-ca"] = CertificateAuthorityAsLeaf,
		["webpki::ca-as-leaf"] = CertificateAuthorityAsLeaf,
	};

	// Testcases that the validator rejects although limbo expects a success.
	public static readonly IReadOnlyDictionary<string, string> UnexpectedFailures = new Dictionary<string, string>(StringComparer.Ordinal);
}
