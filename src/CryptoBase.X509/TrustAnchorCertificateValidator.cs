namespace CryptoBase.X509;

/// <summary>
/// Validates certificate chains against trust anchors that the caller gives, in managed code and alike on every platform, as RFC 5280, Sec. 6, describes.
/// </summary>
/// <remarks>
/// <para>
/// The validator trusts the given certificates alone: it reads no certificate store and holds no roots of its own, which suits private PKIs, Ed25519, Ed448, ML-DSA and SM2 chains, and roots or certificates that the caller pins.
/// Each given certificate is a trust anchor (RFC 5280, Sec. 6.1.1), a version 1 certificate included, whose key the validator trusts without verifying its own signature; a peer's certificate that is one of them, byte for byte, is a path of its own.
/// By default the validator uses no network: it neither retrieves missing issuers nor checks revocation, <see cref="CertificateValidationContext.Deadline" /> has no effect, and validation completes synchronously. <see cref="Retriever" /> and <see cref="RevocationMode" /> opt in to that.
/// </para>
/// <para>
/// Paths are built from the peer's certificate depth first, trying as the issuer of each certificate the trust anchors, then the other presented certificates in their order, whose subject is its issuer byte for byte; within each, those whose subject key identifier is its authority key identifier come first, then those that lack one of the two, then the rest.
/// Each issuer is checked as it is added, and one that fails a check gives way to the next candidate, so the validator returns the first path that passes every check, if there is one. A certificate whose subject and key are those of one already in the path is not tried again.
/// </para>
/// <para>
/// Every certificate of the path, the trust anchor included, must be valid at the time of <see cref="CertificateValidationContext.TimeProvider" />, truncated to the second, with both ends of its validity period included,
/// must have no critical extension other than basic constraints, key usage, extended key usage, subject alternative name, name constraints, the certificate policy extensions and CRL distribution points (accepted whether or not revocation is checked), which must decode, as must the authority and subject key identifier extensions, which must not be critical.
/// Every certificate but the trust anchor must have a nonempty issuer name (RFC 5280, Sec. 4.1.2.4), and must mark a policy constraints or inhibit anyPolicy extension critical (RFC 5280, Secs. 4.2.1.11 and 4.2.1.14).
/// </para>
/// <para>
/// Each certificate that issues another in the path must assert keyCertSign if it has a key usage extension (RFC 5280, Sec. 6.1.4 (n)), and must have id-kp-serverAuth or id-kp-clientAuth, as <see cref="CertificateValidationContext.Usage" /> requires, or anyExtendedKeyUsage, if it has an extended key usage extension.
/// An intermediate certificate must have a basic constraints extension that asserts cA (RFC 5280, Sec. 6.1.4 (k)), and a trust anchor that has one must assert it, critical or not.
/// The pathLenConstraint of each, the trust anchor's included, and <see cref="MaxPathLength" /> bound the intermediate certificates that are not self-issued (RFC 5280, Sec. 6.1.4 (l) and (m)).
/// The peer's certificate needs the usage itself if it has an extended key usage extension, which must not be empty; anyExtendedKeyUsage does not stand for it. It may assert cA, as RFC 5280 allows, so that a certificate that the caller pins may be a CA.
/// The validator does not check <see cref="Certificate.KeyUsage" /> of the peer's certificate; the caller checks it.
/// </para>
/// <para>
/// Name constraints (RFC 5280, Sec. 4.2.1.10) of every CA of the path, the trust anchor's included, apply to the subject alternative names and the subject of every certificate below it but the self-issued intermediate ones, and, for a certificate without that extension, to the emailAddress attributes of its subject.
/// dNSName, iPAddress, rfc822Name and directoryName subtrees are matched; a dNSName subtree must be a DNS name or empty, without a wildcard or a leading period, an iPAddress subtree an address and a mask of contiguous ones, and the extension must have permitted or excluded subtrees, neither list empty.
/// A wildcard name is within a permitted subtree if every name that it stands for is, and within an excluded one if any is. A name of these forms that is not valid, under a subtree of its form, fails the path.
/// A directoryName subtree applies to a nonempty subject and to the directory names of the subject alternative name extension, and compares as RFC 5280, Sec. 7.1, describes. In string values, ASCII letters compare regardless of case and insignificant white space is ignored (RFC 4518, Secs. 2.2 and 2.6.1); other characters compare by code point, without case folding or normalization. A value of another type, or one that does not decode, compares byte for byte.
/// A value that holds a character other than those of ASCII, the CJK Unified Ideographs and Extension A, the Hangul Syllables, Hiragana and Katakana cannot be compared exactly: such a character could become any text, so a name that such a value could put within an excluded subtree fails the path with <see cref="CertificateValidationError.NotValidForUsage" />, unless, in a relative name of one attribute, the characters at the ends of the value that no such character could change differ; a permitted subtree is matched exactly.
/// Subtrees of the other forms that are not matched, uniformResourceIdentifier among them, fail a path whose certificates below have a name of that form. The peer's certificate must not have the extension.
/// </para>
/// <para>
/// Certificate policies are processed as in RFC 5280, Sec. 6.1; the trust anchor takes no part, and <see cref="InitialPolicies" />, <see cref="RequireExplicitPolicy" />, <see cref="InhibitPolicyMapping" /> and <see cref="InhibitAnyPolicy" /> are the inputs of Sec. 6.1.1.
/// A path is valid for its policies if no explicit policy is required of it, or if a policy of <see cref="InitialPolicies" /> is valid for it; an explicit policy is required by <see cref="RequireExplicitPolicy" /> or by a policy constraints extension whose requireExplicitPolicy has been reached.
/// A certificate policies extension must have at least one policy, each once; a policy mappings extension at least one mapping, and neither of its policies may be anyPolicy; a policy constraints extension at least one field.
/// A path that fails this check gives way to the next candidate. A malformed qualifier is <see cref="CertificateValidationError.Malformed" /> whether the extension is critical or not; a qualifier other than id-qt-cps and id-qt-unotice fails only a critical certificate policies extension (Sec. 4.2.1.4).
/// </para>
/// <para>
/// Signatures are verified with the key of the issuer, imported with the importer given to the constructor; an RSA key that it does not support is imported with <see cref="PlatformRsaKey.ImportSubjectPublicKeyInfo" />.
/// The algorithms are those of <see cref="AlgorithmIdentifier.TryGetSignatureAlgorithm" />, Ed25519, Ed448, ML-DSA and SM2 with SM3 among them; an SM2 signature is verified with the default ID "1234567812345678" of GB/T 35276-2017, as <see cref="SignatureAlgorithm.SM2SM3" /> specifies, so a certificate that its issuer signed with another ID gives <see cref="CertificateValidationError.InvalidSignature" />. Signatures with MD2, MD4, MD5, SHA-1 or SHA-224, and DSA signatures, fail with <see cref="CertificateValidationError.WeakAlgorithm" />, and any other algorithm with <see cref="CertificateValidationError.UnsupportedAlgorithm" />.
/// The key of every certificate, the peer's and the trust anchor's included, must also pass the policy: an RSA modulus of <see cref="MinRsaKeySize" /> to 16384 bits that is a multiple of 8, as the CA/Browser Forum Baseline Requirements, Sec. 6.1.5, require, with a public exponent of at most 33 bits; and an EC key on the named curve P-256, P-384, P-521 or that of SM2, 1.2.156.10197.1.301.
/// A key that fails gives <see cref="CertificateValidationError.WeakAlgorithm" />, as does a DSA key; an EC key with explicit parameters, or a key that the importer does not support, gives <see cref="CertificateValidationError.UnsupportedAlgorithm" />.
/// </para>
/// <para>
/// A host name, if <see cref="CertificateValidationContext.HostName" /> is set, must be identified by the peer's certificate as <see cref="Certificate.MatchHostName" /> describes; the subject's common name is not used.
/// </para>
/// <para>
/// With a <see cref="Retriever" /> and unless <see cref="DisableCertificateDownloads" /> is set, a search that finds no path retrieves what the id-ad-caIssuers URIs, http and https only, of the certificates at which it found no issuer point to or, if those add no certificate, of all the certificates that it knows but the trust anchors: a single DER certificate or a BER or DER certs-only CMS message (RFC 5280, Sec. 4.2.2.1).
/// Retrieved certificates pass every check that a presented certificate passes, and the search runs again. An extension that does not decode names nothing. A peer's certificate that is unacceptable by itself, such as one that has expired or does not identify the host, causes no retrieval.
/// </para>
/// <para>
/// With a <see cref="RevocationMode" /> other than <see cref="X509RevocationMode.NoCheck" />, a path that passes every other check has the certificates that <see cref="RevocationFlag" /> selects checked from the peer's up, with the sources in order: the CRLs of <see cref="RevocationLists" /> by issuer; online, the responders of the id-ad-ocsp URIs of the certificate, asked without a nonce and by GET if the request is short enough (RFC 9919, Sec. 6), with a SHA-256 CertID and, if a responder answers with neither good nor revoked, once more with SHA-1; and the CRLs of its CRL distribution points, retrieved. Only http and https URIs are used.
/// The first source that says that the certificate is good or revoked decides; CRLs for some reasons alone combine as RFC 5280, Sec. 6.3.3, describes. Delta and indirect CRLs are not used, and neither is a CRL whose issuer has a version 3 certificate without a key usage extension that asserts cRLSign (RFC 5280, Sec. 6.3.3 (f), as RFC 10007, Sec. 4, amends it).
/// The status of a certificate with a noRevAvail or ocsp-nocheck extension is not checked (RFC 9608, Sec. 4): no source is asked, so even a CRL of <see cref="RevocationLists" /> that lists it has no effect.
/// Whatever the <see cref="RevocationMode" />, every certificate but the trust anchor must have a NULL value in either extension, and one with noRevAvail must not assert cA, have a CRL distribution points or freshest CRL extension, or have an id-ad-ocsp access description (RFC 9608, Sec. 3), or the result is <see cref="CertificateValidationError.Malformed" />; an authority information access extension that does not decode counts as one that has such a description. A delegated OCSP responder's certificate that breaks these rules makes its response unusable.
/// A revoked certificate, and a certificate whose status no source determines unless <see cref="IgnoreRevocationUnknown" /> accepts it, fail that path, and the validator tries the others; if none is valid, the result reports the first path that was revoked, with <see cref="CertificateValidationError.Revoked" />, or otherwise the first whose status was not determined, with <see cref="CertificateValidationError.RevocationUnknown" />.
/// </para>
/// <para>
/// The validator caches what it retrieves once verified, in memory bounded in entries and bytes: an issuer for an hour, and CRLs and OCSP responses until their nextUpdate. A cached CRL that decides nothing about a certificate, and cached issuers that lead to no valid path, give way to one retrieval of what the URI gives now.
/// The retriever and the importer of public keys are called on any thread, concurrently.
/// </para>
/// <para>
/// A valid result has the path from the peer's certificate to the trust anchor. The problems of the peer's certificate alone hold for every path, so a result that rejects the certificates for them only has the path that is otherwise valid.
/// If no path is valid, even if a limit stopped the search, a second search with limits of its own also follows the issuers that fail, and the result reports the best path that it ended, with all of its errors: one that reaches a trust anchor before one that ends at a self-signed certificate, <see cref="CertificatePathEnd.UntrustedRoot" />, before one whose last certificate has no issuer, <see cref="CertificatePathEnd.MissingIssuer" />; then the one with the fewest distinct errors; then the first found.
/// The second search accepts no path; if a limit stops it before it ends one, the result reports the peer's certificate alone, as a path that ends there.
/// A certificate is self-signed if it is self-issued and its own key verifies its signature; one whose signature cannot be verified, as its algorithm or key is not supported, is not, and neither is one that rolls over a CA key, which the old key signs, whatever its key identifiers say.
/// The errors are <see cref="CertificateValidationError.Malformed" /> for an extension that does not decode or breaks the rules of its syntax, an empty issuer name, a key that does not decode, or a name that name constraints cannot be checked against;
/// <see cref="CertificateValidationError.WeakAlgorithm" /> and <see cref="CertificateValidationError.UnsupportedAlgorithm" /> as above; <see cref="CertificateValidationError.InvalidSignature" />; <see cref="CertificateValidationError.Expired" />;
/// <see cref="CertificateValidationError.Revoked" /> and <see cref="CertificateValidationError.RevocationUnknown" /> as above; <see cref="CertificateValidationError.UntrustedRoot" /> for a path that does not reach a trust anchor; <see cref="CertificateValidationError.NotValidForUsage" /> for an extended key usage, basic constraints, key usage, path length, name or certificate policy that the rules above refuse, or an extension that the validator does not process;
/// <see cref="CertificateValidationError.Unspecified" /> for a search or a retrieval of issuers that a limit stopped; and <see cref="CertificateValidationError.NameMismatch" /> for a host name that the certificate does not identify or that is neither a DNS name nor an IP address.
/// <see cref="CertificateValidationResult.Message" /> describes each problem; the text that it takes from the certificates, such as their subjects, and from the host name has each control character, line or paragraph separator and unpaired surrogate written as \uXXXX, so that the message is one line that any encoding can write.
/// </para>
/// <para>
/// Each search considers at most 100 candidate issuers, makes at most 2^20 comparisons of a name with a subtree, and handles at most 2^16 entries of the policy graphs of the paths that reach a trust anchor, so a validation considers at most 200 candidates, makes at most 2^21 comparisons and handles at most 2^17 entries.
/// A limit that stops the first search fails the validation, and one that stops either search adds <see cref="CertificateValidationError.Unspecified" /> to the errors.
/// A validation that retrieves repeats the first search at most once for each of 8 rounds of retrieving issuers and of 8 certificates revoked or of unknown status. It makes at most 32 retrievals of at most 64 MiB in all, adds at most 32 retrieved certificates to the candidates, and takes at most 64 KiB of a certificate, a certs-only message of at most 16 certificates or an OCSP response, and 32 MiB of a CRL. A retrieval of issuers that reaches a limit adds <see cref="CertificateValidationError.Unspecified" />; a certificate whose status it then cannot learn is <see cref="CertificateValidationError.RevocationUnknown" /> instead.
/// Cancellation is observed between candidates and during a retrieval.
/// </para>
/// <para>
/// The constructor imports the keys of the trust anchors, which the validator owns and <see cref="Dispose" /> disposes; the keys of the other certificates are imported for each validation and disposed at its end.
/// Validations may run concurrently on one instance; the caller disposes it once none is running.
/// </para>
/// </remarks>
public sealed class TrustAnchorCertificateValidator : ICertificateValidator, IDisposable
{
	private const int MinRsaKeySizeAllowed = 1024;
	private const string AnyPolicyOid = "2.5.29.32.0";

	private readonly TrustAnchorEntry[] _anchors;
	private readonly Dictionary<ReadOnlyMemory<byte>, TrustAnchorEntry[]> _anchorsBySubject;
	private readonly Dictionary<ReadOnlyMemory<byte>, TrustAnchorEntry> _anchorsByEncoding;
	private readonly Dictionary<ReadOnlyMemory<byte>, CertificateRevocationList[]>? _revocationListsByIssuer;
	private int _disposed;

	/// <summary>
	/// Initializes a validator, and imports the key of each trust anchor.
	/// </summary>
	/// <remarks>
	/// <para>
	/// The importer turns a DER-encoded SubjectPublicKeyInfo (RFC 5280) into a key that verifies signatures, such as the <c>SignatureKey.ImportSubjectPublicKeyInfo</c> method of the <c>CryptoBase</c> package, and the validator calls it on any thread, concurrently.
	/// It throws <see cref="NotSupportedException" /> for a key algorithm that it does not support, and <see cref="ArgumentException" /> or <see cref="CryptographicException" /> for a key that is invalid; the validator then treats the certificate as unsupported or malformed, and lets other exceptions escape.
	/// An RSA key that it does not support is imported with <see cref="PlatformRsaKey.ImportSubjectPublicKeyInfo" />, whose verification is managed.
	/// </para>
	/// <para>
	/// A trust anchor whose key cannot be imported is kept, and fails the paths that need it. The validator holds the certificates, which are immutable, and copies the list.
	/// </para>
	/// </remarks>
	/// <param name="trustAnchors">The trusted certificates; a certificate given twice counts once.</param>
	/// <param name="importPublicKey">The importer of public keys.</param>
	/// <exception cref="ArgumentNullException"><paramref name="trustAnchors" /> or <paramref name="importPublicKey" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException"><paramref name="trustAnchors" /> is empty or holds <see langword="null" />.</exception>
	/// <exception cref="InvalidOperationException"><paramref name="importPublicKey" /> returned <see langword="null" />.</exception>
	public TrustAnchorCertificateValidator(IEnumerable<Certificate> trustAnchors, Func<ReadOnlySpan<byte>, ISignatureKey> importPublicKey)
	{
		ArgumentNullException.ThrowIfNull(trustAnchors);
		ArgumentNullException.ThrowIfNull(importPublicKey);

		Certificate[] copy = [.. trustAnchors];

		if (copy.Length is 0 || Array.IndexOf(copy, null) >= 0)
		{
			throw new ArgumentException("The trust anchors must include at least one certificate and no null.", nameof(trustAnchors));
		}

		ImportPublicKey = importPublicKey;
		_anchorsByEncoding = new Dictionary<ReadOnlyMemory<byte>, TrustAnchorEntry>(ByteMemoryComparer.Instance);
		List<TrustAnchorEntry> anchors = [];

		try
		{
			foreach (Certificate certificate in copy)
			{
				if (_anchorsByEncoding.ContainsKey(certificate.Encoded))
				{
					continue;
				}

				ISignatureKey? key = ImportKey(importPublicKey, certificate.PublicKeyInfo, out CertificateValidationError error, out string? message);
				TrustAnchorEntry anchor = new(certificate, key, error, message);
				anchors.Add(anchor);
				_anchorsByEncoding.Add(certificate.Encoded, anchor);
			}
		}
		catch
		{
			foreach (TrustAnchorEntry anchor in anchors)
			{
				anchor.Key?.Dispose();
			}

			throw;
		}

		_anchors = [.. anchors];
		_anchorsBySubject = new Dictionary<ReadOnlyMemory<byte>, TrustAnchorEntry[]>(ByteMemoryComparer.Instance);

		foreach (IGrouping<ReadOnlyMemory<byte>, TrustAnchorEntry> group in _anchors.GroupBy(static anchor => anchor.Certificate.Subject, ByteMemoryComparer.Instance))
		{
			_anchorsBySubject.Add(group.Key, [.. group]);
		}
	}

	/// <summary>
	/// Gets the most intermediate certificates that are not self-issued that a path may have, as RFC 5280, Sec. 6.1.1 (k), lets the trust anchor give max_path_length; 8 by default.
	/// </summary>
	/// <remarks>The peer's certificate and the trust anchor do not count, nor do self-issued certificates, such as those of a key rollover; zero allows no intermediate certificates other than self-issued ones.</remarks>
	/// <exception cref="ArgumentOutOfRangeException">The value set is negative.</exception>
	public int MaxPathLength
	{
		get;
		init
		{
			ArgumentOutOfRangeException.ThrowIfNegative(value);
			field = value;
		}
	} = 8;

	/// <summary>
	/// Gets the fewest bits that the policy allows an RSA modulus in the path; 2048 by default (RFC 9325, Sec. 4.5).
	/// </summary>
	/// <remarks>The policy also requires the modulus to have at most 16384 bits and a multiple of 8, and the public exponent at most 33 bits, whatever this value.</remarks>
	/// <exception cref="ArgumentOutOfRangeException">The value set is less than 1024 or greater than 16384.</exception>
	public int MinRsaKeySize
	{
		get;
		init
		{
			ArgumentOutOfRangeException.ThrowIfLessThan(value, MinRsaKeySizeAllowed);
			ArgumentOutOfRangeException.ThrowIfGreaterThan(value, CertificatePolicy.MaxRsaKeySize);
			field = value;
		}
	} = 2048;

	/// <summary>
	/// Gets the certificate policies that are acceptable to the caller, the user-initial-policy-set of RFC 5280, Sec. 6.1.1 (c), as object identifiers in dotted decimal; by default anyPolicy, 2.5.29.32.0, alone.
	/// </summary>
	/// <remarks>
	/// The policies matter only for a path that must have an explicit policy, because of <see cref="RequireExplicitPolicy" /> or a policy constraints extension of the path.
	/// The validator holds a copy of the collection; anyPolicy among other policies means anyPolicy.
	/// </remarks>
	/// <exception cref="ArgumentNullException">The value set is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException">The value set is empty, or holds <see langword="null" /> or something other than an object identifier.</exception>
	public IReadOnlyCollection<string> InitialPolicies
	{
		get;
		init
		{
			ArgumentNullException.ThrowIfNull(value);

			string[] policies = [.. value];

			if (policies.Length is 0)
			{
				throw new ArgumentException("The initial policies must include at least one policy.", nameof(value));
			}

			HashSet<ReadOnlyMemory<byte>> contents = new(ByteMemoryComparer.Instance);

			foreach (string policy in policies)
			{
				if (policy is null)
				{
					throw new ArgumentException("The initial policies must not include null.", nameof(value));
				}

				AsnWriter writer = new(AsnEncodingRules.DER);
				writer.WriteObjectIdentifier(policy);
				byte[] encoded = writer.Encode();

				// DerReader keeps to what a certificate can hold; a longer identifier is still one, and matches nothing.
				AsnDecoder.ReadEncodedValue(encoded, AsnEncodingRules.DER, out int offset, out int length, out _);
				contents.Add(encoded.AsMemory(offset, length));
			}

			field = policies;
			InitialPolicySet = contents.Contains(PolicyGraph.AnyPolicy) ? null : contents;
		}
	} = [AnyPolicyOid];

	/// <summary>
	/// Gets whether every path must be valid for one of <see cref="InitialPolicies" />, the initial-explicit-policy of RFC 5280, Sec. 6.1.1 (f); <see langword="false" /> by default.
	/// </summary>
	public bool RequireExplicitPolicy { get; init; }

	/// <summary>
	/// Gets whether the policy mappings of the certificates of a path are not honored, the initial-policy-mapping-inhibit of RFC 5280, Sec. 6.1.1 (e); <see langword="false" /> by default.
	/// </summary>
	public bool InhibitPolicyMapping { get; init; }

	/// <summary>
	/// Gets whether anyPolicy in the certificates of a path does not match other policies, the initial-any-policy-inhibit of RFC 5280, Sec. 6.1.1 (g); <see langword="false" /> by default.
	/// </summary>
	public bool InhibitAnyPolicy { get; init; }

	/// <summary>
	/// Gets what retrieves missing issuers, CRLs and OCSP responses from the network, or <see langword="null" />, the default, for no network.
	/// </summary>
	/// <remarks>
	/// The validator retrieves issuers with it unless <see cref="DisableCertificateDownloads" /> is set, and revocation data with it if <see cref="RevocationMode" /> is <see cref="X509RevocationMode.Online" />.
	/// </remarks>
	public ICertificateDataRetriever? Retriever
	{
		get;
		init
		{
			field = value;
			Caches = value is null ? null : new RetrievalCaches();
		}
	}

	/// <summary>
	/// Gets how the revocation status of the certificates of a path is determined; <see cref="X509RevocationMode.NoCheck" /> by default, which does not check it.
	/// </summary>
	/// <remarks><see cref="X509RevocationMode.Offline" /> uses only <see cref="RevocationLists" />. <see cref="X509RevocationMode.Online" /> also asks the OCSP responders of each certificate, then retrieves its CRLs, so it needs <see cref="Retriever" />.</remarks>
	/// <exception cref="ArgumentOutOfRangeException">The value set is not defined.</exception>
	public X509RevocationMode RevocationMode
	{
		get;
		init
		{
			if (value is not (X509RevocationMode.NoCheck or X509RevocationMode.Offline or X509RevocationMode.Online))
			{
				throw new ArgumentOutOfRangeException(nameof(value), value, "The revocation mode is not defined.");
			}

			field = value;
		}
	} = X509RevocationMode.NoCheck;

	/// <summary>
	/// Gets which certificates of a path have their revocation status checked: <see cref="X509RevocationFlag.EndCertificateOnly" />, or by default <see cref="X509RevocationFlag.ExcludeRoot" />, every certificate but the trust anchor.
	/// </summary>
	/// <remarks>The validator trusts the key of the trust anchor as it is given, so <see cref="X509RevocationFlag.EntireChain" /> means <see cref="X509RevocationFlag.ExcludeRoot" />. The revocation of the certificate of a delegated OCSP responder is not checked, whether or not it has the id-pkix-ocsp-nocheck extension.</remarks>
	/// <exception cref="ArgumentOutOfRangeException">The value set is not defined.</exception>
	public X509RevocationFlag RevocationFlag
	{
		get;
		init
		{
			if (value is not (X509RevocationFlag.EndCertificateOnly or X509RevocationFlag.EntireChain or X509RevocationFlag.ExcludeRoot))
			{
				throw new ArgumentOutOfRangeException(nameof(value), value, "The revocation flag is not defined.");
			}

			field = value;
		}
	} = X509RevocationFlag.ExcludeRoot;

	/// <summary>
	/// Gets the CRLs that the caller gives, which the validator consults first, for each certificate by its issuer; empty by default.
	/// </summary>
	/// <remarks>
	/// The validator holds a copy of the collection and skips a CRL that it cannot use. It uses them if <see cref="RevocationMode" /> is <see cref="X509RevocationMode.Offline" /> or <see cref="X509RevocationMode.Online" />.
	/// A CRL that revokes a certificate decides, whatever the others say.
	/// </remarks>
	/// <exception cref="ArgumentNullException">The value set is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException">The value set holds <see langword="null" />.</exception>
	public IReadOnlyCollection<CertificateRevocationList> RevocationLists
	{
		get;
		init
		{
			ArgumentNullException.ThrowIfNull(value);

			CertificateRevocationList[] lists = [.. value];

			if (Array.IndexOf(lists, null) >= 0)
			{
				throw new ArgumentException("The revocation lists must not include null.", nameof(value));
			}

			field = lists;
			_revocationListsByIssuer = lists.Length is 0 ? null : lists.GroupBy(static list => list.Issuer, ByteMemoryComparer.Instance).ToDictionary(static group => group.Key, static group => group.ToArray(), ByteMemoryComparer.Instance);
		}
	} = [];

	/// <summary>
	/// Gets whether a revocation status that cannot be determined is accepted, soft-fail; <see langword="false" /> by default, which fails that path, and gives <see cref="CertificateValidationError.RevocationUnknown" /> if no other is valid.
	/// </summary>
	/// <remarks>A certificate that a source revokes is refused either way.</remarks>
	public bool IgnoreRevocationUnknown { get; init; }

	/// <summary>
	/// Gets whether issuers are not retrieved with <see cref="Retriever" />; <see langword="false" /> by default.
	/// </summary>
	public bool DisableCertificateDownloads { get; init; }

	// The contents of the object identifiers of InitialPolicies, or null for anyPolicy.
	internal HashSet<ReadOnlyMemory<byte>>? InitialPolicySet { get; private init; }

	internal Func<ReadOnlySpan<byte>, ISignatureKey> ImportPublicKey { get; }

	internal RetrievalCaches? Caches { get; private init; }

	/// <inheritdoc />
	/// <exception cref="ObjectDisposedException">The validator has been disposed.</exception>
	/// <exception cref="InvalidOperationException"><see cref="RevocationMode" /> is <see cref="X509RevocationMode.Online" /> and <see cref="Retriever" /> is <see langword="null" />, or the importer of public keys returned <see langword="null" />.</exception>
	public ValueTask<CertificateValidationResult> ValidateAsync(CertificateValidationContext context, CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(context);
		ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) is not 0, this);

		if (RevocationMode is X509RevocationMode.Online && Retriever is null)
		{
			throw new InvalidOperationException($"{nameof(X509RevocationMode)}.{nameof(X509RevocationMode.Online)} needs a {nameof(Retriever)}.");
		}

		if (cancellationToken.IsCancellationRequested)
		{
			return ValueTask.FromCanceled<CertificateValidationResult>(cancellationToken);
		}

		if (Retriever is not null || RevocationMode is not X509RevocationMode.NoCheck)
		{
			return ValidateWithRetrievalAsync(context, cancellationToken);
		}

		try
		{
			using CertificatePathSearch search = new(this, context, cancellationToken);
			return ValueTask.FromResult(search.Run());
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			return ValueTask.FromCanceled<CertificateValidationResult>(cancellationToken);
		}
	}

	/// <summary>
	/// Disposes the keys of the trust anchors.
	/// </summary>
	/// <remarks>Disposal is idempotent; the caller disposes the validator once no validation on it is running.</remarks>
	public void Dispose()
	{
		if (Interlocked.Exchange(ref _disposed, 1) is not 0)
		{
			return;
		}

		foreach (TrustAnchorEntry anchor in _anchors)
		{
			anchor.Key?.Dispose();
		}
	}

	// The trust anchor that is this certificate byte for byte, or null. The lookups call the dictionaries directly, as GetValueOrDefault would call them through IReadOnlyDictionary.
	internal TrustAnchorEntry? FindAnchor(Certificate certificate)
	{
		return _anchorsByEncoding.TryGetValue(certificate.Encoded, out TrustAnchorEntry? anchor) ? anchor : null;
	}

	internal TrustAnchorEntry[] FindAnchorsBySubject(ReadOnlyMemory<byte> subject)
	{
		return _anchorsBySubject.TryGetValue(subject, out TrustAnchorEntry[]? anchors) ? anchors : [];
	}

	// The CRLs that the caller gave whose issuer is this name, byte for byte, as CheckCrl compares them (RFC 5280, Sec. 6.3.3 (b)(1)).
	internal CertificateRevocationList[] FindRevocationLists(ReadOnlyMemory<byte> issuer)
	{
		return _revocationListsByIssuer is not null && _revocationListsByIssuer.TryGetValue(issuer, out CertificateRevocationList[]? lists) ? lists : [];
	}

	private async ValueTask<CertificateValidationResult> ValidateWithRetrievalAsync(CertificateValidationContext context, CancellationToken cancellationToken)
	{
		using CertificatePathSearch search = new(this, context, cancellationToken);
		return await search.RunAsync().ConfigureAwait(false);
	}

	// The key of a SubjectPublicKeyInfo, with PlatformRsaKey for an RSA key that the importer does not support; or null, with the reason, if neither imports it.
	internal static ISignatureKey? ImportKey(Func<ReadOnlySpan<byte>, ISignatureKey> importPublicKey, SubjectPublicKeyInfo info, out CertificateValidationError error, out string? message)
	{
		ReadOnlySpan<byte> encoded = info.Encoded.Span;

		try
		{
			ISignatureKey? key;

			try
			{
				key = importPublicKey(encoded);
			}
			catch (NotSupportedException) when (CertificatePolicy.IsRsa(info.Algorithm))
			{
				key = PlatformRsaKey.ImportSubjectPublicKeyInfo(encoded);
			}

			if (key is null)
			{
				throw new InvalidOperationException("The importer of public keys returned null.");
			}

			(error, message) = (default, null);
			return key;
		}
		catch (NotSupportedException e)
		{
			(error, message) = (CertificateValidationError.UnsupportedAlgorithm, e.Message);
		}
		catch (Exception e) when (e is ArgumentException or CryptographicException)
		{
			(error, message) = (CertificateValidationError.Malformed, e.Message);
		}

		return null;
	}
}
