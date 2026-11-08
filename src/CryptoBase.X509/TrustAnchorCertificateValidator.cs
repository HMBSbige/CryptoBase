namespace CryptoBase.X509;

/// <summary>
/// Validates certificate chains against trust anchors that the caller gives, in managed code and alike on every platform, as RFC 5280, Sec. 6, describes.
/// </summary>
/// <remarks>
/// <para>
/// The validator trusts the given certificates alone: it reads no certificate store and holds no roots of its own, which suits private PKIs, Ed25519, Ed448, ML-DSA and SM2 chains, and roots or certificates that the caller pins.
/// Each given certificate is a trust anchor (RFC 5280, Sec. 6.1.1), a version 1 certificate included, whose key the validator trusts without verifying its own signature; a peer's certificate that is one of them, byte for byte, is a path of its own.
/// The validator uses no network: it neither retrieves missing issuers nor checks revocation, so <see cref="CertificateValidationContext.Deadline" /> has no effect, and validation completes synchronously.
/// </para>
/// <para>
/// Paths are built from the peer's certificate depth first, trying as the issuer of each certificate the trust anchors, then the other presented certificates in their order, whose subject is its issuer byte for byte; within each, those whose subject key identifier is its authority key identifier come first, then those that lack one of the two, then the rest.
/// Each issuer is checked as it is added, and one that fails a check gives way to the next candidate, so the validator returns the first path that passes every check, if there is one. A certificate whose subject and key are those of one already in the path is not tried again.
/// </para>
/// <para>
/// Every certificate of the path, the trust anchor included, must be valid at the time of <see cref="CertificateValidationContext.TimeProvider" />, truncated to the second, with both ends of its validity period included,
/// must have no critical extension other than basic constraints, key usage, extended key usage, subject alternative name, name constraints and the certificate policy extensions, which must decode, as must the authority and subject key identifier extensions, which must not be critical.
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
/// A directoryName subtree applies to a nonempty subject and to the directory names of the subject alternative name extension: a name is within it, as RFC 5280, Sec. 7.1, describes, if its first relative names match all those of the subtree, in order, each with the same attributes in any order. An attribute matches if it has the same type and its value is the same byte for byte or, for a value of a string type (PrintableString, UTF8String, TeletexString, BMPString, UniversalString, IA5String or VisibleString), the same after preparation:
/// letters of ASCII are compared regardless of case, the characters that RFC 4518, Sec. 2.2, maps to nothing are removed and those that it maps to a space become one, and spaces are removed at the ends and reduced to one inside (Sec. 2.6.1); other characters are compared by code point, without case folding of those beyond ASCII or normalization, so that the result does not depend on the globalization mode. A value of another type, or one that does not decode, is compared byte for byte.
/// Subtrees of the other forms that are not matched, uniformResourceIdentifier among them, fail a path whose certificates below have a name of that form. The peer's certificate must not have the extension.
/// </para>
/// <para>
/// Certificate policies are processed as in RFC 5280, Sec. 6.1, with the policy graph of RFC 9618, whose size is linear in the policies and mappings of the path; the trust anchor takes no part, and <see cref="InitialPolicies" />, <see cref="RequireExplicitPolicy" />, <see cref="InhibitPolicyMapping" /> and <see cref="InhibitAnyPolicy" /> are the inputs of Sec. 6.1.1.
/// A path is valid for its policies if no explicit policy is required of it, or if a policy of <see cref="InitialPolicies" /> is valid for it; an explicit policy is required by <see cref="RequireExplicitPolicy" /> or by a policy constraints extension whose requireExplicitPolicy has been reached.
/// A certificate policies extension must have at least one policy, each once; a policy mappings extension at least one mapping, and neither of its policies may be anyPolicy; a policy constraints extension at least one field.
/// The path that the strict search accepts must also pass this check, so a path that fails it gives way to the next candidate. A qualifier other than id-qt-cps and id-qt-unotice, which change nothing, fails a critical certificate policies extension (Sec. 4.2.1.4); the qualifiers of an extension that is not critical are not read.
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
/// A valid result has the path from the peer's certificate to the trust anchor. The problems of the peer's certificate alone hold for every path, so a result that rejects the certificates for them only has the path that is otherwise valid.
/// If no path is valid, even if a limit stopped the search, a second search with limits of its own also follows the issuers that fail, and the result reports the best path that it ended, with all of its errors: one that reaches a trust anchor before one that ends at a self-signed certificate, <see cref="CertificatePathEnd.UntrustedRoot" />, before one whose last certificate has no issuer, <see cref="CertificatePathEnd.MissingIssuer" />; then the one with the fewest distinct errors; then the first found.
/// The second search accepts no path; if a limit stops it before it ends one, the result reports the peer's certificate alone, as a path that ends there.
/// A certificate is self-signed if it is self-issued and its own key verifies its signature; one whose signature cannot be verified, as its algorithm or key is not supported, is not, and neither is one that rolls over a CA key, which the old key signs, whatever its key identifiers say.
/// The errors are <see cref="CertificateValidationError.Malformed" /> for an extension that does not decode or breaks the rules of its syntax, an empty issuer name, a key that does not decode, or a name that name constraints cannot be checked against;
/// <see cref="CertificateValidationError.WeakAlgorithm" /> and <see cref="CertificateValidationError.UnsupportedAlgorithm" /> as above; <see cref="CertificateValidationError.InvalidSignature" />; <see cref="CertificateValidationError.Expired" />;
/// <see cref="CertificateValidationError.UntrustedRoot" /> for a path that does not reach a trust anchor; <see cref="CertificateValidationError.NotValidForUsage" /> for an extended key usage, basic constraints, key usage, path length, name or certificate policy that the rules above refuse, or an extension that the validator does not process;
/// <see cref="CertificateValidationError.Unspecified" /> for a search that a limit stopped; and <see cref="CertificateValidationError.NameMismatch" /> for a host name that the certificate does not identify or that is neither a DNS name nor an IP address.
/// <see cref="CertificateValidationResult.Message" /> describes each problem; the text that it takes from the certificates, such as their subjects, and from the host name has each control character, line or paragraph separator and unpaired surrogate written as \uXXXX, so that the message is one line that any encoding can write.
/// </para>
/// <para>
/// So that a peer cannot make it work without bound, each search considers at most 100 candidate issuers, each counted as a signature check whether or not it is verified, the check of whether the last certificate of a path is self-signed counting as one more, once for each certificate, makes at most 2^20 comparisons of a name with a subtree, a directoryName counting by its attributes and length, and handles at most 2^16 entries of the policy graphs of the paths that reach a trust anchor, so a validation considers at most 200 candidates, makes at most 2^21 comparisons and handles at most 2^17 entries.
/// A limit that stops the first search fails the validation, and one that stops either search adds <see cref="CertificateValidationError.Unspecified" /> to the errors.
/// Cancellation is observed between candidates.
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
	/// The policies matter only for a path that must have an explicit policy, because of <see cref="RequireExplicitPolicy" /> or a policy constraints extension of the path; RFC 5280, Sec. 6.1.5, accepts any other path whatever its policies are.
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
				DerReader reader = new(writer.Encode());
				contents.Add(reader.ReadObjectIdentifierContents());
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

	// The contents of the object identifiers of InitialPolicies, or null for anyPolicy.
	internal HashSet<ReadOnlyMemory<byte>>? InitialPolicySet { get; private init; }

	internal Func<ReadOnlySpan<byte>, ISignatureKey> ImportPublicKey { get; }

	/// <inheritdoc />
	/// <exception cref="ObjectDisposedException">The validator has been disposed.</exception>
	/// <exception cref="InvalidOperationException">The importer of public keys returned <see langword="null" />.</exception>
	public ValueTask<CertificateValidationResult> ValidateAsync(CertificateValidationContext context, CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(context);
		ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) is not 0, this);

		if (cancellationToken.IsCancellationRequested)
		{
			return ValueTask.FromCanceled<CertificateValidationResult>(cancellationToken);
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
