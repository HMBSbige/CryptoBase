using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

namespace CryptoBase.X509;

// One validation of TrustAnchorCertificateValidator. It builds certification paths from the peer's certificate towards the trust anchors depth first, and checks each issuer as it adds it (RFC 5280, Sec. 6.1), so that a failed check moves on to the next candidate.
// The first search follows only the issuers that pass every check and returns the first path that reaches a trust anchor; if there is none, a second search, with limits of its own, also follows those that fail, to report the best of the paths that it ends, as RunAsync describes.
// An instance serves one call, which a retrieval may move to another thread, and owns the keys that it imports for the certificates other than the trust anchors.
internal sealed partial class CertificatePathSearch : IDisposable
{
	// The limits of each search: the candidate issuers, each a signature check whether or not its signature is verified; the name and subtree comparisons, a directoryName counting by its attributes and length; and the entries of the policy graphs.
	public const int MaxCandidates = 100;
	public const long MaxNameComparisons = 1 << 20;
	public const long MaxPolicyGraphEntries = 1 << 16;

	private const string BasicConstraintsOid = "2.5.29.19";
	private const string KeyUsageOid = "2.5.29.15";
	private const string ExtendedKeyUsageOid = "2.5.29.37";
	private const string SubjectAlternativeNameOid = "2.5.29.17";
	private const string NameConstraintsOid = "2.5.29.30";
	private const string AuthorityKeyIdentifierOid = "2.5.29.35";
	private const string SubjectKeyIdentifierOid = "2.5.29.14";
	private const string CertificatePoliciesOid = "2.5.29.32";
	private const string PolicyMappingsOid = "2.5.29.33";
	private const string PolicyConstraintsOid = "2.5.29.36";
	private const string InhibitAnyPolicyOid = "2.5.29.54";
	private const string CrlDistributionPointsOid = "2.5.29.31";
	private const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";
	private const string ClientAuthenticationOid = "1.3.6.1.5.5.7.3.2";

	private readonly TrustAnchorCertificateValidator _validator;
	private readonly CertificateValidationContext _context;
	private readonly CancellationToken _cancellationToken;
	private readonly DateTimeOffset _time;
	private readonly PathNode _leaf;
	private readonly TrustAnchorEntry? _leafAnchor;
	private readonly List<PathNode> _pool = [];
	private readonly Dictionary<TrustAnchorEntry, PathNode> _anchorNodes = [];

	// Null for a validation that neither retrieves nor checks revocation, so that it allocates nothing for them.
	private readonly RetrievalState? _retrieval;

	// The candidates that GetCandidates finds, before it orders them; reused by each call.
	private readonly List<PathNode> _found = [];

	// The path from the peer's certificate, the problems of the edge to each certificate from the one before it, and the intermediate certificates up to each that are not self-issued.
	private readonly List<PathNode> _path = [];
	private readonly List<List<PathProblem>> _edges = [];
	private readonly List<int> _intermediates = [];

	// The results of the signature checks and of the name constraint checks, by pair of certificates; the latter is created by the first check of name constraints, which most paths lack.
	private readonly Dictionary<long, bool> _signatures = [];
	private Dictionary<long, PathProblem?>? _nameChecks;

	private int _candidatesLeft = MaxCandidates;
	private long _comparisonsLeft = MaxNameComparisons;
	private long _policyEntriesLeft = MaxPolicyGraphEntries;
	private int _nextIndex;

	private bool _relaxed;
	private bool _stopped;
	private string? _limit;
	private Attempt? _best;

	public CertificatePathSearch(TrustAnchorCertificateValidator validator, CertificateValidationContext context, CancellationToken cancellationToken)
	{
		_validator = validator;
		_context = context;
		_cancellationToken = cancellationToken;
		_time = X509Time.TruncateToSeconds(context.TimeProvider.GetUtcNow());

		IReadOnlyList<Certificate> presented = context.PresentedCertificates;
		_leafAnchor = validator.FindAnchor(presented[0]);
		_leaf = new PathNode(presented[0], PathRole.Leaf, _nextIndex++);
		HashSet<ReadOnlyMemory<byte>> encodings = new(ByteMemoryComparer.Instance) { presented[0].Encoded };

		// The others in their order, once each; a copy of a trust anchor is the trust anchor.
		for (int i = 1; i < presented.Count; ++i)
		{
			Certificate certificate = presented[i];

			if (validator.FindAnchor(certificate) is null && encodings.Add(certificate.Encoded))
			{
				_pool.Add(new PathNode(certificate, PathRole.Intermediate, _nextIndex++));
			}
		}

		if (validator.Retriever is not null || validator.RevocationMode is not X509RevocationMode.NoCheck)
		{
			_retrieval = new RetrievalState(encodings, retrievesIssuers: validator is { Retriever: not null, DisableCertificateDownloads: false });
		}
	}

	private string Purpose => _context.Usage is CertificateUsage.ServerAuthentication ? ServerAuthenticationOid : ClientAuthenticationOid;

	private string PurposeName => _context.Usage is CertificateUsage.ServerAuthentication ? "id-kp-serverAuth" : "id-kp-clientAuth";

	// For a validator that neither retrieves nor checks revocation, which never waits.
	public CertificateValidationResult Run()
	{
		List<PathProblem> leafProblems = GetProblems(_leaf);
		PathProblem? identity = CheckHostName();

		// A trust anchor presented as the peer's certificate is a path of its own: its key is trusted, so nothing signs it.
		if (_leafAnchor is not null)
		{
			return CreateResult([_leaf], CertificatePathEnd.TrustAnchor, [.. leafProblems, .. Optional(identity)]);
		}

		Push(_leaf, [], 0);
		return Search(relaxed: false) is { } path ? CreateResult(path, CertificatePathEnd.TrustAnchor, [.. leafProblems, .. Optional(identity)]) : ReportBestPath(identity);
	}

	// As Run, with the retrievals and the revocation checks, which complete synchronously unless they wait for the network.
	public async ValueTask<CertificateValidationResult> RunAsync()
	{
		List<PathProblem> leafProblems = GetProblems(_leaf);
		PathProblem? identity = CheckHostName();

		if (_leafAnchor is not null)
		{
			return CreateResult([_leaf], CertificatePathEnd.TrustAnchor, [.. leafProblems, .. Optional(identity)]);
		}

		Push(_leaf, [], 0);

		// The problems of the peer's certificate alone hold for every path, so that nothing retrieved could make it acceptable.
		bool acceptable = leafProblems.Count is 0 && identity is null;
		bool checksRevocation = acceptable && _validator.RevocationMode is not X509RevocationMode.NoCheck;

		while (true)
		{
			_retrieval?.DeadEnds?.Clear();

			if (Search(relaxed: false) is { } path)
			{
				KeepRetrievedIssuers(path);

				if (!checksRevocation)
				{
					return CreateResult(path, CertificatePathEnd.TrustAnchor, [.. leafProblems, .. Optional(identity)]);
				}

				// A certificate that is revoked, or whose status no source determines, gives way to another path, such as through a cross-certificate. If none is valid, the first revoked path is reported, or else the first whose status is not known.
				if (await CheckRevocationAsync(path).ConfigureAwait(false) is not { } problem)
				{
					return CreateResult(path, CertificatePathEnd.TrustAnchor, []);
				}

				if (_best is null || problem.Error is CertificateValidationError.Revoked && _best.Problems[0].Error is not CertificateValidationError.Revoked)
				{
					_best = new Attempt(path, CertificatePathEnd.TrustAnchor, [problem], 0, 1);
				}

				if (_retrieval?.RejectedEdges?.Count > MaxRejectedEdges)
				{
					Stop($"{MaxRejectedEdges} revoked certificates or certificates of unknown status");
					break;
				}
			}
			else if (!acceptable || _stopped || !await RetrieveIssuersAsync().ConfigureAwait(false))
			{
				break;
			}

			RestartSearch();
		}

		return ReportBestPath(identity);
	}

	// No path is valid, so the relaxed search, with limits of its own, records the paths that it ends, to report the best, whether or not a limit stopped the strict search; it accepts none, as only the strict search decides. A path that only revocation fails is already the best.
	private CertificateValidationResult ReportBestPath(PathProblem? identity)
	{
		PathProblem? strictLimit = GetLimit();

		if (_best is null)
		{
			RestartSearch();
			_relaxed = true;
			_ = Search(relaxed: true);

			// A limit stopped the relaxed search before it ended a path, so the peer's certificate ends the one reported.
			if (_best is null)
			{
				RecordDeadEnd(_leaf);
			}
		}

		Attempt best = _best ?? throw new InvalidOperationException();
		return CreateResult(best.Path, best.End, [.. best.Problems, .. Optional(strictLimit), .. Optional(GetLimit()), .. Optional(_retrieval?.Limit), .. Optional(identity)]);
	}

	public void Dispose()
	{
		_leaf.Key?.Dispose();

		foreach (PathNode node in _pool)
		{
			node.Key?.Dispose();
		}
	}

	private static IEnumerable<PathProblem> Optional(PathProblem? problem)
	{
		return problem is { } value ? [value] : [];
	}

	// The candidates for the issuer of the last certificate, each tried with the path so far. The strict search follows only the candidates without problems, and returns the first path that reaches a trust anchor, which then has no problem other than those of the peer's certificate, or null.
	// The relaxed search follows the candidates with problems too, one intermediate certificate beyond MaxPathLength at most, records the paths that they end, and returns null.
	private PathNode[]? Search(bool relaxed)
	{
		PathNode child = _path[^1];
		int below = _intermediates[^1];
		bool considered = false;
		bool extended = false;

		foreach (PathNode candidate in GetCandidates(child))
		{
			if (IsInPath(candidate) || _retrieval?.RejectedEdges?.Contains(EdgeOf(child, candidate)) is true)
			{
				continue;
			}

			bool intermediate = candidate.Role is PathRole.Intermediate;
			int intermediates = intermediate && !candidate.SelfIssued ? below + 1 : below;
			bool tooLong = intermediate && intermediates > _validator.MaxPathLength;

			if (tooLong && (!relaxed || intermediates > _validator.MaxPathLength + 1))
			{
				continue;
			}

			_cancellationToken.ThrowIfCancellationRequested();

			if (_candidatesLeft is 0)
			{
				StopAtCandidateLimit();
				return null;
			}

			--_candidatesLeft;
			considered = true;
			List<PathProblem> problems = GetProblems(candidate);

			if (!relaxed && problems.Count > 0)
			{
				continue;
			}

			List<PathProblem> edge = CheckEdge(child, candidate, below, tooLong, complete: relaxed);

			if (_stopped)
			{
				return null;
			}

			if (!relaxed && edge.Count > 0)
			{
				continue;
			}

			Push(candidate, edge, intermediates);
			extended = true;

			if (candidate.Role is not PathRole.Anchor)
			{
				if (Search(relaxed) is { } path)
				{
					return path;
				}
			}
			else
			{
				// RFC 5280, Sec. 6.1, needs the whole path, so its policies are checked when the path reaches a trust anchor; a path that fails gives way to the next candidate.
				PathProblem? policyProblem = CheckPolicies();

				if (relaxed)
				{
					Record(CertificatePathEnd.TrustAnchor, policyProblem);
				}
				else if (policyProblem is null && !_stopped)
				{
					return [.. _path];
				}
			}

			Pop();

			if (_stopped)
			{
				return null;
			}
		}

		if (relaxed)
		{
			if (!considered)
			{
				RecordDeadEnd(child);
			}
		}
		else if (!extended && _retrieval?.DeadEnds is { } deadEnds && !deadEnds.Contains(child))
		{
			deadEnds.Add(child);
		}

		return null;
	}

	// The candidates for the issuer of a certificate, those whose subject is its issuer byte for byte: the trust anchors, then the presented certificates in their order.
	// Within each, those whose subject key identifier is the certificate's authority key identifier come first, then those that lack one or the other, then the rest (RFC 5280, Sec. 4.2.1.1).
	private PathNode[] GetCandidates(PathNode child)
	{
		if (child.Candidates is { } cached)
		{
			return cached;
		}

		ReadOnlyMemory<byte> issuer = child.Certificate.Issuer;
		List<PathNode> found = _found;
		found.Clear();

		foreach (TrustAnchorEntry anchor in _validator.FindAnchorsBySubject(issuer))
		{
			if (!_anchorNodes.TryGetValue(anchor, out PathNode? node))
			{
				node = new PathNode(anchor.Certificate, PathRole.Anchor, _nextIndex++, anchor);
				_anchorNodes.Add(anchor, node);
			}

			found.Add(node);
		}

		int anchors = found.Count;
		ReadOnlySpan<byte> issuerName = issuer.Span;

		foreach (PathNode node in _pool)
		{
			if (node != child && node.Certificate.Subject.Span.SequenceEqual(issuerName))
			{
				found.Add(node);
			}
		}

		ReadOnlySpan<PathNode> all = CollectionsMarshal.AsSpan(found);
		PathNode[] candidates = all.IsEmpty ? [] : new PathNode[all.Length];
		int count = AddByKeyIdentifier(candidates, 0, all.Slice(0, anchors), child.AuthorityKeyIdentifier);
		AddByKeyIdentifier(candidates, count, all.Slice(anchors), child.AuthorityKeyIdentifier);
		child.Candidates = candidates;
		return candidates;
	}

	// Writes the candidates to ordered from count on, in the tiers that GetCandidates describes, and returns the new count.
	private static int AddByKeyIdentifier(PathNode[] ordered, int count, ReadOnlySpan<PathNode> candidates, ReadOnlyMemory<byte>? authorityKeyIdentifier)
	{
		for (int tier = 0; tier < 3; ++tier)
		{
			foreach (PathNode candidate in candidates)
			{
				int match = authorityKeyIdentifier is not { } wanted || candidate.SubjectKeyIdentifier is not { } actual ? 1 : wanted.Span.SequenceEqual(actual.Span) ? 0 : 2;

				if (match == tier)
				{
					ordered[count++] = candidate;
				}
			}
		}

		return count;
	}

	// A candidate whose subject and key are those of a certificate of the path would make a cycle.
	private bool IsInPath(PathNode candidate)
	{
		ReadOnlySpan<byte> subject = candidate.Certificate.Subject.Span;

		foreach (PathNode node in CollectionsMarshal.AsSpan(_path))
		{
			if (node.Certificate.Subject.Span.SequenceEqual(subject) && node.Certificate.PublicKeyInfo.Encoded.Span.SequenceEqual(candidate.Certificate.PublicKeyInfo.Encoded.Span))
			{
				return true;
			}
		}

		return false;
	}

	// The checks of the edge from the last certificate of the path to a candidate for its issuer, other than the candidate's own; complete makes every check, and otherwise the first problem ends them.
	private List<PathProblem> CheckEdge(PathNode child, PathNode issuer, int below, bool tooLong, bool complete)
	{
		List<PathProblem> problems = [];

		// RFC 5280, Sec. 6.1.4 (l), with MaxPathLength as the max_path_length of the trust anchor.
		if (tooLong)
		{
			problems.Add(new PathProblem(CertificateValidationError.NotValidForUsage, $"The path has more than {_validator.MaxPathLength} intermediate certificates that are not self-issued, the most that the validator allows."));
		}

		// RFC 5280, Sec. 6.1.4 (l) and (m): the pathLenConstraint of a CA, the trust anchor's included, bounds the intermediate certificates below it that are not self-issued.
		if (issuer.PathLengthConstraint is { } limit && below > limit)
		{
			problems.Add(new PathProblem(CertificateValidationError.NotValidForUsage, $"{{0}} allows {limit} intermediate certificates that are not self-issued below it, and the path has {below}.", issuer));
		}

		if (problems.Count > 0 && !complete)
		{
			return problems;
		}

		// RFC 5280, Sec. 6.1.3 (b) and (c), and 6.1.4 (g): the name constraints of a CA apply to every certificate below it but the self-issued intermediate ones.
		if (issuer.NameConstraints is { } constraints)
		{
			for (int i = 0; i < _path.Count; ++i)
			{
				PathNode node = _path[i];

				if (i > 0 && node.SelfIssued)
				{
					continue;
				}

				PathProblem? problem = CheckNames(issuer, constraints, node);

				if (_stopped)
				{
					return problems;
				}

				if (problem is { } value)
				{
					problems.Add(value);

					if (!complete)
					{
						return problems;
					}
				}
			}
		}

		// RFC 5280, Sec. 6.1.3 (a)(1). A certificate whose algorithm cannot be verified, or an issuer whose key cannot be imported, has the problem already, so the edge fails without a signature.
		if (child.SignatureProblem is { } signatureProblem)
		{
			problems.Add(signatureProblem);
		}
		else if (issuer.Key is { } key && !Verify(child, issuer, key))
		{
			problems.Add(new PathProblem(CertificateValidationError.InvalidSignature, "The signature of {0} does not verify with the key of {1}.", child, issuer));
		}

		return problems;
	}

	private bool Verify(PathNode child, PathNode issuer, ISignatureKey key)
	{
		long pair = (long)child.Index << 32 | (uint)issuer.Index;

		if (!_signatures.TryGetValue(pair, out bool valid))
		{
			valid = child.Certificate.VerifySignature(key);
			_signatures.Add(pair, valid);
		}

		return valid;
	}

	// The names of a certificate against the name constraints of a CA, once for each pair; stops the search, and returns null, if the comparisons would exceed the limit.
	private PathProblem? CheckNames(PathNode issuer, NameConstraints constraints, PathNode node)
	{
		long pair = (long)issuer.Index << 32 | (uint)node.Index;
		Dictionary<long, PathProblem?> nameChecks = _nameChecks ??= [];

		if (nameChecks.TryGetValue(pair, out PathProblem? cached))
		{
			return cached;
		}

		PathProblem? problem = null;

		if (node.GetNames() is not { } names)
		{
			problem = new PathProblem(CertificateValidationError.Malformed, "The subject alternative name extension of {0} does not decode, so the name constraints of {1} cannot be checked.", node, issuer);
		}
		else
		{
			long comparisons = constraints.CountComparisons(names);

			if (comparisons > _comparisonsLeft)
			{
				Stop($"{MaxNameComparisons} comparisons of names with name constraints");
				return null;
			}

			_comparisonsLeft -= comparisons;

			if (constraints.Check(names, out string? text) is { } error)
			{
				problem = new PathProblem(error, "{0} " + text + ".", node, issuer);
			}
		}

		nameChecks.Add(pair, problem);
		return problem;
	}

	// Stops the search, and returns null, if the entries of the graph would exceed the limit.
	private PathProblem? CheckPolicies()
	{
		PathProblem? problem = PolicyGraph.Check(_path, _validator, ref _policyEntriesLeft, out bool limitReached);

		if (limitReached)
		{
			Stop($"{MaxPolicyGraphEntries} entries of the policy graphs");
		}

		return problem;
	}

	// The problems of a certificate whatever path it is in, found once.
	private List<PathProblem> GetProblems(PathNode node)
	{
		if (node.Problems is { } cached)
		{
			return cached;
		}

		List<PathProblem> problems = [];
		Certificate certificate = node.Certificate;
		DecodedExtensions decoded = certificate.DecodedExtensions;

		// RFC 5280, Sec. 6.1.3 (a)(2): the validity period includes both ends, to the second.
		if (_time < certificate.NotBefore || _time > certificate.NotAfter)
		{
			problems.Add(new PathProblem(CertificateValidationError.Expired, string.Create(CultureInfo.InvariantCulture, $"{{0}} is valid from {certificate.NotBefore:u} to {certificate.NotAfter:u}, which leaves out the validation time, {_time:u}."), node));
		}

		// RFC 5280, Sec. 4.1.2.4: the issuer, which links the certificate to the subject of the next, must not be empty. A trust anchor's issuer links nothing.
		if (node.Role is not PathRole.Anchor && _leafAnchor is null && certificate.Issuer.Span is [0x30, 0x00])
		{
			problems.Add(new PathProblem(CertificateValidationError.Malformed, "{0} has an empty issuer name.", node));
		}

		CheckExtensions(node, problems);

		switch (node.Role)
		{
			case PathRole.Leaf:
			{
				// RFC 5280, Sec. 4.2.1.12: the peer's certificate needs the usage itself if it has the extension; anyExtendedKeyUsage does not stand for it.
				if (decoded.ExtendedKeyUsage.Value is { } usage && !usage.Contains(Purpose))
				{
					problems.Add(new PathProblem(CertificateValidationError.NotValidForUsage, $"{{0}} has an extended key usage extension without {PurposeName}.", node));
				}

				// RFC 5280, Sec. 4.2.1.10: only CAs constrain names, for the certificates that they issue.
				if (decoded.NameConstraints.Value is not null || decoded.NameConstraints.Error is not null)
				{
					problems.Add(new PathProblem(CertificateValidationError.NotValidForUsage, "{0} has a name constraints extension, which only a CA certificate may have.", node));
				}

				if (_leafAnchor is null)
				{
					CheckSignatureAlgorithm(node, problems);
				}

				break;
			}
			case PathRole.Intermediate:
			{
				// RFC 5280, Sec. 6.1.4 (k): an intermediate certificate, whatever its version, must be a CA certificate.
				if (decoded.BasicConstraints.Error is null && decoded.BasicConstraints.Value is not { CertificateAuthority: true })
				{
					problems.Add(new PathProblem(CertificateValidationError.NotValidForUsage, decoded.BasicConstraints.Value is null ? "{0} issues another certificate of the path, but has no basic constraints extension." : "{0} issues another certificate of the path, but its basic constraints do not assert cA.", node));
				}

				CheckIssuer(node, problems);
				CheckSignatureAlgorithm(node, problems);
				break;
			}
			default:
			{
				// A trust anchor needs no basic constraints extension, as a version 1 certificate has none, but one that it has must assert cA.
				if (decoded.BasicConstraints.Value is { CertificateAuthority: false })
				{
					problems.Add(new PathProblem(CertificateValidationError.NotValidForUsage, "{0} is a trust anchor whose basic constraints do not assert cA.", node));
				}

				CheckIssuer(node, problems);
				break;
			}
		}

		CheckKey(node, problems);
		node.Problems = problems;
		return problems;
	}

	// RFC 5280, Sec. 4.2: a critical extension must be one that the validator processes. The authority and subject key identifier extensions must not be critical (Secs. 4.2.1.1 and 4.2.1.2), the policy constraints and inhibit anyPolicy extensions of a certificate that takes part in policy processing must be (Secs. 4.2.1.11 and 4.2.1.14), and the extensions that decode on first use must decode.
	private void CheckExtensions(PathNode node, List<PathProblem> problems)
	{
		IReadOnlyList<CertificateExtension> extensions = node.Certificate.Extensions;
		DecodedExtensions decoded = node.Certificate.DecodedExtensions;

		// Most certificates have neither extension, and their other extensions are not compared with the two.
		bool hasPolicyExtensions = decoded.PolicyConstraints.Value is not null || decoded.PolicyConstraints.Error is not null || decoded.InhibitAnyPolicy.Value is not null || decoded.InhibitAnyPolicy.Error is not null;

		// Indexed, as an enumerator of the interface would be allocated.
		for (int i = 0; i < extensions.Count; ++i)
		{
			CertificateExtension extension = extensions[i];

			if (!extension.Critical)
			{
				if (hasPolicyExtensions && node.Role is not PathRole.Anchor && _leafAnchor is null && extension.Oid is PolicyConstraintsOid or InhibitAnyPolicyOid)
				{
					problems.Add(new PathProblem(CertificateValidationError.Malformed, $"{{0}} does not mark its {(extension.Oid is PolicyConstraintsOid ? "policy constraints" : "inhibit anyPolicy")} extension critical, which RFC 5280 requires.", node));
				}

				continue;
			}

			switch (extension.Oid)
			{
				case BasicConstraintsOid or KeyUsageOid or ExtendedKeyUsageOid or SubjectAlternativeNameOid or NameConstraintsOid or PolicyMappingsOid or PolicyConstraintsOid or InhibitAnyPolicyOid:
				{
					break;
				}
				case CertificatePoliciesOid:
				{
					// RFC 5280, Sec. 4.2.1.4: the qualifiers of a critical extension must be ones that the validator interprets, unless the certificate takes no part in policy processing.
					if (node.Role is not PathRole.Anchor && _leafAnchor is null && node.Certificate.DecodedExtensions.CertificatePolicies.Value is { HasUnrecognizedQualifier: true })
					{
						problems.Add(new PathProblem(CertificateValidationError.NotValidForUsage, "{0} has a critical certificate policies extension with a qualifier that the validator does not interpret.", node));
					}

					break;
				}
				case CrlDistributionPointsOid:
				{
					// RFC 5280, Sec. 4.2.1.13: the extension should not be critical, but is understood; revocation checks use it.
					if (node.Certificate.DecodedExtensions.CrlDistributionPoints.Error is not null)
					{
						problems.Add(new PathProblem(CertificateValidationError.Malformed, "{0} has a critical CRL distribution points extension that does not decode.", node));
					}

					break;
				}
				case AuthorityKeyIdentifierOid or SubjectKeyIdentifierOid:
				{
					problems.Add(new PathProblem(CertificateValidationError.Malformed, $"{{0}} marks its {(extension.Oid is AuthorityKeyIdentifierOid ? "authority" : "subject")} key identifier extension critical, which RFC 5280 forbids.", node));
					break;
				}
				default:
				{
					problems.Add(new PathProblem(CertificateValidationError.NotValidForUsage, $"{{0}} has the critical extension {extension.Oid}, which the validator does not recognize.", node));
					break;
				}
			}
		}

		if (node.Role is not PathRole.Anchor && _leafAnchor is null)
		{
			CheckRevocationExemption(node, problems);
		}

		// Nearly every certificate gets here with all of them decoded, for which the list below is not built.
		if ((decoded.BasicConstraints.Error ?? decoded.ExtendedKeyUsage.Error ?? decoded.SubjectAlternativeName.Error ?? decoded.NameConstraints.Error ?? decoded.AuthorityKeyIdentifier.Error ?? decoded.SubjectKeyIdentifier.Error ?? decoded.CertificatePolicies.Error ?? decoded.PolicyMappings.Error ?? decoded.PolicyConstraints.Error ?? decoded.InhibitAnyPolicy.Error) is null)
		{
			return;
		}

		foreach ((AsnContentException? error, string name) in (ReadOnlySpan<(AsnContentException?, string)>)[(decoded.BasicConstraints.Error, "basic constraints"), (decoded.ExtendedKeyUsage.Error, "extended key usage"), (decoded.SubjectAlternativeName.Error, "subject alternative name"), (decoded.NameConstraints.Error, "name constraints"), (decoded.AuthorityKeyIdentifier.Error, "authority key identifier"), (decoded.SubjectKeyIdentifier.Error, "subject key identifier"), (decoded.CertificatePolicies.Error, "certificate policies"), (decoded.PolicyMappings.Error, "policy mappings"), (decoded.PolicyConstraints.Error, "policy constraints"), (decoded.InhibitAnyPolicy.Error, "inhibit anyPolicy")])
		{
			if (error is not null)
			{
				problems.Add(new PathProblem(CertificateValidationError.Malformed, $"{{0}} has a {name} extension that does not decode.", node));
			}
		}
	}

	// RFC 9608, Sec. 3: a certificate that breaks these rules is invalid, whether or not revocation is checked. A value that is not NULL exempts nothing and is an error too.
	private static void CheckRevocationExemption(PathNode node, List<PathProblem> problems)
	{
		DecodedExtensions decoded = node.Certificate.DecodedExtensions;

		if (decoded.OcspNoCheck.Error is not null)
		{
			problems.Add(new PathProblem(CertificateValidationError.Malformed, "{0} has an ocsp-nocheck extension whose value is not NULL.", node));
		}

		if (decoded.NoRevocationAvailable.Error is not null)
		{
			problems.Add(new PathProblem(CertificateValidationError.Malformed, "{0} has a noRevAvail extension whose value is not NULL.", node));
		}

		if (decoded.FindNoRevocationAvailableProblem() is { } problem)
		{
			problems.Add(new PathProblem(CertificateValidationError.Malformed, $"{{0}} {problem}.", node));
		}
	}

	// The checks of a CA certificate, a trust anchor's included, that do not depend on the path.
	private void CheckIssuer(PathNode node, List<PathProblem> problems)
	{
		Certificate certificate = node.Certificate;
		DecodedExtensions decoded = certificate.DecodedExtensions;

		// RFC 5280, Sec. 6.1.4 (n).
		if (certificate.KeyUsage is { } keyUsage && (keyUsage & X509KeyUsageFlags.KeyCertSign) is 0)
		{
			problems.Add(new PathProblem(CertificateValidationError.NotValidForUsage, "{0} issues another certificate of the path, but its key usage extension does not assert keyCertSign.", node));
		}

		// A CA's extended key usage extension, if any, restricts the certificates below it: it must have the usage or anyExtendedKeyUsage.
		if (decoded.ExtendedKeyUsage.Value is { } usage && !usage.Contains(Purpose) && !usage.Contains(ExtendedKeyUsage.AnyExtendedKeyUsage))
		{
			problems.Add(new PathProblem(CertificateValidationError.NotValidForUsage, $"{{0}} has an extended key usage extension with neither {PurposeName} nor anyExtendedKeyUsage.", node));
		}
	}

	// The signature algorithm of a certificate other than a trust anchor, which an issuer must verify.
	private static void CheckSignatureAlgorithm(PathNode node, List<PathProblem> problems)
	{
		if (CertificatePolicy.CheckSignatureAlgorithm(node.Certificate.SignatureAlgorithm) is not { } error)
		{
			return;
		}

		string text = error is CertificateValidationError.WeakAlgorithm
			? $"{{0}} is signed with {node.Certificate.SignatureAlgorithm.Oid}, which the policy refuses."
			: $"{{0}} is signed with {node.Certificate.SignatureAlgorithm.Oid}, which the validator does not support.";

		node.SignatureProblem = new PathProblem(error, text, node);
		problems.Add(node.SignatureProblem.Value);
	}

	// The key against the policy, and imported: an intermediate certificate's to verify the certificate below it, and the peer's, which the caller verifies with, to learn that it is supported.
	private void CheckKey(PathNode node, List<PathProblem> problems)
	{
		SubjectPublicKeyInfo info = node.Certificate.PublicKeyInfo;

		if (CertificatePolicy.CheckPublicKey(info, _validator.MinRsaKeySize, out string? reason) is { } policyError)
		{
			problems.Add(new PathProblem(policyError, "{0} " + reason + ".", node));
			return;
		}

		ISignatureKey? key;
		CertificateValidationError error;
		string? message;

		if ((node.Anchor ?? (node.Role is PathRole.Leaf ? _leafAnchor : null)) is { } anchor)
		{
			(key, error, message) = (anchor.Key, anchor.ImportError, anchor.ImportMessage);
		}
		else
		{
			key = TrustAnchorCertificateValidator.ImportKey(_validator.ImportPublicKey, info, out error, out message);

			// The peer's key verifies only the certificate's own signature, if it is self-issued, to tell whether a path that ends with it ends at a self-signed certificate.
			if (node.Role is PathRole.Leaf && !node.SelfIssued)
			{
				key?.Dispose();
			}
		}

		if (key is null)
		{
			problems.Add(new PathProblem(error, $"{{0}} has a key that the validator cannot import: {PathProblem.Escape(message ?? "")}", node));
			return;
		}

		if (node.Role is not PathRole.Leaf || _leafAnchor is null && node.SelfIssued)
		{
			node.Key = key;
		}
	}

	private PathProblem? CheckHostName()
	{
		if (_context.HostName is not { } hostName)
		{
			return null;
		}

		try
		{
			return _leaf.Certificate.MatchHostName(hostName) switch
			{
				HostNameMatch.Match => null,
				HostNameMatch.MalformedExtension => new PathProblem(CertificateValidationError.Malformed, "The subject alternative name extension of {0} does not decode, so the certificate identifies no host.", _leaf),
				_ => new PathProblem(CertificateValidationError.NameMismatch, $"{{0}} does not identify {PathProblem.Escape(hostName)}.", _leaf)
			};
		}
		catch (ArgumentException)
		{
			return new PathProblem(CertificateValidationError.NameMismatch, $"The host name {PathProblem.Escape(hostName)} is neither a DNS name nor an IP address.", _leaf);
		}
	}

	private void Push(PathNode node, List<PathProblem> edge, int intermediates)
	{
		_path.Add(node);
		_edges.Add(edge);
		_intermediates.Add(intermediates);
	}

	private void Pop()
	{
		_path.RemoveAt(_path.Count - 1);
		_edges.RemoveAt(_edges.Count - 1);
		_intermediates.RemoveAt(_intermediates.Count - 1);
	}

	// Back to the peer's certificate, with new limits: a search that follows a retrieval or a revocation repeats the checks from their caches.
	private void RestartSearch()
	{
		while (_path.Count > 1)
		{
			Pop();
		}

		(_stopped, _limit, _candidatesLeft, _comparisonsLeft, _policyEntriesLeft) = (false, null, MaxCandidates, MaxNameComparisons, MaxPolicyGraphEntries);
	}

	// A limit stops the search, which the result reports: one that stops the strict search fails the validation, as a valid path may be among those left, and one that stops the relaxed search leaves out the paths that it did not end.
	private void Stop(string limit)
	{
		_stopped = true;
		_limit ??= $"The search for {(_relaxed ? "the path to report" : "a valid path")} stopped at the limit of {limit}.";
	}

	private void StopAtCandidateLimit()
	{
		Stop($"{MaxCandidates} candidate issuers");
	}

	private PathProblem? GetLimit()
	{
		return _limit is { } text ? new PathProblem(CertificateValidationError.Unspecified, text) : null;
	}

	private void RecordDeadEnd(PathNode last)
	{
		bool selfSigned = IsSelfSigned(last);
		PathProblem end = selfSigned
			? new PathProblem(CertificateValidationError.UntrustedRoot, "{0} is self-signed, but not a trust anchor.", last)
			: new PathProblem(CertificateValidationError.UntrustedRoot, "No issuer of {0} was found that leads to a trust anchor.", last);

		Record(selfSigned ? CertificatePathEnd.UntrustedRoot : CertificatePathEnd.MissingIssuer, end);
	}

	// Whether a certificate is self-signed: self-issued, with a signature that its own key verifies. One whose signature cannot be verified, as its algorithm or key is not supported, is not.
	// The check counts as a candidate, once for each certificate; without a candidate left, it stops the search, and the certificate counts as not self-signed.
	private bool IsSelfSigned(PathNode node)
	{
		if (!node.SelfIssued || node.SignatureProblem is not null || node.Key is not { } key)
		{
			return false;
		}

		if (!_signatures.ContainsKey((long)node.Index << 32 | (uint)node.Index))
		{
			if (_candidatesLeft is 0)
			{
				StopAtCandidateLimit();
				return false;
			}

			--_candidatesLeft;
		}

		return Verify(node, node, key);
	}

	// Keeps the path if it is the best so far: one that ends at a trust anchor before one that ends at a self-signed certificate before a partial one, then the one with the fewest errors, then the first.
	private void Record(CertificatePathEnd end, PathProblem? endProblem)
	{
		List<PathProblem> problems = [];

		for (int i = 0; i < _path.Count; ++i)
		{
			problems.AddRange(_path[i].Problems ?? []);
			problems.AddRange(_edges[i]);
		}

		if (endProblem is { } value)
		{
			problems.Add(value);
		}

		int rank = end switch
		{
			CertificatePathEnd.TrustAnchor => 0,
			CertificatePathEnd.UntrustedRoot => 1,
			_ => 2
		};

		int errors = CountErrors(problems);

		if (_best is null || rank < _best.Rank || rank == _best.Rank && errors < _best.Errors)
		{
			_best = new Attempt([.. _path], end, [.. problems], rank, errors);
		}
	}

	private static int CountErrors(List<PathProblem> problems)
	{
		int seen = 0;

		foreach (PathProblem problem in problems)
		{
			seen |= 1 << (int)problem.Error;
		}

		return System.Numerics.BitOperations.PopCount((uint)seen);
	}

	private static CertificateValidationResult CreateResult(IReadOnlyList<PathNode> path, CertificatePathEnd end, IReadOnlyList<PathProblem> problems)
	{
		List<CertificateValidationError> errors = new(problems.Count);
		List<string> messages = [];

		foreach (PathProblem problem in problems)
		{
			errors.Add(problem.Error);
			string message = problem.Format(path);

			if (!messages.Contains(message))
			{
				messages.Add(message);
			}
		}

		Certificate[] certificates = new Certificate[path.Count];

		for (int i = 0; i < certificates.Length; ++i)
		{
			certificates[i] = path[i].Certificate;
		}

		return CertificateValidationResult.Create(errors, certificates, end, messages.Count > 0 ? string.Join(" ", messages) : null);
	}

	private sealed class Attempt(PathNode[] path, CertificatePathEnd end, PathProblem[] problems, int rank, int errors)
	{
		public PathNode[] Path { get; } = path;

		public CertificatePathEnd End { get; } = end;

		public PathProblem[] Problems { get; } = problems;

		public int Rank { get; } = rank;

		public int Errors { get; } = errors;
	}
}

internal enum PathRole
{
	Leaf,
	Intermediate,
	Anchor
}

// A certificate in one validation, with what the search learns of it.
internal sealed class PathNode
{
	private bool _namesRead;
	private ConstrainedNames? _names;

	public PathNode(Certificate certificate, PathRole role, int index, TrustAnchorEntry? anchor = null)
	{
		Certificate = certificate;
		Role = role;
		Index = index;
		Anchor = anchor;
		SelfIssued = certificate.Issuer.Span.SequenceEqual(certificate.Subject.Span);
		DecodedExtensions decoded = certificate.DecodedExtensions;
		AuthorityKeyIdentifier = decoded.AuthorityKeyIdentifier.Value?.KeyIdentifier;
		SubjectKeyIdentifier = decoded.SubjectKeyIdentifier.Value;
		PathLengthConstraint = role is PathRole.Leaf ? null : decoded.BasicConstraints.Value?.PathLengthConstraint;
		NameConstraints = role is PathRole.Leaf ? null : decoded.NameConstraints.Value;
	}

	public Certificate Certificate { get; }

	public PathRole Role { get; }

	// Unique within the validation, for the caches of pairs.
	public int Index { get; }

	public TrustAnchorEntry? Anchor { get; }

	// RFC 5280, Sec. 6.1: the issuer is the subject, byte for byte.
	public bool SelfIssued { get; }

	public ReadOnlyMemory<byte>? AuthorityKeyIdentifier { get; }

	public ReadOnlyMemory<byte>? SubjectKeyIdentifier { get; }

	public int? PathLengthConstraint { get; }

	public NameConstraints? NameConstraints { get; }

	public List<PathProblem>? Problems { get; set; }

	public PathProblem? SignatureProblem { get; set; }

	public ISignatureKey? Key { get; set; }

	public PathNode[]? Candidates { get; set; }

	// The names that name constraints apply to, or null if the subject alternative name extension does not decode.
	public ConstrainedNames? GetNames()
	{
		if (!_namesRead)
		{
			DecodedExtension<SubjectAlternativeName> alternativeName = Certificate.DecodedExtensions.SubjectAlternativeName;
			_names = alternativeName.Error is null ? ConstrainedNames.Create(Certificate, alternativeName.Value) : null;
			_namesRead = true;
		}

		return _names;
	}
}

// A reason why a certification path is not acceptable. Text is a composite format string whose argument {0} describes Subject and {1} Other, and whose other braces are doubled.
internal readonly record struct PathProblem(CertificateValidationError Error, string Text, PathNode? Subject = null, PathNode? Other = null)
{
	// Text to put in Text, the composite format string: as EscapeText makes it, with its braces doubled.
	public static string Escape(string value)
	{
		return EscapeText(value).Replace("{", "{{", StringComparison.Ordinal).Replace("}", "}}", StringComparison.Ordinal);
	}

	// Text from a certificate or the peer, with each control character, line or paragraph separator and unpaired surrogate written as \uXXXX, so that a message is one line that any encoding can write.
	public static string EscapeText(string value)
	{
		StringBuilder? escaped = null;

		for (int i = 0; i < value.Length; ++i)
		{
			char c = value[i];

			if (char.IsHighSurrogate(c) && i + 1 < value.Length && char.IsLowSurrogate(value[i + 1]))
			{
				escaped?.Append(value, i, 2);
				++i;
			}
			else if (char.IsControl(c) || char.IsSurrogate(c) || CharUnicodeInfo.GetUnicodeCategory(c) is UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator)
			{
				escaped ??= new StringBuilder(value, 0, i, value.Length + 8);
				escaped.Append(CultureInfo.InvariantCulture, $"\\u{(int)c:X4}");
			}
			else
			{
				escaped?.Append(c);
			}
		}

		return escaped?.ToString() ?? value;
	}

	public string Format(IReadOnlyList<PathNode> path)
	{
		string message = string.Format(CultureInfo.InvariantCulture, Text, Describe(Subject, path), Describe(Other, path));
		return message.Length > 0 && char.IsAsciiLetterLower(message[0]) ? char.ToUpperInvariant(message[0]) + message.Substring(1) : message;
	}

	private static string Describe(PathNode? node, IReadOnlyList<PathNode> path)
	{
		if (node is null)
		{
			return "";
		}

		int position = -1;

		for (int i = 0; i < path.Count && position < 0; ++i)
		{
			position = path[i] == node ? i : -1;
		}

		string description = position switch
		{
			0 => "the peer's certificate",
			_ when node.Role is PathRole.Anchor => "the trust anchor",
			> 0 => $"certificate {position} of the path",
			_ => "a certificate"
		};

		try
		{
			string subject = EscapeText(new X500DistinguishedName(node.Certificate.Subject.Span).Name);
			return subject.Length > 0 ? $"{description} ({subject})" : description;
		}
		catch (CryptographicException)
		{
			return description;
		}
	}
}

// A trust anchor of a validator, with its key, imported once, or why it was not.
internal sealed class TrustAnchorEntry(Certificate certificate, ISignatureKey? key, CertificateValidationError importError, string? importMessage)
{
	public Certificate Certificate { get; } = certificate;

	public ISignatureKey? Key { get; } = key;

	public CertificateValidationError ImportError { get; } = importError;

	public string? ImportMessage { get; } = importMessage;
}

// Compares byte sequences by their contents, such as encoded names.
internal sealed class ByteMemoryComparer : IEqualityComparer<ReadOnlyMemory<byte>>
{
	public static readonly ByteMemoryComparer Instance = new();

	public bool Equals(ReadOnlyMemory<byte> x, ReadOnlyMemory<byte> y)
	{
		return x.Span.SequenceEqual(y.Span);
	}

	public int GetHashCode(ReadOnlyMemory<byte> obj)
	{
		HashCode hash = new();
		hash.AddBytes(obj.Span);
		return hash.ToHashCode();
	}
}
