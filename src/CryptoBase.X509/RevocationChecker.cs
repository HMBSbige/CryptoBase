namespace CryptoBase.X509;

// What one CRL or OCSP response says about one certificate.
internal enum RevocationStatus
{
	// The source covers the certificate and does not list it: for a CRL, for every reason; for OCSP, a good response.
	Good,

	// The source revokes the certificate.
	Revoked,

	// An OCSP response that says that the responder does not know the certificate.
	Unknown,

	// The CRL does not cover the certificate, or not for every reason: its issuer differs, it is out of scope, it is a delta or indirect CRL, or it covers only some reasons, which CoveredReasons gives.
	NotApplicable,

	// The source cannot be used, for the reason that Detail gives: bad signature, out of date, malformed or with an extension that the checker does not process.
	Invalid,
}

// The result of RevocationChecker. Reason and RevocationTime are set for Revoked, Reason being Unspecified if the source gives none; CoveredReasons is the interim_reasons_mask of RFC 5280, Sec. 6.3.3, for a CRL, which is set only once the signature has been verified, as it is empty for a CRL that goes no further; NextUpdate is the nextUpdate of a response that the checker accepted.
internal readonly record struct RevocationResult(RevocationStatus Status, string? Detail = null)
{
	public X509RevocationReason? Reason { get; init; }

	public DateTimeOffset? RevocationTime { get; init; }

	public CrlReasonFlags CoveredReasons { get; init; }

	public DateTimeOffset? NextUpdate { get; init; }
}

// Decides what a CRL or an OCSP response says about a certificate whose issuer is known, without retrieving anything. Each call is about one source; combining sources is the caller's.
internal static class RevocationChecker
{
	// The clock difference that an OCSP validity interval tolerates by default (RFC 9919, Sec. 5).
	public static readonly TimeSpan OcspClockSkew = TimeSpan.FromMinutes(5);

	// The reasons of RFC 5280, Sec. 6.3.2 (a): all those of ReasonFlags but unused.
	public const CrlReasonFlags AllReasons = CrlReasonFlags.KeyCompromise | CrlReasonFlags.CACompromise | CrlReasonFlags.AffiliationChanged | CrlReasonFlags.Superseded | CrlReasonFlags.CessationOfOperation | CrlReasonFlags.CertificateHold | CrlReasonFlags.PrivilegeWithdrawn | CrlReasonFlags.AACompromise;

	// The candidates for a delegated responder that a response may make the checker verify, each costing two signature checks, so that a response with many certificates of one name cannot make it work without bound.
	private const int MaxResponderCandidates = 8;

	private const string AuthorityKeyIdentifierOid = "2.5.29.35";
	private const string IssuerAlternativeNameOid = "2.5.29.18";
	private const string DeltaCrlIndicatorOid = "2.5.29.27";
	private const string IssuingDistributionPointOid = "2.5.29.28";
	private const string BasicConstraintsOid = "2.5.29.19";
	private const string KeyUsageOid = "2.5.29.15";
	private const string ExtendedKeyUsageOid = "2.5.29.37";
	private const string SubjectAlternativeNameOid = "2.5.29.17";
	private const string ReasonCodeOid = "2.5.29.21";
	private const string InvalidityDateOid = "2.5.29.24";
	private const string OcspNoCheckOid = "1.3.6.1.5.5.7.48.1.5";
	private const string OcspExtendedRevokeOid = "1.3.6.1.5.5.7.48.1.9";
	private const string OcspCrlReferenceOid = "1.3.6.1.5.5.7.48.1.3";
	private const string OcspArchiveCutoffOid = "1.3.6.1.5.5.7.48.1.6";
	private const string OcspSigningOid = "1.3.6.1.5.5.7.3.9";

	// Checks a certificate against one CRL at a time (RFC 5280, Sec. 6.3.3), for a complete CRL of the certificate's issuer. issuer is a certificate of the CRL's issuer whose validity the caller established, and issuerKey is its key; the caller keeps ownership of the key.
	// Delta and indirect CRLs are refused as NotApplicable, never as Good: a delta CRL lists only changes (Sec. 5.2.4), and an indirect CRL attributes its entries to issuers that the checker does not track (Sec. 5.3.3).
	public static RevocationResult CheckCrl(CertificateRevocationList crl, Certificate certificate, Certificate issuer, ISignatureKey issuerKey, DateTimeOffset time)
	{
		// Sec. 6.3.3 (b)(1). The names are compared byte for byte, as Sec. 5.2.5 and the path search compare them; a name in another encoding is out of scope, which never reports a certificate as good.
		if (!crl.Issuer.Span.SequenceEqual(certificate.Issuer.Span))
		{
			return NotApplicable("The CRL's issuer is not the certificate's.");
		}

		DecodedCrlExtensions extensions = crl.DecodedExtensions;

		if (extensions.AuthorityKeyIdentifier.Error is not null || extensions.CrlNumber.Error is not null || extensions.DeltaCrlIndicator.Error is not null || extensions.IssuingDistributionPoint.Error is not null)
		{
			return Invalid("An extension of the CRL does not decode.");
		}

		// Sec. 5.2 and 5.3: a critical extension that is not understood forbids using the CRL for any certificate.
		if (FindUnrecognizedCriticalExtension(crl.Extensions) is { } unrecognized)
		{
			return Invalid($"The CRL has the critical extension {unrecognized}, which the checker does not process.");
		}

		if (crl.HasUnrecognizedCriticalEntryExtension)
		{
			return Invalid("A CRL entry has a critical extension that the checker does not process.");
		}

		// Sec. 5.2.3: a conforming CRL has a CRL number, and so must every version 2 CRL. A version 1 CRL has no extensions at all, and Sec. 5 requires applications to process it.
		if (crl.Version is 2 && extensions.CrlNumber.Value is null)
		{
			return Invalid("The CRL has no CRL number extension.");
		}

		if (extensions.DeltaCrlIndicator.Value is not null)
		{
			return NotApplicable("The CRL is a delta CRL, which the checker does not support.");
		}

		IssuingDistributionPoint? issuingDistributionPoint = extensions.IssuingDistributionPoint.Value;

		if (GetScopeProblem(issuingDistributionPoint, certificate) is { } scopeProblem)
		{
			return NotApplicable(scopeProblem);
		}

		DecodedExtension<IReadOnlyList<CrlDistributionPoint>> distributionPoints = certificate.DecodedExtensions.CrlDistributionPoints;

		if (distributionPoints.Error is not null)
		{
			return Invalid("The certificate's CRL distribution points extension does not decode.");
		}

		CrlReasonFlags coveredReasons = GetCoveredReasons(crl, issuingDistributionPoint, certificate, distributionPoints.Value);

		if (coveredReasons is CrlReasonFlags.None)
		{
			return NotApplicable("The CRL covers none of the reasons of the certificate's distribution points.") with { CoveredReasons = coveredReasons };
		}

		// RFC 5280, Sec. 6.3.3 (f), as RFC 10007, Sec. 4, amends it: only a version 3 certificate has extensions.
		if (issuer.Version is 3 && (issuer.KeyUsage is not { } keyUsage || (keyUsage & X509KeyUsageFlags.CrlSign) is 0))
		{
			return Invalid("The CRL's issuer does not have a key usage extension that asserts cRLSign.");
		}

		if (time < crl.ThisUpdate)
		{
			return Invalid("The CRL is not yet valid.");
		}

		// Sec. 5.1.2.5 leaves a CRL without nextUpdate to the application: without it, nothing bounds how old the CRL may be, so it is not used.
		if (crl.NextUpdate is not { } nextUpdate)
		{
			return Invalid("The CRL has no nextUpdate.");
		}

		if (time >= nextUpdate)
		{
			return Invalid("The CRL has expired.");
		}

		// Sec. 5.2.1: the key identifier must name the key of the issuer's certificate.
		if (extensions.AuthorityKeyIdentifier.Value?.KeyIdentifier is { } keyIdentifier && issuer.DecodedExtensions.SubjectKeyIdentifier.Value is { } subjectKeyIdentifier && !keyIdentifier.Span.SequenceEqual(subjectKeyIdentifier.Span))
		{
			return Invalid("The CRL's authority key identifier is not the issuer's subject key identifier.");
		}

		if (CertificatePolicy.CheckSignatureAlgorithm(crl.SignatureAlgorithm) is { } algorithmError)
		{
			return Invalid(algorithmError is CertificateValidationError.WeakAlgorithm ? $"The CRL is signed with {crl.SignatureAlgorithm.Oid}, which the policy refuses." : $"The CRL is signed with {crl.SignatureAlgorithm.Oid}, which is not supported.");
		}

		// Sec. 6.3.3 (g).
		if (!crl.VerifySignature(issuerKey, issuer.PublicKeyInfo.Encoded))
		{
			return Invalid("The CRL's signature does not verify with the issuer's key.");
		}

		// Sec. 6.3.3 (j).
		if (crl.TryGetEntry(certificate.SerialNumber.Span, out RevokedCertificate entry))
		{
			if (entry.ReasonCode is X509RevocationReason.RemoveFromCrl)
			{
				return Invalid("A complete CRL lists the certificate with the reason removeFromCRL, which only a delta CRL may use (Sec. 5.3.1).");
			}

			return new RevocationResult(RevocationStatus.Revoked)
			{
				Reason = entry.ReasonCode ?? X509RevocationReason.Unspecified,
				RevocationTime = entry.RevocationDate,
				CoveredReasons = coveredReasons
			};
		}

		// Sec. 6.3.3 (d) and (l): a CRL for some reasons alone says nothing about the others.
		if (coveredReasons is not AllReasons)
		{
			return NotApplicable("The CRL covers only some revocation reasons.") with { CoveredReasons = coveredReasons };
		}

		return new RevocationResult(RevocationStatus.Good) { CoveredReasons = coveredReasons };
	}

	// Checks a certificate against an OCSP response (RFC 6960, Sec. 3.2 and 4.2.2.2). issuer is the certificate's issuer; importPublicKey is the importer of TrustAnchorCertificateValidator.
	// The response's certificates are not trusted by themselves: a delegated responder must be issued directly by issuer, as Sec. 4.2.2.2 requires.
	public static RevocationResult CheckOcsp(OcspResponse response, Certificate certificate, Certificate issuer, Func<ReadOnlySpan<byte>, ISignatureKey> importPublicKey, DateTimeOffset time, int minRsaKeySize = 2048)
	{
		if (response.Status is not OcspResponseStatus.Successful)
		{
			return Invalid($"The responder answered {response.Status}.");
		}

		if (response.Responder is not { } responderId || response.SignatureAlgorithm is not { } signatureAlgorithm)
		{
			return Invalid($"The response has the type {response.ResponseType}, not id-pkix-ocsp-basic.");
		}

		if (FindUnrecognizedCriticalExtension(response.Extensions, single: false) is { } unrecognized)
		{
			return Invalid($"The response has the critical extension {unrecognized}, which the checker does not process.");
		}

		// Sec. 3.2, requirement 1. Of several responses for the certificate, the most severe stands.
		OcspSingleResponse? selected = FindSingleResponse(response, certificate, issuer);

		if (selected is null)
		{
			return Invalid("The response has no status for the certificate.");
		}

		if (FindUnrecognizedCriticalExtension(selected.Extensions, single: true) is { } unrecognizedSingle)
		{
			return Invalid($"The response for the certificate has the critical extension {unrecognizedSingle}, which the checker does not process.");
		}

		// Sec. 4.2.2.1, and RFC 9919, Sec. 5: thisUpdate at or before now and nextUpdate at or after now, within the skew. RFC 9919, Sec. 5, requires a client to reject a response without nextUpdate, as nothing else bounds its age.
		if (time + OcspClockSkew < selected.ThisUpdate)
		{
			return Invalid("The response is not yet valid.");
		}

		if (selected.NextUpdate is not { } nextUpdate)
		{
			return Invalid("The response has no nextUpdate.");
		}

		if (time - OcspClockSkew > nextUpdate)
		{
			return Invalid("The response has expired.");
		}

		if (CertificatePolicy.CheckSignatureAlgorithm(signatureAlgorithm) is { } algorithmError)
		{
			return Invalid(algorithmError is CertificateValidationError.WeakAlgorithm ? $"The response is signed with {signatureAlgorithm.Oid}, which the policy refuses." : $"The response is signed with {signatureAlgorithm.Oid}, which is not supported.");
		}

		using ISignatureKey? issuerKey = TrustAnchorCertificateValidator.ImportKey(importPublicKey, issuer.PublicKeyInfo, out _, out string? importMessage);

		if (issuerKey is null)
		{
			return Invalid($"The issuer's key cannot be imported: {importMessage}");
		}

		if (CheckSigner(response, responderId, issuer, issuerKey, importPublicKey, time, minRsaKeySize) is { } signerProblem)
		{
			return Invalid(signerProblem);
		}

		return selected.Status switch
		{
			OcspCertificateStatus.Good => new RevocationResult(RevocationStatus.Good) { NextUpdate = nextUpdate },
			OcspCertificateStatus.Unknown => new RevocationResult(RevocationStatus.Unknown) { NextUpdate = nextUpdate },
			_ => new RevocationResult(RevocationStatus.Revoked)
			{
				Reason = selected.RevocationReason ?? X509RevocationReason.Unspecified,
				RevocationTime = selected.RevocationTime,
				NextUpdate = nextUpdate
			}
		};
	}

	private static RevocationResult NotApplicable(string detail)
	{
		return new RevocationResult(RevocationStatus.NotApplicable, detail);
	}

	private static RevocationResult Invalid(string detail)
	{
		return new RevocationResult(RevocationStatus.Invalid, detail);
	}

	// The critical CRL extensions that the checker processes; nothing else may be critical (RFC 5280, Sec. 5.2). The CRL number, the freshest CRL and the authority information access extensions must not be critical (Secs. 5.2.3, 5.2.6 and 5.2.7), so a critical one is refused.
	private static string? FindUnrecognizedCriticalExtension(IReadOnlyList<CertificateExtension> extensions)
	{
		for (int i = 0; i < extensions.Count; ++i)
		{
			CertificateExtension extension = extensions[i];

			if (extension.Critical && extension.Oid is not (AuthorityKeyIdentifierOid or IssuerAlternativeNameOid or DeltaCrlIndicatorOid or IssuingDistributionPointOid))
			{
				return extension.Oid;
			}
		}

		return null;
	}

	// RFC 6960, Sec. 4.1.2: an extension may be critical if it is one that the checker understands, whose meaning is to inform; the others are refused.
	private static string? FindUnrecognizedCriticalExtension(IReadOnlyList<CertificateExtension> extensions, bool single)
	{
		for (int i = 0; i < extensions.Count; ++i)
		{
			CertificateExtension extension = extensions[i];

			if (!extension.Critical)
			{
				continue;
			}

			bool understood = single
				? extension.Oid is OcspCrlReferenceOid or OcspArchiveCutoffOid or ReasonCodeOid or InvalidityDateOid
				: extension.Oid is OcspRequest.NonceOid or OcspExtendedRevokeOid;

			if (!understood)
			{
				return extension.Oid;
			}
		}

		return null;
	}

	// RFC 5280, Sec. 6.3.3 (b)(2) (ii) to (iv), and the indirect CRLs that the checker does not support.
	private static string? GetScopeProblem(IssuingDistributionPoint? point, Certificate certificate)
	{
		if (point is null)
		{
			return null;
		}

		if (point.IndirectCrl)
		{
			return "The CRL is an indirect CRL, which the checker does not support.";
		}

		if (point.OnlyContainsAttributeCertificates)
		{
			return "The CRL covers only attribute certificates.";
		}

		bool certificateAuthority = certificate.DecodedExtensions.BasicConstraints.Value is { CertificateAuthority: true };

		if (point.OnlyContainsUserCertificates && certificateAuthority)
		{
			return "The CRL covers only end entity certificates.";
		}

		return point.OnlyContainsCACertificates && !certificateAuthority ? "The CRL covers only CA certificates." : null;
	}

	// The interim_reasons_mask of Sec. 6.3.3 (d): the reasons of the distribution points of the certificate whose names match the CRL's, and of the distribution point that the last paragraph of Sec. 6.3.3 assumes for a CRL not specified in one, named by the certificate's issuer. A distribution point with a cRLIssuer is for an indirect CRL, which is not supported.
	private static CrlReasonFlags GetCoveredReasons(CertificateRevocationList crl, IssuingDistributionPoint? point, Certificate certificate, IReadOnlyList<CrlDistributionPoint>? distributionPoints)
	{
		CrlReasonFlags onlySomeReasons = point?.OnlySomeReasons ?? AllReasons;

		if (point?.DistributionPoint is not { } name)
		{
			return onlySomeReasons & AllReasons;
		}

		IReadOnlyList<GeneralName> names = name.GetNames(crl.Issuer);
		CrlReasonFlags covered = CrlReasonFlags.None;

		if (distributionPoints is not null)
		{
			for (int i = 0; i < distributionPoints.Count; ++i)
			{
				CrlDistributionPoint distributionPoint = distributionPoints[i];

				if (distributionPoint.CrlIssuer is null && distributionPoint.DistributionPoint is { } pointName && NamesMatch(names, pointName.GetNames(certificate.Issuer)))
				{
					covered |= (distributionPoint.Reasons ?? AllReasons) & onlySomeReasons;
				}
			}
		}

		if (NamesMatch(names, GetIssuerNames(certificate)))
		{
			covered |= onlySomeReasons;
		}

		return covered & AllReasons;
	}

	// The certificate's issuer, as a directoryName, and the names of its issuer alternative name extension, if that decodes.
	private static IReadOnlyList<GeneralName> GetIssuerNames(Certificate certificate)
	{
		List<GeneralName> names = [new(GeneralNameType.DirectoryName, certificate.Issuer)];
		IReadOnlyList<CertificateExtension> extensions = certificate.Extensions;

		for (int i = 0; i < extensions.Count; ++i)
		{
			if (extensions[i].Oid is IssuerAlternativeNameOid)
			{
				try
				{
					DerReader reader = new(extensions[i].Value);
					GeneralName[] alternatives = GeneralName.ReadGeneralNames(ref reader);
					reader.ThrowIfNotEmpty();
					names.AddRange(alternatives);
				}
				catch (AsnContentException)
				{
				}

				break;
			}
		}

		return names;
	}

	private static bool NamesMatch(IReadOnlyList<GeneralName> first, IReadOnlyList<GeneralName> second)
	{
		for (int i = 0; i < first.Count; ++i)
		{
			for (int j = 0; j < second.Count; ++j)
			{
				if (first[i].Type == second[j].Type && first[i].Value.Span.SequenceEqual(second[j].Value.Span))
				{
					return true;
				}
			}
		}

		return false;
	}

	private static OcspSingleResponse? FindSingleResponse(OcspResponse response, Certificate certificate, Certificate issuer)
	{
		IReadOnlyList<OcspSingleResponse> responses = response.Responses;
		OcspSingleResponse? selected = null;

		for (int i = 0; i < responses.Count; ++i)
		{
			OcspSingleResponse candidate = responses[i];

			if (candidate.CertificateId.Matches(certificate, issuer) && (selected is null || Severity(candidate.Status) > Severity(selected.Status)))
			{
				selected = candidate;
			}
		}

		return selected;

		static int Severity(OcspCertificateStatus status)
		{
			return status switch
			{
				OcspCertificateStatus.Revoked => 2,
				OcspCertificateStatus.Unknown => 1,
				_ => 0
			};
		}
	}

	private static bool IsResponder(OcspResponderId responder, Certificate certificate)
	{
		if (responder.ByName is { } name)
		{
			return name.Span.SequenceEqual(certificate.Subject.Span);
		}

		Span<byte> digest = stackalloc byte[SHA1.HashSizeInBytes];
		SHA1.HashData(certificate.PublicKeyInfo.PublicKey.Span, digest);
		return responder.ByKey is { } key && key.Span.SequenceEqual(digest);
	}

	// RFC 6960, Sec. 4.2.2.2: the signer must be the CA that issued the certificate, or a certificate in the response that it issued directly, which holds id-kp-OCSPSigning.
	private static string? CheckSigner(OcspResponse response, OcspResponderId responderId, Certificate issuer, ISignatureKey issuerKey, Func<ReadOnlySpan<byte>, ISignatureKey> importPublicKey, DateTimeOffset time, int minRsaKeySize)
	{
		string? problem = null;

		if (IsResponder(responderId, issuer))
		{
			if (response.VerifySignature(issuerKey))
			{
				return null;
			}

			// A byName ResponderID does not tell the CA from a delegated responder that has its name.
			problem = "The response's signature does not verify with the issuer's key.";
		}

		int candidates = 0;
		IReadOnlyList<Certificate> certificates = response.Certificates;

		for (int i = 0; i < certificates.Count; ++i)
		{
			Certificate candidate = certificates[i];

			if (!IsResponder(responderId, candidate))
			{
				continue;
			}

			if (++candidates > MaxResponderCandidates)
			{
				return $"The response names more than {MaxResponderCandidates} certificates as its responder.";
			}

			if (CheckDelegatedResponder(response, candidate, issuer, issuerKey, importPublicKey, time, minRsaKeySize) is not { } candidateProblem)
			{
				return null;
			}

			problem ??= candidateProblem;
		}

		return problem ?? "The response's responder is neither the certificate's issuer nor a certificate in the response.";
	}

	private static string? CheckDelegatedResponder(OcspResponse response, Certificate candidate, Certificate issuer, ISignatureKey issuerKey, Func<ReadOnlySpan<byte>, ISignatureKey> importPublicKey, DateTimeOffset time, int minRsaKeySize)
	{
		if (!candidate.Issuer.Span.SequenceEqual(issuer.Subject.Span))
		{
			return "The responder's certificate is not issued by the CA that issued the certificate.";
		}

		if (time < candidate.NotBefore || time > candidate.NotAfter)
		{
			return "The responder's certificate is not valid at the time.";
		}

		DecodedExtensions decoded = candidate.DecodedExtensions;

		if (decoded.BasicConstraints.Error is not null || decoded.ExtendedKeyUsage.Error is not null || decoded.SubjectAlternativeName.Error is not null || decoded.NameConstraints.Error is not null || decoded.AuthorityKeyIdentifier.Error is not null || decoded.SubjectKeyIdentifier.Error is not null || decoded.OcspNoCheck.Error is not null || decoded.NoRevocationAvailable.Error is not null)
		{
			return "The responder's certificate has an extension that does not decode.";
		}

		if (decoded.FindNoRevocationAvailableProblem() is { } problem)
		{
			return $"The responder's certificate {problem}.";
		}

		if (decoded.ExtendedKeyUsage.Value is null || !decoded.ExtendedKeyUsage.Value.Contains(OcspSigningOid))
		{
			return "The responder's certificate does not assert id-kp-OCSPSigning.";
		}

		if (candidate.KeyUsage is { } keyUsage && (keyUsage & X509KeyUsageFlags.DigitalSignature) is 0)
		{
			return "The key usage extension of the responder's certificate does not assert digitalSignature.";
		}

		IReadOnlyList<CertificateExtension> extensions = candidate.Extensions;

		for (int i = 0; i < extensions.Count; ++i)
		{
			if (extensions[i].Critical && extensions[i].Oid is not (BasicConstraintsOid or KeyUsageOid or ExtendedKeyUsageOid or SubjectAlternativeNameOid or OcspNoCheckOid))
			{
				return $"The responder's certificate has the critical extension {extensions[i].Oid}, which the checker does not process.";
			}
		}

		if (CertificatePolicy.CheckSignatureAlgorithm(candidate.SignatureAlgorithm) is not null)
		{
			return $"The responder's certificate is signed with {candidate.SignatureAlgorithm.Oid}, which the policy refuses or does not support.";
		}

		if (CertificatePolicy.CheckPublicKey(candidate.PublicKeyInfo, minRsaKeySize, out string? reason) is not null)
		{
			return $"The responder's certificate {reason}.";
		}

		using ISignatureKey? candidateKey = TrustAnchorCertificateValidator.ImportKey(importPublicKey, candidate.PublicKeyInfo, out _, out string? importMessage);

		if (candidateKey is null)
		{
			return $"The responder's key cannot be imported: {importMessage}";
		}

		if (!response.VerifySignature(candidateKey))
		{
			return "The response's signature does not verify with the responder's key.";
		}

		return candidate.VerifySignature(issuerKey) ? null : "The responder's certificate's signature does not verify with the issuer's key.";
	}
}
