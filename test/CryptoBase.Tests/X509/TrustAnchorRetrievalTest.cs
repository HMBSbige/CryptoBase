using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures;
using CryptoBase.X509;
using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using static CryptoBase.Tests.TestUtils;
using static CryptoBase.Tests.X509.TestPki;
using static CryptoBase.Tests.X509.TrustAnchorCertificateValidatorTest;
using static CryptoBase.Tests.X509.X509TestUtils;

namespace CryptoBase.Tests.X509;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class TrustAnchorRetrievalTest
{
	private const string IssuerUri = "http://ca.test/issuer.cer";
	private const string OcspUri = "http://ocsp.test/";
	private const string CrlUri = "http://crl.test/ca.crl";
	private const string NoRevAvailOid = "2.5.29.56";
	private const string OcspNoCheckOid = "1.3.6.1.5.5.7.48.1.5";
	private const string CrlDistributionPointsOid = "2.5.29.31";
	private const string FreshestCrlOid = "2.5.29.46";
	private const string AiaOid = "1.3.6.1.5.5.7.1.1";
	private const string Sha1Oid = "1.3.14.3.2.26";
	private const string Sha256Oid = "2.16.840.1.101.3.4.2.1";

	private static readonly byte[] OnlyKeyCompromise = Tlv(0x83, [0x06, 0x40]);
	private static readonly byte[] EveryOtherReason = Tlv(0x83, [0x07, 0x3F, 0x80]);

	private static CertificateExtension Aia(string[]? caIssuers = null, string[]? ocsp = null, bool critical = false)
	{
		byte[][] descriptions = [.. (ocsp ?? []).Select(static uri => Sequence(Oid("1.3.6.1.5.5.7.48.1"), UniformResourceIdentifier(uri))), .. (caIssuers ?? []).Select(static uri => Sequence(Oid("1.3.6.1.5.5.7.48.2"), UniformResourceIdentifier(uri)))];
		return new CertificateExtension("1.3.6.1.5.5.7.1.1", critical, Sequence(descriptions));
	}

	private static CertificateExtension Cdp(params string[] uris)
	{
		return TestCrl.DistributionPoints([.. uris.Select(static uri => Sequence(TestCrl.FullName(0xA0, UniformResourceIdentifier(uri))))]);
	}

	private static CertificateExtension NullExtension(string oid, bool critical = false)
	{
		return new CertificateExtension(oid, critical, TestCrl.NullValue);
	}

	private static TrustAnchorCertificateValidator Checking(X509RevocationMode mode, FakeRetriever retriever, params Certificate[] anchors)
	{
		return new TrustAnchorCertificateValidator(anchors, SignatureKey.ImportSubjectPublicKeyInfo)
		{
			Retriever = retriever,
			RevocationMode = mode
		};
	}

	private static byte[] Ocsp(Certificate certificate, Authority issuer, byte[] status, DateTimeOffset? nextUpdate = null, byte[]? certificateId = null)
	{
		return new TestOcsp.Basic
		{
			ResponderId = TestOcsp.ResponderByKey(issuer.Certificate),
			Responses =
			[
				new TestOcsp.SingleEntry
				{
					CertificateId = certificateId ?? TestOcsp.CertificateIdOf(certificate, issuer.Certificate),
					Status = status,
					NextUpdate = Time(nextUpdate ?? Now.AddHours(1), generalized: true)
				}.Encode()
			]
		}.Encode(issuer.Key);
	}

	private static byte[] OcspSha256(Certificate certificate, Authority issuer, byte[] status, DateTimeOffset? nextUpdate = null)
	{
		return Ocsp(certificate, issuer, status, nextUpdate, TestOcsp.Sha256CertificateIdOf(certificate, issuer.Certificate));
	}

	// The hash algorithm of the CertID of an OCSP request, decoded from what was sent: OCSPRequest, TBSRequest, requestList, Request, CertID.
	private static string CertIdHashOf(FakeRetriever.Request request)
	{
		byte[] encoded = request.Content ?? Convert.FromBase64String(Uri.UnescapeDataString(request.Uri.Segments[^1]));
		AsnReader certificateId = new AsnReader(encoded, AsnEncodingRules.DER).ReadSequence().ReadSequence().ReadSequence().ReadSequence().ReadSequence();
		return certificateId.ReadSequence().ReadObjectIdentifier();
	}

	private static byte[] EncodeCrl(Authority authority, params Certificate[] revoked)
	{
		return TestCrl.Conforming(authority, revoked.Length is 0 ? null : [.. revoked.Select(static certificate => TestCrl.Entry(TestCrl.SerialNumberOf(certificate)))]).Encode(authority);
	}

	private static CertificateRevocationList DecodeCrl(Authority authority, params Certificate[] revoked)
	{
		return CertificateRevocationList.Decode(EncodeCrl(authority, revoked));
	}

	// A certs-only SignedData (RFC 5652, Sec. 5.1) with the elements of its certificates field.
	private static byte[] CertsOnly(params byte[][] elements)
	{
		return Sequence(Oid("1.2.840.113549.1.7.2"), Tlv(0xA0, Sequence([0x02, 0x01, 0x01], Tlv(0x31), Sequence(Oid("1.2.840.113549.1.7.1")), Tlv(0xA0, elements), Tlv(0x31))));
	}

	// The same message in BER, every constructed value but the certificates of indefinite length.
	private static byte[] CertsOnlyIndefinite(params byte[][] elements)
	{
		return Indefinite(0x30, Oid("1.2.840.113549.1.7.2"), Indefinite(0xA0, Indefinite(0x30, [0x02, 0x01, 0x01], Indefinite(0x31), Indefinite(0x30, Oid("1.2.840.113549.1.7.1")), Indefinite(0xA0, elements), Indefinite(0x31))));

		static byte[] Indefinite(byte tag, params byte[][] contents)
		{
			return [tag, 0x80, .. contents.SelectMany(static content => content), 0x00, 0x00];
		}
	}

	private static byte[] Encoded(Certificate certificate)
	{
		return certificate.Encoded.ToArray();
	}

	private static async Task<CertificateValidationResult> Validate(TrustAnchorCertificateValidator validator, TimeProvider? clock = null, DateTimeOffset? deadline = null, string? hostName = null, CancellationToken cancellationToken = default, params Certificate[] presented)
	{
		return await validator.ValidateAsync
		(
			new CertificateValidationContext(presented, CertificateUsage.ServerAuthentication)
			{
				HostName = hostName,
				TimeProvider = clock ?? new FixedTimeProvider(Now),
				Deadline = deadline
			}, cancellationToken
		);
	}

	private static TrustAnchorCertificateValidator Online(FakeRetriever retriever, params Certificate[] anchors)
	{
		return new TrustAnchorCertificateValidator(anchors, SignatureKey.ImportSubjectPublicKeyInfo)
		{
			Retriever = retriever,
			RevocationMode = X509RevocationMode.Online
		};
	}

	private static TrustAnchorCertificateValidator WithRetriever(FakeRetriever retriever, params Certificate[] anchors)
	{
		return new TrustAnchorCertificateValidator(anchors, SignatureKey.ImportSubjectPublicKeyInfo) { Retriever = retriever };
	}

	[Test]
	public async Task RetrievesAMissingIssuerAsADerCertificate()
	{
		using Authority root = Authority.CreateRoot();
		using Authority intermediate = root.CreateIntermediate();
		Certificate leaf = intermediate.IssueLeaf(more: [Aia(caIssuers: [IssuerUri])]);
		FakeRetriever retriever = new() { [IssuerUri] = Encoded(intermediate.Certificate) };
		using TrustAnchorCertificateValidator validator = WithRetriever(retriever, root.Certificate);

		CertificateValidationResult result = await Validate(validator, presented: [leaf]);

		using (Assert.Multiple())
		{
			await AssertValid(result, leaf, intermediate.Certificate, root.Certificate);
			await Assert.That(retriever.Requests.Single().Uri.AbsoluteUri).IsEqualTo(IssuerUri);
			await Assert.That(retriever.Requests.Single().MaxLength).IsEqualTo(RetrievalBudget.MaxCertificateLength);
		}
	}

	[Test]
	public async Task RetrievesAMissingIssuerFromACertsOnlyMessage()
	{
		using Authority root = Authority.CreateRoot();
		using Authority intermediate = root.CreateIntermediate();
		Certificate leaf = intermediate.IssueLeaf(more: [Aia(caIssuers: [IssuerUri])]);

		foreach (byte[] message in (byte[][])[CertsOnly(Encoded(root.CreateIntermediate("CN=Other").Certificate), Encoded(intermediate.Certificate)), CertsOnlyIndefinite(Encoded(intermediate.Certificate))])
		{
			FakeRetriever retriever = new() { [IssuerUri] = message };
			using TrustAnchorCertificateValidator validator = WithRetriever(retriever, root.Certificate);

			await AssertValid(await Validate(validator, presented: [leaf]), leaf, intermediate.Certificate, root.Certificate);
		}
	}

	[Test]
	public async Task FollowsIssuersOverSeveralRounds()
	{
		using Authority root = Authority.CreateRoot();
		using Authority upper = root.CreateIntermediate("CN=Upper");
		using Authority lower = upper.CreateIntermediate("CN=Lower", more: [Aia(caIssuers: ["http://ca.test/upper.cer"])]);
		Certificate leaf = lower.IssueLeaf(more: [Aia(caIssuers: ["http://ca.test/lower.cer"])]);
		FakeRetriever retriever = new()
		{
			["http://ca.test/lower.cer"] = Encoded(lower.Certificate),
			["http://ca.test/upper.cer"] = Encoded(upper.Certificate)
		};
		using TrustAnchorCertificateValidator validator = WithRetriever(retriever, root.Certificate);

		await AssertValid(await Validate(validator, presented: [leaf]), leaf, lower.Certificate, upper.Certificate, root.Certificate);
	}

	[Test]
	public async Task AFailedRetrievalLeavesTheIssuerMissing()
	{
		using Authority root = Authority.CreateRoot();
		using Authority intermediate = root.CreateIntermediate();
		Certificate leaf = intermediate.IssueLeaf(more: [Aia(caIssuers: [IssuerUri])]);

		foreach (byte[] body in (byte[][])[[], [0x30, 0x03, 0x01], CertsOnly(), Tlv(0x30, Oid("1.2.840.113549.1.7.1"))])
		{
			FakeRetriever retriever = new() { [IssuerUri] = body };
			using TrustAnchorCertificateValidator validator = WithRetriever(retriever, root.Certificate);

			await AssertInvalid(await Validate(validator, presented: [leaf]), [CertificateValidationError.UntrustedRoot], CertificatePathEnd.MissingIssuer, leaf);
		}
	}

	[Test]
	public async Task TriesTheNextUriAfterOneThatFails()
	{
		using Authority root = Authority.CreateRoot();
		using Authority intermediate = root.CreateIntermediate();
		Certificate leaf = intermediate.IssueLeaf(more: [Aia(caIssuers: ["http://ca.test/gone.cer", IssuerUri])]);
		FakeRetriever retriever = new() { [IssuerUri] = Encoded(intermediate.Certificate) };
		using TrustAnchorCertificateValidator validator = WithRetriever(retriever, root.Certificate);

		await AssertValid(await Validate(validator, presented: [leaf]), leaf, intermediate.Certificate, root.Certificate);
	}

	// A retrieved certificate is held to what a presented one is.
	[Test]
	public async Task RetrievedCertificatesPassEveryCheck()
	{
		using Authority root = Authority.CreateRoot();
		using Authority expired = root.CreateIntermediate(notBefore: Now.AddDays(-2), notAfter: Now.AddDays(-1));
		Certificate leaf = expired.IssueLeaf(more: [Aia(caIssuers: [IssuerUri])]);
		FakeRetriever retriever = new() { [IssuerUri] = Encoded(expired.Certificate) };
		using TrustAnchorCertificateValidator validator = WithRetriever(retriever, root.Certificate);

		await AssertInvalid(await Validate(validator, presented: [leaf]), [CertificateValidationError.Expired], CertificatePathEnd.TrustAnchor, leaf, expired.Certificate, root.Certificate);
	}

	// The presented issuer fails a check, so that the retrieved one is what makes the path valid.
	[Test]
	public async Task ARetrievedIssuerReplacesOneThatFails()
	{
		using Authority root = Authority.CreateRoot();
		using Authority intermediate = root.CreateIntermediate();
		byte[] subjectPublicKeyInfo = intermediate.Certificate.PublicKeyInfo.Encoded.ToArray();
		Certificate expired = root.Issue
		(
			new Template
			{
				Subject = intermediate.Name,
				SubjectPublicKeyInfo = subjectPublicKeyInfo,
				NotBefore = Now.AddDays(-3),
				NotAfter = Now.AddDays(-2),
				Extensions = [.. CaExtensions(subjectPublicKeyInfo), AuthorityKeyIdentifier(root.KeyIdentifier)]
			}
		);
		Certificate leaf = intermediate.IssueLeaf(more: [Aia(caIssuers: [IssuerUri])]);
		FakeRetriever retriever = new() { [IssuerUri] = Encoded(intermediate.Certificate) };
		using TrustAnchorCertificateValidator validator = WithRetriever(retriever, root.Certificate);

		await AssertValid(await Validate(validator, presented: [leaf, expired]), leaf, intermediate.Certificate, root.Certificate);
	}

	[Test]
	public async Task RetrievesNothingWithoutARetrieverOrWithDownloadsDisabled()
	{
		using Authority root = Authority.CreateRoot();
		using Authority intermediate = root.CreateIntermediate();
		Certificate leaf = intermediate.IssueLeaf(more: [Aia(caIssuers: [IssuerUri])]);
		FakeRetriever retriever = new() { [IssuerUri] = Encoded(intermediate.Certificate) };
		using TrustAnchorCertificateValidator none = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo);
		using TrustAnchorCertificateValidator disabled = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo)
		{
			Retriever = retriever,
			DisableCertificateDownloads = true
		};

		ValueTask<CertificateValidationResult> synchronous = none.ValidateAsync(new CertificateValidationContext([leaf], CertificateUsage.ServerAuthentication) { TimeProvider = new FixedTimeProvider(Now) });

		using (Assert.Multiple())
		{
			await Assert.That(synchronous.IsCompletedSuccessfully).IsTrue();
			await AssertInvalid(await synchronous, [CertificateValidationError.UntrustedRoot], CertificatePathEnd.MissingIssuer, leaf);
			await AssertInvalid(await Validate(disabled, presented: [leaf]), [CertificateValidationError.UntrustedRoot], CertificatePathEnd.MissingIssuer, leaf);
			await Assert.That(retriever.Requests).IsEmpty();
		}
	}

	[Test]
	public async Task RetrievesOnlyOverHttp()
	{
		using Authority root = Authority.CreateRoot();
		using Authority intermediate = root.CreateIntermediate();
		Certificate leaf = intermediate.IssueLeaf(more: [Aia(caIssuers: ["ldap://ca.test/cn=ca", "ftp://ca.test/ca.cer", "not a uri"])]);
		FakeRetriever retriever = new();
		using TrustAnchorCertificateValidator validator = WithRetriever(retriever, root.Certificate);

		await AssertInvalid(await Validate(validator, presented: [leaf]), [CertificateValidationError.UntrustedRoot], CertificatePathEnd.MissingIssuer, leaf);
		await Assert.That(retriever.Requests).IsEmpty();
	}

	// Two certificates that end paths name one URI, retrieved once; a validation that follows reuses what a path used.
	[Test]
	public async Task RetrievesEachUriOnceAndKeepsTheIssuersThatAPathUsed()
	{
		using Authority root = Authority.CreateRoot();
		using Authority intermediate = root.CreateIntermediate();
		Certificate leaf = intermediate.IssueLeaf(more: [Aia(caIssuers: [IssuerUri, IssuerUri])]);
		FakeRetriever retriever = new() { [IssuerUri] = Encoded(intermediate.Certificate) };
		using TrustAnchorCertificateValidator validator = WithRetriever(retriever, root.Certificate);
		MovingClock clock = new();

		using (Assert.Multiple())
		{
			await AssertValid(await Validate(validator, clock, presented: [leaf]), leaf, intermediate.Certificate, root.Certificate);
			await Assert.That(retriever.Requests.Count).IsEqualTo(1);
			await AssertValid(await Validate(validator, clock, presented: [leaf]), leaf, intermediate.Certificate, root.Certificate);
			await Assert.That(retriever.Requests.Count).IsEqualTo(1);

			clock.Time = Now.AddHours(2);
			await AssertValid(await Validate(validator, clock, presented: [leaf]), leaf, intermediate.Certificate, root.Certificate);
			await Assert.That(retriever.Requests.Count).IsEqualTo(2);
		}
	}

	// A validation less than the lifetime of a kept issuer before the last time that DateTimeOffset holds keeps it until that time, rather than failing a path that it found.
	[Test]
	public async Task KeepsAnIssuerAtTheEndOfTime()
	{
		DateTimeOffset last = new(9999, 12, 31, 23, 59, 59, TimeSpan.Zero);
		using Authority root = Authority.CreateRoot(notAfter: last);
		using Authority intermediate = root.CreateIntermediate(notAfter: last);
		Certificate leaf = intermediate.IssueLeaf(notAfter: last, more: [Aia(caIssuers: [IssuerUri])]);
		FakeRetriever retriever = new() { [IssuerUri] = Encoded(intermediate.Certificate) };
		using TrustAnchorCertificateValidator validator = WithRetriever(retriever, root.Certificate);
		FixedTimeProvider clock = new(DateTimeOffset.MaxValue);

		using (Assert.Multiple())
		{
			await AssertValid(await Validate(validator, clock, presented: [leaf]), leaf, intermediate.Certificate, root.Certificate);
			await AssertValid(await Validate(validator, clock, presented: [leaf]), leaf, intermediate.Certificate, root.Certificate);
			await Assert.That(retriever.Requests.Count).IsEqualTo(1);
		}
	}

	// Certificates that no path used are not kept, as the peer chooses their URIs.
	[Test]
	public async Task DoesNotKeepIssuersThatNoPathUsed()
	{
		using Authority root = Authority.CreateRoot();
		using Authority other = Authority.CreateRoot("CN=Other");
		using Authority intermediate = root.CreateIntermediate();
		Certificate leaf = intermediate.IssueLeaf(more: [Aia(caIssuers: [IssuerUri])]);
		FakeRetriever retriever = new() { [IssuerUri] = Encoded(other.Certificate) };
		using TrustAnchorCertificateValidator validator = WithRetriever(retriever, root.Certificate);

		for (int i = 0; i < 2; ++i)
		{
			await Validate(validator, presented: [leaf]);
		}

		await Assert.That(retriever.Requests.Count).IsEqualTo(2);
	}

	// Nothing retrieved could make acceptable a certificate that fails by itself.
	[Test]
	public async Task RetrievesNothingForACertificateThatFailsByItself()
	{
		using Authority root = Authority.CreateRoot();
		using Authority intermediate = root.CreateIntermediate();
		Certificate expired = intermediate.IssueLeaf(notBefore: Now.AddDays(-2), notAfter: Now.AddDays(-1), more: [Aia(caIssuers: [IssuerUri], ocsp: [OcspUri])]);
		Certificate leaf = intermediate.IssueLeaf(more: [Aia(caIssuers: [IssuerUri], ocsp: [OcspUri])]);
		FakeRetriever retriever = new() { [IssuerUri] = Encoded(intermediate.Certificate) };
		using TrustAnchorCertificateValidator validator = Online(retriever, root.Certificate);

		await AssertInvalid(await Validate(validator, presented: [expired, intermediate.Certificate]), [CertificateValidationError.Expired], CertificatePathEnd.TrustAnchor, expired, intermediate.Certificate, root.Certificate);
		await AssertInvalid(await Validate(validator, presented: [expired]), [CertificateValidationError.Expired, CertificateValidationError.UntrustedRoot], CertificatePathEnd.MissingIssuer, expired);
		await AssertInvalid(await Validate(validator, hostName: "other.test", presented: [leaf, intermediate.Certificate]), [CertificateValidationError.NameMismatch], CertificatePathEnd.TrustAnchor, leaf, intermediate.Certificate, root.Certificate);
		await Assert.That(retriever.Requests).IsEmpty();
	}

	// The certificate at which the search ended comes first, and a certificate whose issuer the search found once it adds nothing. The longest path that the validator allows keeps nothing from being retrieved, as a self-issued issuer would still fit, and the checks of the path decide.
	[Test]
	public async Task RetrievesWhereAnIssuerIsMissingFirst()
	{
		using Authority root = Authority.CreateRoot();
		using Authority upper = root.CreateIntermediate("CN=Upper");
		using Authority lower = upper.CreateIntermediate("CN=Lower", more: [Aia(caIssuers: ["http://ca.test/upper.cer"])]);
		Certificate leaf = lower.IssueLeaf(more: [Aia(caIssuers: ["http://ca.test/lower.cer"])]);
		FakeRetriever retriever = new();
		using TrustAnchorCertificateValidator validator = WithRetriever(retriever, root.Certificate);
		FakeRetriever limitedRetriever = new();
		using TrustAnchorCertificateValidator limited = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo)
		{
			Retriever = limitedRetriever,
			MaxPathLength = 0
		};

		await AssertInvalid(await Validate(validator, presented: [leaf, lower.Certificate]), [CertificateValidationError.UntrustedRoot], CertificatePathEnd.MissingIssuer, leaf, lower.Certificate);
		await AssertInvalid(await Validate(limited, presented: [leaf, lower.Certificate]), [CertificateValidationError.UntrustedRoot, CertificateValidationError.NotValidForUsage], CertificatePathEnd.MissingIssuer, leaf, lower.Certificate);

		using (Assert.Multiple())
		{
			await Assert.That(retriever.Requests.Select(static request => request.Uri.AbsoluteUri)).IsEquivalentTo((string[])["http://ca.test/upper.cer", "http://ca.test/lower.cer"], CollectionOrdering.Matching);
			await Assert.That(limitedRetriever.Requests.Select(static request => request.Uri.AbsoluteUri)).IsEquivalentTo((string[])["http://ca.test/lower.cer", "http://ca.test/upper.cer"], CollectionOrdering.Matching);
		}
	}

	// A presented issuer that passes every check and leads nowhere leaves no certificate without an issuer to retrieve; the peer's own URI has the one under the trust anchor.
	[Test]
	public async Task RetrievesTheIssuerOfThePeerWhenAPresentedIssuerLeadsNowhere()
	{
		using Authority trusted = Authority.CreateRoot("CN=Trusted");
		using Authority untrusted = Authority.CreateRoot("CN=Untrusted");
		using Authority intermediate = trusted.CreateIntermediate();
		byte[] subjectPublicKeyInfo = intermediate.Certificate.PublicKeyInfo.Encoded.ToArray();
		Certificate cross = untrusted.Issue
		(
			new Template
			{
				Subject = intermediate.Name,
				SubjectPublicKeyInfo = subjectPublicKeyInfo,
				Extensions = [.. CaExtensions(subjectPublicKeyInfo), AuthorityKeyIdentifier(untrusted.KeyIdentifier)]
			}
		);
		Certificate leaf = intermediate.IssueLeaf(more: [Aia(caIssuers: [IssuerUri])]);
		FakeRetriever retriever = new() { [IssuerUri] = Encoded(intermediate.Certificate) };
		using TrustAnchorCertificateValidator validator = WithRetriever(retriever, trusted.Certificate);

		await AssertValid(await Validate(validator, presented: [leaf, cross]), leaf, intermediate.Certificate, trusted.Certificate);
		await Assert.That(retriever.Requests.Count).IsEqualTo(1);
	}

	// The URI of a presented issuer that leads nowhere fails, which leaves the pool as it was: the peer's own URI still has the one under the trust anchor.
	[Test]
	public async Task AFailedRetrievalForAPresentedIssuerDoesNotHideTheUriOfThePeer()
	{
		const string gone = "http://ca.test/gone.cer";
		using Authority trusted = Authority.CreateRoot("CN=Trusted");
		using Authority untrusted = Authority.CreateRoot("CN=Untrusted");
		using Authority intermediate = trusted.CreateIntermediate();
		byte[] subjectPublicKeyInfo = intermediate.Certificate.PublicKeyInfo.Encoded.ToArray();
		Certificate cross = untrusted.Issue
		(
			new Template
			{
				Subject = intermediate.Name,
				SubjectPublicKeyInfo = subjectPublicKeyInfo,
				Extensions = [.. CaExtensions(subjectPublicKeyInfo), AuthorityKeyIdentifier(untrusted.KeyIdentifier), Aia(caIssuers: [gone])]
			}
		);
		Certificate leaf = intermediate.IssueLeaf(more: [Aia(caIssuers: [IssuerUri])]);
		FakeRetriever retriever = new() { [IssuerUri] = Encoded(intermediate.Certificate) };
		using TrustAnchorCertificateValidator validator = WithRetriever(retriever, trusted.Certificate);

		await AssertValid(await Validate(validator, presented: [leaf, cross]), leaf, intermediate.Certificate, trusted.Certificate);
		await Assert.That(retriever.Requests.Select(static request => request.Uri.AbsoluteUri)).IsEquivalentTo((string[])[gone, IssuerUri], CollectionOrdering.Matching);
	}

	// MaxPathLength bounds the intermediate certificates that are not self-issued, so that a validator with no room for one still finds the certificate of a new key of its trust anchor.
	[Test]
	public async Task RetrievesASelfIssuedIssuerWithNoRoomForIntermediates()
	{
		using Authority root = Authority.CreateRoot();
		using Authority rollover = root.CreateIntermediate("CN=Root");
		Certificate leaf = rollover.IssueLeaf(more: [Aia(caIssuers: [IssuerUri])]);
		FakeRetriever retriever = new() { [IssuerUri] = Encoded(rollover.Certificate) };
		using TrustAnchorCertificateValidator validator = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo)
		{
			Retriever = retriever,
			MaxPathLength = 0
		};

		await AssertValid(await Validate(validator, presented: [leaf]), leaf, rollover.Certificate, root.Certificate);
		await Assert.That(retriever.Requests.Count).IsEqualTo(1);
	}

	// A path can reach a trust anchor and fail as a whole, on its policies, with no certificate left without an issuer: the peer's URI still names one that passes.
	[Test]
	public async Task RetrievesAnIssuerWhenAPresentedPathFailsItsPolicies()
	{
		const string wanted = "1.3.6.1.4.1.55738.77.1";
		const string other = "1.3.6.1.4.1.55738.77.2";
		using Authority root = Authority.CreateRoot();
		using Authority intermediate = root.CreateIntermediate(more: [CertificatePolicies(other)]);
		byte[] subjectPublicKeyInfo = intermediate.Certificate.PublicKeyInfo.Encoded.ToArray();
		Certificate conforming = root.Issue
		(
			new Template
			{
				Subject = intermediate.Name,
				SubjectPublicKeyInfo = subjectPublicKeyInfo,
				Extensions = [.. CaExtensions(subjectPublicKeyInfo), AuthorityKeyIdentifier(root.KeyIdentifier), CertificatePolicies(wanted)]
			}
		);
		Certificate leaf = intermediate.IssueLeaf(more: [CertificatePolicies(wanted), Aia(caIssuers: [IssuerUri])]);
		FakeRetriever retriever = new() { [IssuerUri] = Encoded(conforming) };
		using TrustAnchorCertificateValidator validator = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo)
		{
			Retriever = retriever,
			RequireExplicitPolicy = true,
			InitialPolicies = [wanted]
		};

		await AssertValid(await Validate(validator, presented: [leaf, intermediate.Certificate]), leaf, conforming, root.Certificate);
		await Assert.That(retriever.Requests.Count).IsEqualTo(1);
	}

	// Beyond the certificates without an issuer, each known certificate names its URIs once, and a search that nothing helps ends.
	[Test]
	public async Task RetrievesTheOtherKnownCertificatesOnce()
	{
		using Authority trusted = Authority.CreateRoot("CN=Trusted");
		using Authority untrusted = Authority.CreateRoot("CN=Untrusted");
		using Authority intermediate = trusted.CreateIntermediate(more: [Aia(caIssuers: ["http://ca.test/intermediate.cer"])]);
		byte[] subjectPublicKeyInfo = intermediate.Certificate.PublicKeyInfo.Encoded.ToArray();
		Certificate cross = untrusted.Issue
		(
			new Template
			{
				Subject = intermediate.Name,
				SubjectPublicKeyInfo = subjectPublicKeyInfo,
				Extensions = [.. CaExtensions(subjectPublicKeyInfo), AuthorityKeyIdentifier(untrusted.KeyIdentifier)]
			}
		);
		Certificate leaf = intermediate.IssueLeaf(more: [Aia(caIssuers: [IssuerUri])]);
		FakeRetriever retriever = new();
		using TrustAnchorCertificateValidator validator = WithRetriever(retriever, trusted.Certificate);

		await AssertInvalid(await Validate(validator, presented: [leaf, cross]), [CertificateValidationError.UntrustedRoot], CertificatePathEnd.MissingIssuer, leaf, cross);
		await Assert.That(retriever.Requests.Select(static request => request.Uri.AbsoluteUri)).IsEquivalentTo((string[])[IssuerUri]);
	}

	[Test]
	public async Task RetrievesNothingForASelfSignedCertificate()
	{
		byte[] subjectPublicKeyInfo;
		using CryptoBase.Signatures.Ecdsa.EcdsaP256 key = CryptoBase.Signatures.Ecdsa.EcdsaP256.GenerateKey();
		subjectPublicKeyInfo = Signatures.SignatureTestUtils.ExportSubjectPublicKeyInfo(key);
		byte[] subject = Name("CN=Self");
		Certificate selfSigned = Sign
		(
			new Template
			{
				Subject = subject,
				SubjectPublicKeyInfo = subjectPublicKeyInfo,
				Extensions = [Aia(caIssuers: [IssuerUri])]
			}, subject, key, SignatureAlgorithm.EcdsaSha256
		);
		using Authority root = Authority.CreateRoot();
		FakeRetriever retriever = new();
		using TrustAnchorCertificateValidator validator = WithRetriever(retriever, root.Certificate);

		// The same, with the issuer encoded in another string type and case, which RFC 5280, Sec. 7.1, takes for the same name.
		Certificate reencoded = Sign
		(
			new Template
			{
				Subject = CommonName(PrintableStringTag, "Self"),
				SubjectPublicKeyInfo = subjectPublicKeyInfo,
				Extensions = [Aia(caIssuers: [IssuerUri])]
			}, CommonName(Utf8StringTag, "SELF"), key, SignatureAlgorithm.EcdsaSha256
		);

		await AssertInvalid(await Validate(validator, presented: [selfSigned]), [CertificateValidationError.UntrustedRoot], CertificatePathEnd.UntrustedRoot, selfSigned);
		await AssertInvalid(await Validate(validator, presented: [reencoded]), [CertificateValidationError.UntrustedRoot], CertificatePathEnd.UntrustedRoot, reencoded);
		await Assert.That(retriever.Requests).IsEmpty();
	}

	[Test]
	public async Task StopsRetrievingIssuersAtTheLimitOfRounds()
	{
		using Authority root = Authority.CreateRoot();
		List<Authority> chain = [root];
		FakeRetriever retriever = new();

		for (int i = 0; i < 10; ++i)
		{
			Authority next = chain[^1].CreateIntermediate($"CN=I{i}", more: [Aia(caIssuers: [$"http://ca.test/{i - 1}.cer"])]);
			chain.Add(next);
			retriever[$"http://ca.test/{i}.cer"] = Encoded(next.Certificate);
		}

		Certificate leaf = chain[^1].IssueLeaf(more: [Aia(caIssuers: ["http://ca.test/9.cer"])]);
		using TrustAnchorCertificateValidator validator = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo)
		{
			Retriever = retriever,
			MaxPathLength = 20
		};

		CertificateValidationResult result = await Validate(validator, presented: [leaf]);

		foreach (Authority authority in chain)
		{
			authority.Dispose();
		}

		using (Assert.Multiple())
		{
			await Assert.That(result.Errors).IsEquivalentTo((CertificateValidationError[])[CertificateValidationError.UntrustedRoot, CertificateValidationError.Unspecified], CollectionOrdering.Matching).Because($"{result.Message}");
			await Assert.That(result.PathEnd).IsEqualTo(CertificatePathEnd.MissingIssuer);
			await Assert.That(retriever.Requests.Count).IsEqualTo(RetrievalBudget.MaxIssuerRounds);
			await Assert.That(result.Message).Contains("rounds of retrieving issuers");
		}
	}

	[Test]
	public async Task StopsRetrievingAtTheLimitOfRetrievals()
	{
		using Authority root = Authority.CreateRoot();
		using Authority intermediate = root.CreateIntermediate();
		Certificate leaf = intermediate.IssueLeaf(more: [Aia(caIssuers: [.. Enumerable.Range(0, RetrievalBudget.MaxRetrievals + 5).Select(static i => $"http://ca.test/{i}.cer")])]);
		FakeRetriever retriever = new();
		using TrustAnchorCertificateValidator validator = WithRetriever(retriever, root.Certificate);

		CertificateValidationResult result = await Validate(validator, presented: [leaf]);

		using (Assert.Multiple())
		{
			await Assert.That(retriever.Requests.Count).IsEqualTo(RetrievalBudget.MaxRetrievals);
			await Assert.That(result.Errors).Contains(CertificateValidationError.Unspecified);
			await Assert.That(result.Errors).Contains(CertificateValidationError.UntrustedRoot);
		}
	}

	[Test]
	public async Task StopsAddingCertificatesAtTheLimit()
	{
		using Authority root = Authority.CreateRoot();
		using Authority intermediate = root.CreateIntermediate();
		string[] uris = ["http://ca.test/1.p7c", "http://ca.test/2.p7c", "http://ca.test/3.p7c"];
		Certificate leaf = intermediate.IssueLeaf(more: [Aia(caIssuers: uris)]);
		FakeRetriever retriever = new();

		for (int i = 0; i < uris.Length; ++i)
		{
			int index = i;
			retriever[uris[i]] = CertsOnly([.. Enumerable.Range(0, RetrievalBudget.MaxCertificatesPerRetrieval).Select(j => Encoded(root.IssueLeaf($"CN=N{index}-{j}")))]);
		}

		using TrustAnchorCertificateValidator validator = WithRetriever(retriever, root.Certificate);

		CertificateValidationResult result = await Validate(validator, presented: [leaf]);

		using (Assert.Multiple())
		{
			await Assert.That(result.Errors).Contains(CertificateValidationError.Unspecified);
			await Assert.That(result.Message).Contains("retrieved certificates");
		}
	}

	// A certificate longer than the limit for one does not make it into the pool, whatever the retriever returns.
	[Test]
	public async Task IgnoresABodyLongerThanTheLimit()
	{
		using Authority root = Authority.CreateRoot();
		using Authority intermediate = root.CreateIntermediate(more: [new CertificateExtension("1.3.6.1.4.1.55738.666.2", false, new byte[RetrievalBudget.MaxCertificateLength + 16])]);
		Certificate leaf = intermediate.IssueLeaf(more: [Aia(caIssuers: [IssuerUri])]);
		FakeRetriever retriever = new() { [IssuerUri] = Encoded(intermediate.Certificate) };
		using TrustAnchorCertificateValidator validator = WithRetriever(retriever, root.Certificate);

		await AssertInvalid(await Validate(validator, presented: [leaf]), [CertificateValidationError.UntrustedRoot], CertificatePathEnd.MissingIssuer, leaf);
	}

	// The total of the bytes retrieved is limited too: the CRLs here take it all, so the last is not retrieved.
	[Test]
	public async Task StopsRetrievingAtTheLimitOfBytes()
	{
		using Authority root = Authority.CreateRoot();
		string[] uris = ["http://crl.test/1", "http://crl.test/2", "http://crl.test/3"];
		Certificate leaf = root.IssueLeaf(more: [Cdp(uris)]);
		byte[] body = new byte[RetrievalBudget.MaxCrlLength];
		FakeRetriever retriever = new();

		foreach (string uri in uris)
		{
			retriever[uri] = body;
		}

		using TrustAnchorCertificateValidator validator = Online(retriever, root.Certificate);

		CertificateValidationResult result = await Validate(validator, presented: [leaf]);

		using (Assert.Multiple())
		{
			await AssertInvalid(result, [CertificateValidationError.RevocationUnknown], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
			await Assert.That(retriever.Requests.Count).IsEqualTo((int)(RetrievalBudget.MaxRetrievedBytes / RetrievalBudget.MaxCrlLength));
		}
	}

	// The peer chooses how many URIs its certificate names and how long its issuer's name is. A request has a key of fixed size, and the validation prepares a bounded number of them before the limits of retrieval apply, so that what it allocates does not grow with the product of the two.
	[Test]
	public async Task PreparesABoundedNumberOfRequestsForIssuers()
	{
		using Authority root = Authority.CreateRoot();
		using Authority longNamed = root.CreateIntermediate(subject: LongName());
		Certificate leaf = longNamed.IssueLeaf(more: [Aia(caIssuers: ManyUris("http://ca.test/"))]);
		using TrustAnchorCertificateValidator validator = WithRetriever(new FakeRetriever(), root.Certificate);

		(CertificateValidationResult result, long allocated) = await MeasureAsync(validator, leaf);

		using (Assert.Multiple())
		{
			await AssertInvalid(result, [CertificateValidationError.UntrustedRoot, CertificateValidationError.Unspecified], CertificatePathEnd.MissingIssuer, leaf);
			await Assert.That(result.Message).Contains("requests");
			await Assert.That(allocated).IsLessThan(MaxAllocatedForManyUris);
		}
	}

	// As PreparesABoundedNumberOfRequestsForIssuers, for the OCSP responders and the CRL distribution points of a certificate whose status is checked.
	[Test]
	public async Task PreparesABoundedNumberOfRequestsForRevocation()
	{
		using Authority root = Authority.CreateRoot();
		using Authority longNamed = root.CreateIntermediate(subject: LongName());
		Certificate leaf = longNamed.IssueLeaf(more: [Aia(ocsp: ManyUris("http://ocsp.test/")), Cdp(ManyUris("http://crl.test/"))]);
		using TrustAnchorCertificateValidator validator = Online(new FakeRetriever(), longNamed.Certificate);

		(CertificateValidationResult result, long allocated) = await MeasureAsync(validator, leaf);

		using (Assert.Multiple())
		{
			await AssertInvalid(result, [CertificateValidationError.RevocationUnknown], CertificatePathEnd.TrustAnchor, leaf, longNamed.Certificate);
			await Assert.That(allocated).IsLessThan(MaxAllocatedForManyUris);
		}
	}

	// Far less than what a key that grows with the name, for each URI, would take.
	private const long MaxAllocatedForManyUris = 8L << 20;

	private static byte[] LongName()
	{
		return Sequence(Tlv(0x31, Sequence(Oid("2.5.4.3"), Tlv(0x0C, System.Text.Encoding.ASCII.GetBytes(new string('n', 8192))))));
	}

	private static string[] ManyUris(string prefix)
	{
		return [.. Enumerable.Range(0, 600).Select(i => $"{prefix}{i}")];
	}

	// The bytes that a validation allocates, which completes on this thread, as the retriever answers at once.
	private static async Task<(CertificateValidationResult Result, long Allocated)> MeasureAsync(TrustAnchorCertificateValidator validator, Certificate leaf)
	{
		CertificateValidationContext context = new([leaf], CertificateUsage.ServerAuthentication) { TimeProvider = new FixedTimeProvider(Now) };
		long before = GC.GetAllocatedBytesForCurrentThread();
		ValueTask<CertificateValidationResult> validation = validator.ValidateAsync(context);
		long allocated = GC.GetAllocatedBytesForCurrentThread() - before;

		await Assert.That(validation.IsCompletedSuccessfully).IsTrue();
		return (await validation, allocated);
	}

	[Test]
	public async Task ChecksNoRevocationByDefault()
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf(more: [Aia(ocsp: [OcspUri]), Cdp(CrlUri)]);
		FakeRetriever retriever = new();
		using TrustAnchorCertificateValidator validator = WithRetriever(retriever, root.Certificate);

		await AssertValid(await Validate(validator, presented: [leaf]), leaf, root.Certificate);
		await Assert.That(retriever.Requests).IsEmpty();
	}

	[Test]
	public async Task OnlineChecksNeedARetriever()
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf();
		using TrustAnchorCertificateValidator validator = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo) { RevocationMode = X509RevocationMode.Online };

		await Assert.That(async () => await validator.ValidateAsync(new CertificateValidationContext([leaf], CertificateUsage.ServerAuthentication))).ThrowsExactly<InvalidOperationException>();
	}

	[Test]
	public async Task PropertiesRejectWhatIsNotDefined()
	{
		using Authority root = Authority.CreateRoot();
		Certificate[] anchors = [root.Certificate];

		using (Assert.Multiple())
		{
			await Assert.That(() => new TrustAnchorCertificateValidator(anchors, SignatureKey.ImportSubjectPublicKeyInfo) { RevocationMode = (X509RevocationMode)9 }).ThrowsExactly<ArgumentOutOfRangeException>();
			await Assert.That(() => new TrustAnchorCertificateValidator(anchors, SignatureKey.ImportSubjectPublicKeyInfo) { RevocationFlag = (X509RevocationFlag)9 }).ThrowsExactly<ArgumentOutOfRangeException>();
			await Assert.That(() => new TrustAnchorCertificateValidator(anchors, SignatureKey.ImportSubjectPublicKeyInfo) { RevocationLists = null! }).ThrowsExactly<ArgumentNullException>();
			await Assert.That(() => new TrustAnchorCertificateValidator(anchors, SignatureKey.ImportSubjectPublicKeyInfo) { RevocationLists = [null!] }).ThrowsExactly<ArgumentException>();
		}
	}

	[Test]
	public async Task OfflineUsesTheRevocationLists()
	{
		using Authority root = Authority.CreateRoot();
		using Authority other = Authority.CreateRoot("CN=Other");
		Certificate leaf = root.IssueLeaf(more: [Aia(ocsp: [OcspUri]), Cdp(CrlUri)]);
		FakeRetriever retriever = new()
		{
			Responder = Ocsp(root.IssueLeaf(), root, TestOcsp.Good),
			[CrlUri] = EncodeCrl(root)
		};
		CertificateRevocationList good = DecodeCrl(root);
		CertificateRevocationList revoked = DecodeCrl(root, leaf);
		CertificateRevocationList foreign = DecodeCrl(other);
		CertificateRevocationList stale = (TestCrl.Conforming(root) with
		{
			ThisUpdate = Time(Now.AddDays(-2)),
			NextUpdate = Time(Now.AddDays(-1))
		}).Decode(root);

		using (Assert.Multiple())
		{
			await AssertValid(await Run([good]), leaf, root.Certificate);
			await AssertInvalid(await Run([revoked]), [CertificateValidationError.Revoked], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
			await AssertInvalid(await Run([]), [CertificateValidationError.RevocationUnknown], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
			await AssertInvalid(await Run([foreign]), [CertificateValidationError.RevocationUnknown], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
			await AssertInvalid(await Run([stale]), [CertificateValidationError.RevocationUnknown], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
			await AssertValid(await Run([], soft: true), leaf, root.Certificate);
			await AssertValid(await Run([stale], soft: true), leaf, root.Certificate);
			await AssertInvalid(await Run([stale, revoked], soft: true), [CertificateValidationError.Revoked], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
			await AssertInvalid(await Run([good, revoked]), [CertificateValidationError.Revoked], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
			await Assert.That(retriever.Requests).IsEmpty();
		}

		async Task<CertificateValidationResult> Run(CertificateRevocationList[] lists, bool soft = false)
		{
			using TrustAnchorCertificateValidator validator = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo)
			{
				Retriever = retriever,
				RevocationMode = X509RevocationMode.Offline,
				RevocationLists = lists,
				IgnoreRevocationUnknown = soft
			};
			return await Validate(validator, presented: [leaf]);
		}
	}

	[Test]
	public async Task OfflineCompletesSynchronously()
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf();
		using TrustAnchorCertificateValidator validator = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo)
		{
			RevocationMode = X509RevocationMode.Offline,
			RevocationLists = [DecodeCrl(root)]
		};

		ValueTask<CertificateValidationResult> result = validator.ValidateAsync(new CertificateValidationContext([leaf], CertificateUsage.ServerAuthentication) { TimeProvider = new FixedTimeProvider(Now) });

		await Assert.That(result.IsCompletedSuccessfully).IsTrue();
		await AssertValid(await result, leaf, root.Certificate);
	}

	[Test]
	public async Task TheRevocationListsComeBeforeTheNetwork()
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf(more: [Aia(ocsp: [OcspUri]), Cdp(CrlUri)]);
		FakeRetriever retriever = new();
		using TrustAnchorCertificateValidator good = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo)
		{
			Retriever = retriever,
			RevocationMode = X509RevocationMode.Online,
			RevocationLists = [DecodeCrl(root)]
		};
		using TrustAnchorCertificateValidator revoked = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo)
		{
			Retriever = retriever,
			RevocationMode = X509RevocationMode.Online,
			RevocationLists = [DecodeCrl(root, leaf)]
		};

		using (Assert.Multiple())
		{
			await AssertValid(await Validate(good, presented: [leaf]), leaf, root.Certificate);
			await AssertInvalid(await Validate(revoked, presented: [leaf]), [CertificateValidationError.Revoked], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
			await Assert.That(retriever.Requests).IsEmpty();
		}
	}

	[Test]
	public async Task AnOcspResponderDecides()
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf(more: [Aia(ocsp: [OcspUri]), Cdp(CrlUri)]);
		FakeRetriever good = new() { Responder = Ocsp(leaf, root, TestOcsp.Good) };
		FakeRetriever revoked = new() { Responder = Ocsp(leaf, root, TestOcsp.Revoked(Now.AddHours(-3), reason: 1)) };
		using TrustAnchorCertificateValidator goodValidator = Online(good, root.Certificate);
		using TrustAnchorCertificateValidator revokedValidator = Online(revoked, root.Certificate);

		CertificateValidationResult refused = await Validate(revokedValidator, presented: [leaf]);

		using (Assert.Multiple())
		{
			await AssertValid(await Validate(goodValidator, presented: [leaf]), leaf, root.Certificate);
			await Assert.That(good.Requests.Single().Method).IsEqualTo("GET");
			await AssertInvalid(refused, [CertificateValidationError.Revoked], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
			await Assert.That(refused.Message).Contains("KeyCompromise");
			await Assert.That(revoked.Requests.Count).IsEqualTo(1);
		}
	}

	[Test]
	public async Task AResponderThatDoesNotKnowTheCertificateLeavesItToTheCrl()
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf(more: [Aia(ocsp: [OcspUri]), Cdp(CrlUri)]);
		FakeRetriever good = new()
		{
			Responder = Ocsp(leaf, root, TestOcsp.UnknownStatus),
			[CrlUri] = EncodeCrl(root)
		};
		FakeRetriever revoked = new()
		{
			Responder = Ocsp(leaf, root, TestOcsp.UnknownStatus),
			[CrlUri] = EncodeCrl(root, leaf)
		};
		using TrustAnchorCertificateValidator goodValidator = Online(good, root.Certificate);
		using TrustAnchorCertificateValidator revokedValidator = Online(revoked, root.Certificate);

		using (Assert.Multiple())
		{
			await AssertValid(await Validate(goodValidator, presented: [leaf]), leaf, root.Certificate);
			await AssertInvalid(await Validate(revokedValidator, presented: [leaf]), [CertificateValidationError.Revoked], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
		}
	}

	// A responder that does not know the certificate does not speak for the next: only good or revoked ends the responders.
	[Test]
	public async Task AsksTheNextResponderAfterOneThatDoesNotKnowTheCertificate()
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf(more: [Aia(ocsp: ["http://first.test/", "http://second.test/"])]);
		byte[] unknown = Ocsp(leaf, root, TestOcsp.UnknownStatus);
		byte[] revoked = Ocsp(leaf, root, TestOcsp.Revoked(Now.AddHours(-1), reason: 1));
		FakeRetriever hardRetriever = new()
		{
			ByHost =
			{
				["first.test"] = unknown,
				["second.test"] = revoked
			}
		};
		FakeRetriever softRetriever = new()
		{
			ByHost =
			{
				["first.test"] = unknown,
				["second.test"] = revoked
			}
		};
		using TrustAnchorCertificateValidator hard = Online(hardRetriever, root.Certificate);
		using TrustAnchorCertificateValidator soft = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo)
		{
			Retriever = softRetriever,
			RevocationMode = X509RevocationMode.Online,
			IgnoreRevocationUnknown = true
		};

		using (Assert.Multiple())
		{
			await AssertInvalid(await Validate(hard, presented: [leaf]), [CertificateValidationError.Revoked], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
			await AssertInvalid(await Validate(soft, presented: [leaf]), [CertificateValidationError.Revoked], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
			await Assert.That(hardRetriever.Requests.Count).IsEqualTo(3);
		}
	}

	// A response that says unknown is not kept, so that it does not hide the other responders the next time; a good one that a later responder gives is.
	[Test]
	public async Task DoesNotKeepAResponseThatDoesNotKnowTheCertificate()
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf(more: [Aia(ocsp: ["http://first.test/", "http://second.test/"])]);
		byte[] unknown = Ocsp(leaf, root, TestOcsp.UnknownStatus);
		byte[] good = Ocsp(leaf, root, TestOcsp.Good);
		FakeRetriever allUnknown = new()
		{
			ByHost =
			{
				["first.test"] = unknown,
				["second.test"] = unknown
			}
		};
		FakeRetriever laterGood = new()
		{
			ByHost =
			{
				["first.test"] = unknown,
				["second.test"] = good
			}
		};
		using TrustAnchorCertificateValidator unknownValidator = Online(allUnknown, root.Certificate);
		using TrustAnchorCertificateValidator goodValidator = Online(laterGood, root.Certificate);

		using (Assert.Multiple())
		{
			await AssertInvalid(await Validate(unknownValidator, presented: [leaf]), [CertificateValidationError.RevocationUnknown], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
			await AssertInvalid(await Validate(unknownValidator, presented: [leaf]), [CertificateValidationError.RevocationUnknown], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
			await Assert.That(allUnknown.Requests.Count).IsEqualTo(8);
			await AssertValid(await Validate(goodValidator, presented: [leaf]), leaf, root.Certificate);
			await AssertValid(await Validate(goodValidator, presented: [leaf]), leaf, root.Certificate);
			await Assert.That(laterGood.Requests.Count).IsEqualTo(3);
		}
	}

	[Test]
	public async Task AnOcspFailureFallsBackToTheCrl()
	{
		using Authority root = Authority.CreateRoot();
		using Authority other = Authority.CreateRoot("CN=Other");
		Certificate leaf = root.IssueLeaf(more: [Aia(ocsp: [OcspUri]), Cdp(CrlUri)]);
		byte[] notSignedByTheIssuer = new TestOcsp.Basic
		{
			ResponderId = TestOcsp.ResponderByKey(root.Certificate),
			Responses =
			[
				new TestOcsp.SingleEntry
				{
					CertificateId = TestOcsp.CertificateIdOf(leaf, root.Certificate),
					Status = TestOcsp.Revoked(Now)
				}.Encode()
			]
		}.Encode(other.Key);

		foreach (byte[]? answer in (byte[]?[])[null, [0x30, 0x01], notSignedByTheIssuer])
		{
			FakeRetriever retriever = new()
			{
				Responder = answer,
				[CrlUri] = EncodeCrl(root)
			};
			using TrustAnchorCertificateValidator validator = Online(retriever, root.Certificate);

			await AssertValid(await Validate(validator, presented: [leaf]), leaf, root.Certificate);
		}
	}

	// RFC 9919, Sec. 3.1.1: the first request uses SHA-256, and good or revoked ends the questions, whatever SHA-1 would say.
	[Test]
	public async Task ASha256AnswerEndsTheQuestions()
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf(more: [Aia(ocsp: [OcspUri])]);
		FakeRetriever good = new() { ByCertIdHash = { ["ocsp.test"] = (OcspSha256(leaf, root, TestOcsp.Good), Ocsp(leaf, root, TestOcsp.Revoked(Now.AddHours(-1), reason: 1))) } };
		FakeRetriever revoked = new() { ByCertIdHash = { ["ocsp.test"] = (OcspSha256(leaf, root, TestOcsp.Revoked(Now.AddHours(-1), reason: 1)), Ocsp(leaf, root, TestOcsp.Good)) } };
		using TrustAnchorCertificateValidator goodValidator = Online(good, root.Certificate);
		using TrustAnchorCertificateValidator revokedValidator = Online(revoked, root.Certificate);

		using (Assert.Multiple())
		{
			await AssertValid(await Validate(goodValidator, presented: [leaf]), leaf, root.Certificate);
			await Assert.That(good.Requests.Select(CertIdHashOf)).IsEquivalentTo((string[])[Sha256Oid], CollectionOrdering.Matching);
			await AssertInvalid(await Validate(revokedValidator, presented: [leaf]), [CertificateValidationError.Revoked], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
			await Assert.That(revoked.Requests.Select(CertIdHashOf)).IsEquivalentTo((string[])[Sha256Oid], CollectionOrdering.Matching);
		}
	}

	// Whatever keeps a responder from answering the SHA-256 request with good or revoked, the same responder is asked once with SHA-1.
	[Test]
	public async Task AsksTheSameResponderWithSha1AfterASha256RequestWithoutAnAnswer()
	{
		using Authority root = Authority.CreateRoot();
		using Authority other = Authority.CreateRoot("CN=Other");
		Certificate leaf = root.IssueLeaf(more: [Aia(ocsp: [OcspUri])]);
		byte[] signedByAnother = new TestOcsp.Basic
		{
			ResponderId = TestOcsp.ResponderByKey(root.Certificate),
			Responses =
			[
				new TestOcsp.SingleEntry
				{
					CertificateId = TestOcsp.Sha256CertificateIdOf(leaf, root.Certificate),
					Status = TestOcsp.Good
				}.Encode()
			]
		}.Encode(other.Key);
		byte[][] failures = [OcspSha256(leaf, root, TestOcsp.UnknownStatus), Sequence([0x0A, 0x01, 0x06]), Sequence([0x0A, 0x01, 0x01]), [0x30, 0x01], signedByAnother];

		foreach (byte[] failure in failures)
		{
			FakeRetriever retriever = new() { ByCertIdHash = { ["ocsp.test"] = (failure, Ocsp(leaf, root, TestOcsp.Good)) } };
			using TrustAnchorCertificateValidator validator = Online(retriever, root.Certificate);

			using (Assert.Multiple())
			{
				await AssertValid(await Validate(validator, presented: [leaf]), leaf, root.Certificate);
				await Assert.That(retriever.Requests.Select(CertIdHashOf)).IsEquivalentTo((string[])[Sha256Oid, Sha1Oid], CollectionOrdering.Matching);
			}
		}
	}

	[Test]
	public async Task TheSha1AnswerCanRevoke()
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf(more: [Aia(ocsp: [OcspUri])]);
		FakeRetriever retriever = new() { ByCertIdHash = { ["ocsp.test"] = (OcspSha256(leaf, root, TestOcsp.UnknownStatus), Ocsp(leaf, root, TestOcsp.Revoked(Now.AddHours(-1), reason: 1))) } };
		using TrustAnchorCertificateValidator validator = Online(retriever, root.Certificate);

		using (Assert.Multiple())
		{
			await AssertInvalid(await Validate(validator, presented: [leaf]), [CertificateValidationError.Revoked], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
			await Assert.That(retriever.Requests.Count).IsEqualTo(2);
		}
	}

	// A responder that could not be reached is not asked again, even though SHA-1 would have answered.
	[Test]
	public async Task AResponderThatCannotBeReachedIsNotAskedWithSha1()
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf(more: [Aia(ocsp: ["http://first.test/", "http://second.test/"])]);
		FakeRetriever retriever = new()
		{
			ByCertIdHash =
			{
				["first.test"] = (null, Ocsp(leaf, root, TestOcsp.Good)),
				["second.test"] = (OcspSha256(leaf, root, TestOcsp.Good), null)
			}
		};
		using TrustAnchorCertificateValidator validator = Online(retriever, root.Certificate);

		using (Assert.Multiple())
		{
			await AssertValid(await Validate(validator, presented: [leaf]), leaf, root.Certificate);
			await Assert.That(retriever.Requests.Select(static request => (request.Uri.Host, CertIdHashOf(request)))).IsEquivalentTo((ValueTuple<string, string>[])[("first.test", Sha256Oid), ("second.test", Sha256Oid)], CollectionOrdering.Matching);
		}
	}

	// A responder without an answer to either request gives way to the next, and the last to the CRL.
	[Test]
	public async Task RespondersWithoutAnAnswerToEitherRequestLeaveItToTheCrl()
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf(more: [Aia(ocsp: ["http://first.test/", "http://second.test/"]), Cdp(CrlUri)]);
		(byte[]? Sha256, byte[]? Sha1) noAnswer = (OcspSha256(leaf, root, TestOcsp.UnknownStatus), Sequence([0x0A, 0x01, 0x01]));

		foreach (bool revoked in (bool[])[false, true])
		{
			FakeRetriever retriever = new()
			{
				ByCertIdHash =
				{
					["first.test"] = noAnswer,
					["second.test"] = noAnswer
				},
				[CrlUri] = revoked ? EncodeCrl(root, leaf) : EncodeCrl(root)
			};
			using TrustAnchorCertificateValidator validator = Online(retriever, root.Certificate);

			CertificateValidationResult result = await Validate(validator, presented: [leaf]);

			using (Assert.Multiple())
			{
				if (revoked)
				{
					await AssertInvalid(result, [CertificateValidationError.Revoked], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
				}
				else
				{
					await AssertValid(result, leaf, root.Certificate);
				}

				await Assert.That(retriever.Requests.Select(static request => request.Uri.Host)).IsEquivalentTo((string[])["first.test", "first.test", "second.test", "second.test", "crl.test"], CollectionOrdering.Matching);
				await Assert.That(retriever.Requests.Take(4).Select(CertIdHashOf)).IsEquivalentTo((string[])[Sha256Oid, Sha1Oid, Sha256Oid, Sha1Oid], CollectionOrdering.Matching);
			}
		}
	}

	// A response with a SHA-1 CertID is kept where the SHA-256 request looks it up, so that the next validation sends nothing, until it lapses.
	[Test]
	public async Task KeepsTheAnswerToTheSha1RequestForTheSha256Request()
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf(more: [Aia(ocsp: [OcspUri])]);
		FakeRetriever retriever = new() { ByCertIdHash = { ["ocsp.test"] = (OcspSha256(leaf, root, TestOcsp.UnknownStatus), Ocsp(leaf, root, TestOcsp.Good, Now.AddHours(1))) } };
		using TrustAnchorCertificateValidator validator = Online(retriever, root.Certificate);
		MovingClock clock = new();

		using (Assert.Multiple())
		{
			await AssertValid(await Validate(validator, clock, presented: [leaf]), leaf, root.Certificate);
			await Assert.That(retriever.Requests.Count).IsEqualTo(2);
			await AssertValid(await Validate(validator, clock, presented: [leaf]), leaf, root.Certificate);
			await Assert.That(retriever.Requests.Count).IsEqualTo(2);

			clock.Time = Now.AddHours(2);
			retriever.ByCertIdHash["ocsp.test"] = (OcspSha256(leaf, root, TestOcsp.Good, Now.AddHours(3)), null);
			await AssertValid(await Validate(validator, clock, presented: [leaf]), leaf, root.Certificate);
			await Assert.That(retriever.Requests.Select(CertIdHashOf)).IsEquivalentTo((string[])[Sha256Oid, Sha1Oid, Sha256Oid], CollectionOrdering.Matching);
		}
	}

	// A request with SHA-1 is a retrieval like any other: the issuer takes one, each responder two, and the limit falls between a responder's two requests.
	[Test]
	public async Task TheSha1RequestCountsTowardTheLimitOfRetrievals()
	{
		using Authority root = Authority.CreateRoot();
		using Authority intermediate = root.CreateIntermediate();
		string[] hosts = [.. Enumerable.Range(0, RetrievalBudget.MaxRetrievals).Select(static i => $"r{i}.test")];
		Certificate leaf = intermediate.IssueLeaf(more: [Aia(caIssuers: [IssuerUri], ocsp: [.. hosts.Select(static host => $"http://{host}/")])]);
		byte[] unknown = OcspSha256(leaf, intermediate, TestOcsp.UnknownStatus);
		FakeRetriever retriever = new() { [IssuerUri] = Encoded(intermediate.Certificate) };

		foreach (string host in hosts)
		{
			retriever.ByCertIdHash[host] = (unknown, unknown);
		}

		using TrustAnchorCertificateValidator validator = Online(retriever, root.Certificate);

		CertificateValidationResult result = await Validate(validator, presented: [leaf]);
		FakeRetriever.Request last = retriever.Requests.Last();

		using (Assert.Multiple())
		{
			await Assert.That(result.Errors).Contains(CertificateValidationError.RevocationUnknown);
			await Assert.That(retriever.Requests.Count).IsEqualTo(RetrievalBudget.MaxRetrievals);
			await Assert.That(last.Uri.Host).IsEqualTo(hosts[(RetrievalBudget.MaxRetrievals - 2) / 2]);
			await Assert.That(CertIdHashOf(last)).IsEqualTo(Sha256Oid);
		}
	}

	[Test]
	public async Task AStatusThatNoSourceDeterminesIsUnknown()
	{
		using Authority root = Authority.CreateRoot();
		Certificate withSources = root.IssueLeaf(more: [Aia(ocsp: [OcspUri]), Cdp(CrlUri)]);
		Certificate withoutSources = root.IssueLeaf();
		byte[] stale = (TestCrl.Conforming(root) with
		{
			ThisUpdate = Time(Now.AddDays(-2)),
			NextUpdate = Time(Now.AddDays(-1))
		}).Encode(root);

		foreach (byte[]? crl in (byte[]?[])[null, [0x30, 0x01], stale])
		{
			FakeRetriever retriever = new() { [CrlUri] = crl ?? [] };
			using TrustAnchorCertificateValidator hard = Online(retriever, root.Certificate);
			using TrustAnchorCertificateValidator soft = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo)
			{
				Retriever = retriever,
				RevocationMode = X509RevocationMode.Online,
				IgnoreRevocationUnknown = true
			};

			await AssertInvalid(await Validate(hard, presented: [withSources]), [CertificateValidationError.RevocationUnknown], CertificatePathEnd.TrustAnchor, withSources, root.Certificate);
			await AssertValid(await Validate(soft, presented: [withSources]), withSources, root.Certificate);
		}

		using TrustAnchorCertificateValidator noSources = Online(new FakeRetriever(), root.Certificate);
		await AssertInvalid(await Validate(noSources, presented: [withoutSources]), [CertificateValidationError.RevocationUnknown], CertificatePathEnd.TrustAnchor, withoutSources, root.Certificate);
	}

	[Test]
	public async Task RetrievesACrlFromADistributionPoint()
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf(more: [Cdp(CrlUri)]);
		FakeRetriever good = new() { [CrlUri] = EncodeCrl(root) };
		FakeRetriever revoked = new() { [CrlUri] = EncodeCrl(root, leaf) };
		using TrustAnchorCertificateValidator goodValidator = Online(good, root.Certificate);
		using TrustAnchorCertificateValidator revokedValidator = Online(revoked, root.Certificate);

		using (Assert.Multiple())
		{
			await AssertValid(await Validate(goodValidator, presented: [leaf]), leaf, root.Certificate);
			await Assert.That(good.Requests.Single().MaxLength).IsEqualTo(RetrievalBudget.MaxCrlLength);
			await AssertInvalid(await Validate(revokedValidator, presented: [leaf]), [CertificateValidationError.Revoked], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
		}
	}

	// A URI that two distribution points name is retrieved once in a validation, even if it fails.
	[Test]
	public async Task RetrievesACrlUriOnce()
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf(more: [Cdp(CrlUri, CrlUri)]);
		FakeRetriever retriever = new() { [CrlUri] = [0x30, 0x01] };
		using TrustAnchorCertificateValidator validator = Online(retriever, root.Certificate);

		await AssertInvalid(await Validate(validator, presented: [leaf]), [CertificateValidationError.RevocationUnknown], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
		await Assert.That(retriever.Requests.Count).IsEqualTo(1);
	}

	// A kept response that can no longer be used, as its validity has not begun at this time, sends the validator back to the responder.
	[Test]
	public async Task AsksAgainIfAKeptResponseNoLongerApplies()
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf(more: [Aia(ocsp: [OcspUri])]);
		FakeRetriever retriever = new() { Responder = Ocsp(leaf, root, TestOcsp.Good) };
		using TrustAnchorCertificateValidator validator = Online(retriever, root.Certificate);
		MovingClock clock = new();

		await AssertValid(await Validate(validator, clock, presented: [leaf]), leaf, root.Certificate);
		clock.Time = Now.AddMinutes(-20);
		await AssertInvalid(await Validate(validator, clock, presented: [leaf]), [CertificateValidationError.RevocationUnknown], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
		await Assert.That(retriever.Requests.Count).IsEqualTo(3);
	}

	// RFC 5280, Sec. 6.3.3: CRLs for some reasons alone combine, whether the caller gave them or they were retrieved.
	[Test]
	public async Task CombinesCrlsForSomeReasons()
	{
		using Authority root = Authority.CreateRoot();
		string[] uris = ["http://crl.test/key", "http://crl.test/others"];
		Certificate leaf = root.IssueLeaf(more: [Cdp(uris)]);
		byte[] keyCompromise = TestCrl.Conforming(root, null, TestCrl.IssuingDistributionPoint(OnlyKeyCompromise)).Encode(root);
		byte[] others = TestCrl.Conforming(root, null, TestCrl.IssuingDistributionPoint(EveryOtherReason)).Encode(root);
		byte[] othersRevoked = TestCrl.Conforming(root, [TestCrl.Entry(TestCrl.SerialNumberOf(leaf))], TestCrl.IssuingDistributionPoint(EveryOtherReason)).Encode(root);
		FakeRetriever retrieved = new()
		{
			[uris[0]] = keyCompromise,
			[uris[1]] = others
		};
		FakeRetriever partly = new() { [uris[0]] = keyCompromise };
		FakeRetriever revoked = new()
		{
			[uris[0]] = keyCompromise,
			[uris[1]] = othersRevoked
		};
		using TrustAnchorCertificateValidator retrievedValidator = Online(retrieved, root.Certificate);
		using TrustAnchorCertificateValidator partlyValidator = Online(partly, root.Certificate);
		using TrustAnchorCertificateValidator revokedValidator = Online(revoked, root.Certificate);
		using TrustAnchorCertificateValidator offline = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo)
		{
			RevocationMode = X509RevocationMode.Offline,
			RevocationLists = [CertificateRevocationList.Decode(keyCompromise), CertificateRevocationList.Decode(others)]
		};
		using TrustAnchorCertificateValidator mixed = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo)
		{
			Retriever = new FakeRetriever { [uris[1]] = others },
			RevocationMode = X509RevocationMode.Online,
			RevocationLists = [CertificateRevocationList.Decode(keyCompromise)]
		};

		using (Assert.Multiple())
		{
			await AssertValid(await Validate(retrievedValidator, presented: [leaf]), leaf, root.Certificate);
			await AssertInvalid(await Validate(partlyValidator, presented: [leaf]), [CertificateValidationError.RevocationUnknown], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
			await AssertInvalid(await Validate(revokedValidator, presented: [leaf]), [CertificateValidationError.Revoked], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
			await AssertValid(await Validate(offline, presented: [leaf]), leaf, root.Certificate);
			await AssertValid(await Validate(mixed, presented: [leaf]), leaf, root.Certificate);
		}
	}

	// A CRL point with a cRLIssuer is for an indirect CRL, which is not supported, so nothing retrieves it.
	[Test]
	public async Task DoesNotRetrieveAnIndirectCrl()
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf(more: [TestCrl.DistributionPoints(Sequence(TestCrl.FullName(0xA0, UniformResourceIdentifier(CrlUri)), Tlv(0xA2, DirectoryName("CN=Other"))))]);
		FakeRetriever retriever = new() { [CrlUri] = EncodeCrl(root) };
		using TrustAnchorCertificateValidator validator = Online(retriever, root.Certificate);

		await AssertInvalid(await Validate(validator, presented: [leaf]), [CertificateValidationError.RevocationUnknown], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
		await Assert.That(retriever.Requests).IsEmpty();
	}

	// A cross-certificate leads to the other root when the first path is revoked.
	[Test]
	public async Task ARevokedCertificateGivesWayToAnotherPath()
	{
		using Authority first = Authority.CreateRoot("CN=First");
		using Authority second = Authority.CreateRoot("CN=Second");
		using Authority intermediate = first.CreateIntermediate();
		byte[] subjectPublicKeyInfo = intermediate.Certificate.PublicKeyInfo.Encoded.ToArray();
		Certificate cross = second.Issue
		(
			new Template
			{
				Subject = intermediate.Name,
				SubjectPublicKeyInfo = subjectPublicKeyInfo,
				Extensions = [.. CaExtensions(subjectPublicKeyInfo), AuthorityKeyIdentifier(second.KeyIdentifier)]
			}
		);
		Certificate leaf = intermediate.IssueLeaf();
		CertificateRevocationList intermediateCrl = DecodeCrl(intermediate);
		CertificateRevocationList firstRevokes = DecodeCrl(first, intermediate.Certificate);
		CertificateRevocationList secondGood = DecodeCrl(second);
		CertificateRevocationList secondRevokes = DecodeCrl(second, cross);
		using TrustAnchorCertificateValidator alternative = new([first.Certificate, second.Certificate], SignatureKey.ImportSubjectPublicKeyInfo)
		{
			RevocationMode = X509RevocationMode.Offline,
			RevocationLists = [intermediateCrl, firstRevokes, secondGood]
		};
		using TrustAnchorCertificateValidator allRevoked = new([first.Certificate, second.Certificate], SignatureKey.ImportSubjectPublicKeyInfo)
		{
			RevocationMode = X509RevocationMode.Offline,
			RevocationLists = [intermediateCrl, firstRevokes, secondRevokes]
		};

		using (Assert.Multiple())
		{
			await AssertValid(await Validate(alternative, presented: [leaf, intermediate.Certificate, cross]), leaf, cross, second.Certificate);
			await AssertInvalid(await Validate(allRevoked, presented: [leaf, intermediate.Certificate, cross]), [CertificateValidationError.Revoked], CertificatePathEnd.TrustAnchor, leaf, intermediate.Certificate, first.Certificate);
		}
	}

	// A status that no source determines leaves that path as a revoked certificate does, whichever path the search finds first.
	[Test]
	public async Task AStatusThatIsNotKnownGivesWayToAnotherPath()
	{
		using Authority first = Authority.CreateRoot("CN=First");
		using Authority second = Authority.CreateRoot("CN=Second");
		using Authority intermediate = first.CreateIntermediate();
		byte[] subjectPublicKeyInfo = intermediate.Certificate.PublicKeyInfo.Encoded.ToArray();
		Certificate cross = second.Issue
		(
			new Template
			{
				Subject = intermediate.Name,
				SubjectPublicKeyInfo = subjectPublicKeyInfo,
				Extensions = [.. CaExtensions(subjectPublicKeyInfo), AuthorityKeyIdentifier(second.KeyIdentifier)]
			}
		);
		Certificate leaf = intermediate.IssueLeaf();
		CertificateRevocationList intermediateCrl = DecodeCrl(intermediate);
		CertificateRevocationList secondGood = DecodeCrl(second);
		CertificateRevocationList firstGood = DecodeCrl(first);
		CertificateRevocationList firstRevokes = DecodeCrl(first, intermediate.Certificate);
		CertificateRevocationList secondRevokes = DecodeCrl(second, cross);
		using TrustAnchorCertificateValidator secondOnly = Create([first.Certificate, second.Certificate], [intermediateCrl, secondGood]);
		using TrustAnchorCertificateValidator secondOnlySwapped = Create([second.Certificate, first.Certificate], [intermediateCrl, secondGood]);
		using TrustAnchorCertificateValidator firstOnly = Create([first.Certificate, second.Certificate], [intermediateCrl, firstGood]);
		using TrustAnchorCertificateValidator allUnknown = Create([first.Certificate, second.Certificate], [intermediateCrl]);
		using TrustAnchorCertificateValidator revokedAndUnknown = Create([first.Certificate, second.Certificate], [intermediateCrl, firstRevokes]);
		using TrustAnchorCertificateValidator unknownAndRevoked = Create([first.Certificate, second.Certificate], [intermediateCrl, secondRevokes]);
		using TrustAnchorCertificateValidator soft = new([first.Certificate, second.Certificate], SignatureKey.ImportSubjectPublicKeyInfo)
		{
			RevocationMode = X509RevocationMode.Offline,
			RevocationLists = [intermediateCrl],
			IgnoreRevocationUnknown = true
		};

		using (Assert.Multiple())
		{
			// The path through the first root is found first, and has no status; the other is good.
			await AssertValid(await Validate(secondOnly, presented: [leaf, intermediate.Certificate, cross]), leaf, cross, second.Certificate);
			await AssertValid(await Validate(secondOnlySwapped, presented: [leaf, cross, intermediate.Certificate]), leaf, cross, second.Certificate);
			await AssertValid(await Validate(firstOnly, presented: [leaf, cross, intermediate.Certificate]), leaf, intermediate.Certificate, first.Certificate);

			// Every path without a status: the first is reported.
			await AssertInvalid(await Validate(allUnknown, presented: [leaf, intermediate.Certificate, cross]), [CertificateValidationError.RevocationUnknown], CertificatePathEnd.TrustAnchor, leaf, intermediate.Certificate, first.Certificate);

			// A revoked path is reported before one without a status, in either order of finding them.
			await AssertInvalid(await Validate(revokedAndUnknown, presented: [leaf, intermediate.Certificate, cross]), [CertificateValidationError.Revoked], CertificatePathEnd.TrustAnchor, leaf, intermediate.Certificate, first.Certificate);
			await AssertInvalid(await Validate(revokedAndUnknown, presented: [leaf, cross, intermediate.Certificate]), [CertificateValidationError.Revoked], CertificatePathEnd.TrustAnchor, leaf, intermediate.Certificate, first.Certificate);
			await AssertInvalid(await Validate(unknownAndRevoked, presented: [leaf, intermediate.Certificate, cross]), [CertificateValidationError.Revoked], CertificatePathEnd.TrustAnchor, leaf, cross, second.Certificate);

			// Soft-fail accepts the first path, as it did.
			await AssertValid(await Validate(soft, presented: [leaf, intermediate.Certificate, cross]), leaf, intermediate.Certificate, first.Certificate);
		}

		static TrustAnchorCertificateValidator Create(Certificate[] anchors, CertificateRevocationList[] lists)
		{
			return new TrustAnchorCertificateValidator(anchors, SignatureKey.ImportSubjectPublicKeyInfo)
			{
				RevocationMode = X509RevocationMode.Offline,
				RevocationLists = lists
			};
		}
	}

	// The limit on revoked certificates counts those without a status too, and the search says that it stopped.
	[Test]
	public async Task StopsWorkingAroundUnknownStatusesAtTheLimit()
	{
		int limit = CertificatePathSearch.MaxRejectedEdges;
		List<Authority> roots = [.. Enumerable.Range(0, limit + 2).Select(static i => Authority.CreateRoot($"CN=Root {i}"))];
		using Authority intermediate = roots[0].CreateIntermediate();
		byte[] subjectPublicKeyInfo = intermediate.Certificate.PublicKeyInfo.Encoded.ToArray();
		Certificate[] crosses =
		[
			intermediate.Certificate, .. roots.Skip(1).Select
			(root => root.Issue
				(
					new Template
					{
						Subject = intermediate.Name,
						SubjectPublicKeyInfo = subjectPublicKeyInfo,
						Extensions = [.. CaExtensions(subjectPublicKeyInfo), AuthorityKeyIdentifier(root.KeyIdentifier)]
					}
				)
			)
		];
		Certificate leaf = intermediate.IssueLeaf();
		Certificate[] anchors = [.. roots.Select(static root => root.Certificate)];
		CertificateRevocationList[] lists = [DecodeCrl(intermediate)];
		using TrustAnchorCertificateValidator validator = new(anchors, SignatureKey.ImportSubjectPublicKeyInfo)
		{
			RevocationMode = X509RevocationMode.Offline,
			RevocationLists = lists
		};

		CertificateValidationResult result = await Validate(validator, presented: [leaf, .. crosses]);

		foreach (Authority root in roots)
		{
			root.Dispose();
		}

		using (Assert.Multiple())
		{
			await AssertInvalid(result, [CertificateValidationError.RevocationUnknown, CertificateValidationError.Unspecified], CertificatePathEnd.TrustAnchor, leaf, intermediate.Certificate, anchors[0]);
			await Assert.That(result.Message).Contains("revoked certificates");
		}
	}

	// Up to the limit a revoked certificate gives way to another path; beyond it the search stops and says so.
	[Test]
	public async Task StopsWorkingAroundRevokedCertificatesAtTheLimit()
	{
		int limit = CertificatePathSearch.MaxRejectedEdges;
		List<Authority> roots = [.. Enumerable.Range(0, limit + 2).Select(static i => Authority.CreateRoot($"CN=Root {i}"))];
		using Authority intermediate = roots[0].CreateIntermediate();
		byte[] subjectPublicKeyInfo = intermediate.Certificate.PublicKeyInfo.Encoded.ToArray();
		Certificate[] crosses =
		[
			intermediate.Certificate, .. roots.Skip(1).Select
			(root => root.Issue
				(
					new Template
					{
						Subject = intermediate.Name,
						SubjectPublicKeyInfo = subjectPublicKeyInfo,
						Extensions = [.. CaExtensions(subjectPublicKeyInfo), AuthorityKeyIdentifier(root.KeyIdentifier)]
					}
				)
			)
		];
		Certificate leaf = intermediate.IssueLeaf();
		Certificate[] anchors = [.. roots.Select(static root => root.Certificate)];
		CertificateRevocationList[] allRevoked = [DecodeCrl(intermediate), .. roots.Select((root, i) => DecodeCrl(root, crosses[i]))];
		CertificateRevocationList[] oneValid = [DecodeCrl(intermediate), .. roots.Select((root, i) => i < limit ? DecodeCrl(root, crosses[i]) : DecodeCrl(root))];
		using TrustAnchorCertificateValidator exhausted = new(anchors, SignatureKey.ImportSubjectPublicKeyInfo)
		{
			RevocationMode = X509RevocationMode.Offline,
			RevocationLists = allRevoked
		};
		using TrustAnchorCertificateValidator found = new(anchors, SignatureKey.ImportSubjectPublicKeyInfo)
		{
			RevocationMode = X509RevocationMode.Offline,
			RevocationLists = oneValid
		};

		CertificateValidationResult refused = await Validate(exhausted, presented: [leaf, .. crosses]);
		CertificateValidationResult accepted = await Validate(found, presented: [leaf, .. crosses]);

		foreach (Authority root in roots)
		{
			root.Dispose();
		}

		using (Assert.Multiple())
		{
			await AssertInvalid(refused, [CertificateValidationError.Revoked, CertificateValidationError.Unspecified], CertificatePathEnd.TrustAnchor, leaf, intermediate.Certificate, anchors[0]);
			await Assert.That(refused.Message).Contains("revoked certificates");
			await AssertValid(accepted, leaf, crosses[limit], anchors[limit]);
		}
	}

	[Test]
	public async Task RevocationFlagSelectsTheCertificates()
	{
		using Authority root = Authority.CreateRoot();
		using Authority intermediate = root.CreateIntermediate();
		Certificate leaf = intermediate.IssueLeaf();
		CertificateRevocationList leafCrl = DecodeCrl(intermediate);
		CertificateRevocationList revokesIntermediate = DecodeCrl(root, intermediate.Certificate);

		using (Assert.Multiple())
		{
			await AssertValid(await Run(X509RevocationFlag.EndCertificateOnly), leaf, intermediate.Certificate, root.Certificate);
			await AssertInvalid(await Run(X509RevocationFlag.ExcludeRoot), [CertificateValidationError.Revoked], CertificatePathEnd.TrustAnchor, leaf, intermediate.Certificate, root.Certificate);
			await AssertInvalid(await Run(X509RevocationFlag.EntireChain), [CertificateValidationError.Revoked], CertificatePathEnd.TrustAnchor, leaf, intermediate.Certificate, root.Certificate);
		}

		async Task<CertificateValidationResult> Run(X509RevocationFlag flag)
		{
			using TrustAnchorCertificateValidator validator = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo)
			{
				RevocationMode = X509RevocationMode.Offline,
				RevocationFlag = flag,
				RevocationLists = [leafCrl, revokesIntermediate]
			};
			return await Validate(validator, presented: [leaf, intermediate.Certificate]);
		}
	}

	// The trust anchor is not checked, not even a certificate that the peer presents as one.
	[Test]
	public async Task TheTrustAnchorIsNotChecked()
	{
		using Authority root = Authority.CreateRoot();
		using TrustAnchorCertificateValidator validator = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo) { RevocationMode = X509RevocationMode.Offline };
		Certificate leaf = root.IssueLeaf();

		await AssertValid(await Validate(validator, presented: [root.Certificate]), root.Certificate);
		await AssertInvalid(await Validate(validator, presented: [leaf]), [CertificateValidationError.RevocationUnknown], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
	}

	[Test]
	public async Task ADelegatedResponderIsAcceptedWithoutARevocationCheckOfItsOwn()
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf(more: [Aia(ocsp: [OcspUri])]);
		using CryptoBase.Signatures.Ecdsa.EcdsaP256 responderKey = CryptoBase.Signatures.Ecdsa.EcdsaP256.GenerateKey();
		Certificate responder = root.Issue
		(
			new Template
			{
				Subject = Name("CN=Responder"),
				SubjectPublicKeyInfo = Signatures.SignatureTestUtils.ExportSubjectPublicKeyInfo(responderKey),
				Extensions = [ExtendedKeyUsage(TestOcsp.OcspSigningOid)]
			}
		);
		byte[] response = new TestOcsp.Basic
		{
			ResponderId = TestOcsp.ResponderByKey(responder),
			Certificates = [Encoded(responder)],
			Responses =
			[
				new TestOcsp.SingleEntry
				{
					CertificateId = TestOcsp.CertificateIdOf(leaf, root.Certificate),
					Status = TestOcsp.Good
				}.Encode()
			]
		}.Encode(responderKey);
		FakeRetriever retriever = new() { Responder = response };
		using TrustAnchorCertificateValidator validator = Online(retriever, root.Certificate);

		await AssertValid(await Validate(validator, presented: [leaf]), leaf, root.Certificate);
	}

	// RFC 9919, Sec. 6: GET up to 255 bytes after encoding, and POST beyond; a query leaves GET no place for the request.
	[Test]
	public async Task AsksTheResponderByGetIfTheRequestIsShort()
	{
		using Authority root = Authority.CreateRoot();
		const string longUri = "http://ocsp.test/" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/";
		const string queryUri = "http://ocsp.test/check?a=b";
		Certificate leaf = root.IssueLeaf(more: [Aia(ocsp: [OcspUri])]);
		Certificate longLeaf = root.IssueLeaf(more: [Aia(ocsp: [longUri])]);
		Certificate queryLeaf = root.IssueLeaf(more: [Aia(ocsp: [queryUri])]);
		FakeRetriever retriever = new() { Responder = Ocsp(leaf, root, TestOcsp.Good) };
		FakeRetriever longRetriever = new() { Responder = Ocsp(longLeaf, root, TestOcsp.Good) };
		FakeRetriever queryRetriever = new() { Responder = Ocsp(queryLeaf, root, TestOcsp.Good) };
		using TrustAnchorCertificateValidator validator = Online(retriever, root.Certificate);
		using TrustAnchorCertificateValidator longValidator = Online(longRetriever, root.Certificate);
		using TrustAnchorCertificateValidator queryValidator = Online(queryRetriever, root.Certificate);

		await AssertValid(await Validate(validator, presented: [leaf]), leaf, root.Certificate);
		await AssertValid(await Validate(longValidator, presented: [longLeaf]), longLeaf, root.Certificate);
		await AssertValid(await Validate(queryValidator, presented: [queryLeaf]), queryLeaf, root.Certificate);

		FakeRetriever.Request get = retriever.Requests.Single();
		FakeRetriever.Request post = longRetriever.Requests.Single();
		OcspRequest expected = OcspRequest.Create(leaf, root.Certificate);
		string path = get.Uri.AbsoluteUri.Substring(OcspUri.Length);

		using (Assert.Multiple())
		{
			await Assert.That(get.Method).IsEqualTo("GET");
			await Assert.That(get.Uri.AbsoluteUri.Length).IsLessThanOrEqualTo(255);
			await Assert.That(Convert.FromBase64String(Uri.UnescapeDataString(path)).AsSpan().SequenceEqual(expected.Encoded.Span)).IsTrue();
			await Assert.That(post.Method).IsEqualTo("POST");
			await Assert.That(post.Uri.AbsoluteUri).IsEqualTo(longUri);
			await Assert.That(post.ContentType).IsEqualTo("application/ocsp-request");
			await Assert.That(post.Content?.AsSpan().SequenceEqual(OcspRequest.Create(longLeaf, root.Certificate).Encoded.Span)).IsTrue();
			await Assert.That(post.MaxLength).IsEqualTo(RetrievalBudget.MaxOcspResponseLength);
			await Assert.That(queryRetriever.Requests.Single().Method).IsEqualTo("POST");
			await Assert.That(queryRetriever.Requests.Single().Uri.AbsoluteUri).IsEqualTo(queryUri);
		}
	}

	// RFC 6960, Appendix A.1: {url}/{request}, with the URI of the responder kept whole and a slash added only if its path does not end with one, so that a path that ends with several keeps them.
	[Test]
	[Arguments("http://ocsp.test/status//", "http://ocsp.test/status//")]
	[Arguments("http://ocsp.test/ocsp/", "http://ocsp.test/ocsp/")]
	[Arguments("http://ocsp.test/ocsp", "http://ocsp.test/ocsp/")]
	[Arguments("http://ocsp.test", "http://ocsp.test/")]
	public async Task AppendsTheRequestToThePathOfTheResponder(string responder, string prefix)
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf(more: [Aia(ocsp: [responder])]);
		FakeRetriever retriever = new() { Responder = Ocsp(leaf, root, TestOcsp.Good) };
		using TrustAnchorCertificateValidator validator = Online(retriever, root.Certificate);

		await AssertValid(await Validate(validator, presented: [leaf]), leaf, root.Certificate);

		FakeRetriever.Request get = retriever.Requests.Single();
		string request = Uri.EscapeDataString(Convert.ToBase64String(OcspRequest.Create(leaf, root.Certificate).Encoded.Span));

		using (Assert.Multiple())
		{
			await Assert.That(get.Method).IsEqualTo("GET");
			await Assert.That(get.Uri.AbsoluteUri).IsEqualTo(prefix + request);
		}
	}

	// RFC 9919, Sec. 7.1: a response is kept once validated, until its nextUpdate; and so is a CRL.
	[Test]
	public async Task KeepsWhatItVerifiedUntilItsNextUpdate()
	{
		using Authority root = Authority.CreateRoot();
		Certificate withOcsp = root.IssueLeaf(more: [Aia(ocsp: [OcspUri])]);
		Certificate withCrl = root.IssueLeaf("CN=Other", more: [Cdp(CrlUri)]);
		FakeRetriever ocsp = new() { Responder = Ocsp(withOcsp, root, TestOcsp.Good, Now.AddHours(1)) };
		byte[] crlBody = (TestCrl.Conforming(root) with { NextUpdate = Time(Now.AddHours(1)) }).Encode(root);
		FakeRetriever crl = new() { [CrlUri] = crlBody };
		using TrustAnchorCertificateValidator ocspValidator = Online(ocsp, root.Certificate);
		using TrustAnchorCertificateValidator crlValidator = Online(crl, root.Certificate);
		MovingClock clock = new();

		using (Assert.Multiple())
		{
			await AssertValid(await Validate(ocspValidator, clock, presented: [withOcsp]), withOcsp, root.Certificate);
			await AssertValid(await Validate(ocspValidator, clock, presented: [withOcsp]), withOcsp, root.Certificate);
			await Assert.That(ocsp.Requests.Count).IsEqualTo(1);
			await AssertValid(await Validate(crlValidator, clock, presented: [withCrl]), withCrl, root.Certificate);
			await AssertValid(await Validate(crlValidator, clock, presented: [withCrl]), withCrl, root.Certificate);
			await Assert.That(crl.Requests.Count).IsEqualTo(1);

			clock.Time = Now.AddHours(2);
			ocsp.Responder = Ocsp(withOcsp, root, TestOcsp.Good, Now.AddHours(3));
			crl[CrlUri] = (TestCrl.Conforming(root) with { NextUpdate = Time(Now.AddHours(3)) }).Encode(root);
			await AssertValid(await Validate(ocspValidator, clock, presented: [withOcsp]), withOcsp, root.Certificate);
			await AssertValid(await Validate(crlValidator, clock, presented: [withCrl]), withCrl, root.Certificate);
			await Assert.That(ocsp.Requests.Count).IsEqualTo(2);
			await Assert.That(crl.Requests.Count).IsEqualTo(2);
		}
	}

	// What does not verify is retrieved again rather than kept: a bad copy must not hide the real one.
	[Test]
	public async Task DoesNotKeepWhatItDidNotVerify()
	{
		using Authority root = Authority.CreateRoot();
		using Authority other = Authority.CreateRoot("CN=Other");
		Certificate leaf = root.IssueLeaf(more: [Aia(ocsp: [OcspUri]), Cdp(CrlUri)]);
		byte[] signedByAnother = new TestOcsp.Basic
		{
			ResponderId = TestOcsp.ResponderByKey(root.Certificate),
			Responses =
			[
				new TestOcsp.SingleEntry
				{
					CertificateId = TestOcsp.CertificateIdOf(leaf, root.Certificate),
					Status = TestOcsp.Good
				}.Encode()
			]
		}.Encode(other.Key);
		byte[] crlOfAnother = TestCrl.Conforming(other) with { Issuer = root.Name } is var template ? template.Encode(other) : [];
		FakeRetriever retriever = new()
		{
			Responder = signedByAnother,
			[CrlUri] = crlOfAnother
		};
		using TrustAnchorCertificateValidator validator = Online(retriever, root.Certificate);

		for (int i = 0; i < 2; ++i)
		{
			await AssertInvalid(await Validate(validator, presented: [leaf]), [CertificateValidationError.RevocationUnknown], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
		}

		await Assert.That(retriever.Requests.Count).IsEqualTo(6);
	}

	// The URL of another CA's CRL answered once with the CA's own, which verifies: what is kept for it must not stand in for the real CRL of the CA whose URL it is.
	[Test]
	public async Task ACrlKeptForOneIssuerDoesNotHideTheCrlOfAnother()
	{
		const string url = "http://crl.victim.test/ca.crl";
		using Authority root = Authority.CreateRoot();
		using Authority victimCa = root.CreateIntermediate("CN=Victim CA");
		using Authority tenantCa = root.CreateIntermediate("CN=Tenant CA");
		Certificate tenantLeaf = tenantCa.IssueLeaf(more: [Cdp(url)]);
		Certificate victimLeaf = victimCa.IssueLeaf(more: [Cdp(url)]);
		byte[] tenantCrl = (TestCrl.Conforming(tenantCa) with { NextUpdate = Time(Now.AddYears(20)) }).Encode(tenantCa);
		byte[] victimRevokes = EncodeCrl(victimCa, victimLeaf);

		foreach (bool soft in (bool[])[false, true])
		{
			FakeRetriever retriever = new() { [url] = tenantCrl };
			using TrustAnchorCertificateValidator validator = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo)
			{
				Retriever = retriever,
				RevocationMode = X509RevocationMode.Online,
				RevocationFlag = X509RevocationFlag.EndCertificateOnly,
				IgnoreRevocationUnknown = soft
			};

			await AssertValid(await Validate(validator, presented: [tenantLeaf, tenantCa.Certificate]), tenantLeaf, tenantCa.Certificate, root.Certificate);

			retriever[url] = victimRevokes;

			using (Assert.Multiple())
			{
				await AssertInvalid(await Validate(validator, presented: [victimLeaf, victimCa.Certificate]), [CertificateValidationError.Revoked], CertificatePathEnd.TrustAnchor, victimLeaf, victimCa.Certificate, root.Certificate);
				await Assert.That(retriever.Requests.Count).IsEqualTo(2);

				// What was kept still serves the certificates of the CA that it was kept for.
				await AssertValid(await Validate(validator, presented: [tenantLeaf, tenantCa.Certificate]), tenantLeaf, tenantCa.Certificate, root.Certificate);
				await Assert.That(retriever.Requests.Count).IsEqualTo(2);
			}
		}
	}

	// As a kept CRL, issuers that a path used must not stand in for what the URI gives the certificates of another CA.
	[Test]
	public async Task IssuersKeptForOneCertificateDoNotHideThoseOfAnother()
	{
		const string url = "http://aia.victim.test/ca.cer";
		using Authority root = Authority.CreateRoot();
		using Authority victimCa = root.CreateIntermediate("CN=Victim CA");
		using Authority tenantCa = root.CreateIntermediate("CN=Tenant CA");
		Certificate tenantLeaf = tenantCa.IssueLeaf(more: [Aia(caIssuers: [url])]);
		Certificate victimLeaf = victimCa.IssueLeaf(more: [Aia(caIssuers: [url])]);
		FakeRetriever retriever = new() { [url] = Encoded(tenantCa.Certificate) };
		using TrustAnchorCertificateValidator validator = WithRetriever(retriever, root.Certificate);

		await AssertValid(await Validate(validator, presented: [tenantLeaf]), tenantLeaf, tenantCa.Certificate, root.Certificate);

		retriever[url] = Encoded(victimCa.Certificate);

		using (Assert.Multiple())
		{
			await AssertValid(await Validate(validator, presented: [victimLeaf]), victimLeaf, victimCa.Certificate, root.Certificate);
			await Assert.That(retriever.Requests.Count).IsEqualTo(2);
			await AssertValid(await Validate(validator, presented: [tenantLeaf]), tenantLeaf, tenantCa.Certificate, root.Certificate);
			await Assert.That(retriever.Requests.Count).IsEqualTo(2);
		}
	}

	// A certificate and its issuer name one URI, which gives each the CRL of its own issuer: what the first was given says nothing of the second.
	[Test]
	public async Task ACrlRetrievedForOneCertificateDoesNotHideTheOneForItsIssuer()
	{
		const string url = "http://crl.test/shared.crl";
		using Authority root = Authority.CreateRoot();
		using Authority intermediate = root.CreateIntermediate(more: [Cdp(url)]);
		Certificate leaf = intermediate.IssueLeaf(more: [Cdp(url)]);

		foreach (bool soft in (bool[])[false, true])
		{
			FakeRetriever retriever = new() { Turns = { [url] = new Queue<byte[]>([EncodeCrl(intermediate), EncodeCrl(root, intermediate.Certificate)]) } };
			using TrustAnchorCertificateValidator validator = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo)
			{
				Retriever = retriever,
				RevocationMode = X509RevocationMode.Online,
				IgnoreRevocationUnknown = soft
			};

			using (Assert.Multiple())
			{
				await AssertInvalid(await Validate(validator, presented: [leaf, intermediate.Certificate]), [CertificateValidationError.Revoked], CertificatePathEnd.TrustAnchor, leaf, intermediate.Certificate, root.Certificate);
				await Assert.That(retriever.Requests.Count).IsEqualTo(2);
			}
		}
	}

	// Two CAs of one name share a URI, which gave the CRL of the first: signed by another key, it says nothing of a certificate of the second, so that the one at the URI now decides, and replaces it.
	[Test]
	public async Task AKeptCrlOfAnotherKeyOfTheNameGivesWayToTheOneAtTheUri()
	{
		const string url = "http://crl.test/shared.crl";
		using Authority root = Authority.CreateRoot();
		using Authority first = root.CreateIntermediate("CN=Shared");
		using Authority second = root.CreateIntermediate("CN=Shared");
		Certificate firstLeaf = first.IssueLeaf(more: [Cdp(url)]);
		Certificate secondLeaf = second.IssueLeaf(more: [Cdp(url)]);
		byte[] firstCrl = EncodeCrl(first);
		byte[] secondRevokes = EncodeCrl(second, secondLeaf);

		foreach (bool soft in (bool[])[false, true])
		{
			FakeRetriever retriever = new() { [url] = firstCrl };
			using TrustAnchorCertificateValidator validator = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo)
			{
				Retriever = retriever,
				RevocationMode = X509RevocationMode.Online,
				RevocationFlag = X509RevocationFlag.EndCertificateOnly,
				IgnoreRevocationUnknown = soft
			};

			await AssertValid(await Validate(validator, presented: [firstLeaf, first.Certificate]), firstLeaf, first.Certificate, root.Certificate);

			retriever[url] = secondRevokes;

			using (Assert.Multiple())
			{
				await AssertInvalid(await Validate(validator, presented: [secondLeaf, second.Certificate]), [CertificateValidationError.Revoked], CertificatePathEnd.TrustAnchor, secondLeaf, second.Certificate, root.Certificate);
				await Assert.That(retriever.Requests.Count).IsEqualTo(2);
				await AssertInvalid(await Validate(validator, presented: [secondLeaf, second.Certificate]), [CertificateValidationError.Revoked], CertificatePathEnd.TrustAnchor, secondLeaf, second.Certificate, root.Certificate);
				await Assert.That(retriever.Requests.Count).IsEqualTo(2);
			}
		}
	}

	// A kept CRL that decides nothing costs one retrieval in a validation, even if the certificate names the URI twice and the retrieval fails.
	[Test]
	public async Task AKeptCrlThatDecidesNothingCostsOneRetrieval()
	{
		const string url = "http://crl.test/shared.crl";
		using Authority root = Authority.CreateRoot();
		using Authority first = root.CreateIntermediate("CN=Shared");
		using Authority second = root.CreateIntermediate("CN=Shared");
		Certificate firstLeaf = first.IssueLeaf(more: [Cdp(url)]);
		Certificate secondLeaf = second.IssueLeaf(more: [Cdp(url, url)]);
		FakeRetriever retriever = new() { [url] = EncodeCrl(first) };
		using TrustAnchorCertificateValidator validator = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo)
		{
			Retriever = retriever,
			RevocationMode = X509RevocationMode.Online,
			RevocationFlag = X509RevocationFlag.EndCertificateOnly
		};

		await AssertValid(await Validate(validator, presented: [firstLeaf, first.Certificate]), firstLeaf, first.Certificate, root.Certificate);

		retriever[url] = [0x30, 0x01];

		using (Assert.Multiple())
		{
			await AssertInvalid(await Validate(validator, presented: [secondLeaf, second.Certificate]), [CertificateValidationError.RevocationUnknown], CertificatePathEnd.TrustAnchor, secondLeaf, second.Certificate, root.Certificate);
			await Assert.That(retriever.Requests.Count).IsEqualTo(2);
		}
	}

	// One URI holds what two certificates of a chain need: each kept entry serves its own certificate, and neither retrieves anything.
	[Test]
	public async Task IssuersKeptUnderOneUriForTwoIssuersCompleteAPath()
	{
		const string url = "http://aia.test/ca.cer";
		using Authority root = Authority.CreateRoot();
		using Authority upper = root.CreateIntermediate("CN=Upper");
		using Authority lower = upper.CreateIntermediate("CN=Lower", more: [Aia(caIssuers: [url])]);
		Certificate leaf = lower.IssueLeaf(more: [Aia(caIssuers: [url])]);
		Certificate sibling = lower.IssueLeaf("CN=Sibling");
		FakeRetriever retriever = new() { [url] = Encoded(lower.Certificate) };
		using TrustAnchorCertificateValidator validator = WithRetriever(retriever, root.Certificate);

		await AssertValid(await Validate(validator, presented: [leaf, upper.Certificate]), leaf, lower.Certificate, upper.Certificate, root.Certificate);

		retriever[url] = Encoded(upper.Certificate);

		await AssertValid(await Validate(validator, presented: [sibling, lower.Certificate]), sibling, lower.Certificate, upper.Certificate, root.Certificate);

		retriever[url] = [];

		using (Assert.Multiple())
		{
			await AssertValid(await Validate(validator, presented: [leaf]), leaf, lower.Certificate, upper.Certificate, root.Certificate);
			await Assert.That(retriever.Requests.Count).IsEqualTo(2);
		}
	}

	// Two CAs of one name share a URI, which gave the first: its certificate does not verify the second's, whether or not it is already among those presented, so that what the URI gives now decides.
	[Test]
	public async Task KeptIssuersOfAnotherKeyOfTheNameGiveWayToThoseAtTheUri()
	{
		const string url = "http://aia.test/ca.cer";
		using Authority root = Authority.CreateRoot();
		using Authority first = root.CreateIntermediate("CN=Shared");
		using Authority second = root.CreateIntermediate("CN=Shared");
		Certificate firstLeaf = first.IssueLeaf(more: [Aia(caIssuers: [url])]);
		Certificate secondLeaf = second.IssueLeaf(more: [Aia(caIssuers: [url])]);

		foreach (Certificate[] presented in (Certificate[][])[[secondLeaf], [secondLeaf, first.Certificate]])
		{
			FakeRetriever retriever = new() { [url] = Encoded(first.Certificate) };
			using TrustAnchorCertificateValidator validator = WithRetriever(retriever, root.Certificate);

			await AssertValid(await Validate(validator, presented: [firstLeaf]), firstLeaf, first.Certificate, root.Certificate);

			retriever[url] = Encoded(second.Certificate);

			using (Assert.Multiple())
			{
				await AssertValid(await Validate(validator, presented: presented), secondLeaf, second.Certificate, root.Certificate);
				await Assert.That(retriever.Requests.Count).IsEqualTo(2);
			}
		}
	}

	// A kept certificate that the path cannot use, because the presented certificate is the same one, must not hide what the URI gives now.
	[Test]
	public async Task AKeptIssuerThatIsAlreadyPresentedDoesNotHideTheOneAtTheUri()
	{
		const string wanted = "1.3.6.1.4.1.55738.77.1";
		const string other = "1.3.6.1.4.1.55738.77.2";
		using Authority root = Authority.CreateRoot();
		using Authority intermediate = root.CreateIntermediate(more: [CertificatePolicies(other)]);
		byte[] subjectPublicKeyInfo = intermediate.Certificate.PublicKeyInfo.Encoded.ToArray();
		Certificate conforming = root.Issue
		(
			new Template
			{
				Subject = intermediate.Name,
				SubjectPublicKeyInfo = subjectPublicKeyInfo,
				Extensions = [.. CaExtensions(subjectPublicKeyInfo), AuthorityKeyIdentifier(root.KeyIdentifier), CertificatePolicies(wanted)]
			}
		);
		Certificate warmLeaf = intermediate.IssueLeaf("CN=Warm", more: [CertificatePolicies(other), Aia(caIssuers: [IssuerUri])]);
		Certificate leaf = intermediate.IssueLeaf(more: [CertificatePolicies(wanted), Aia(caIssuers: [IssuerUri])]);
		FakeRetriever retriever = new() { [IssuerUri] = Encoded(intermediate.Certificate) };
		using TrustAnchorCertificateValidator validator = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo)
		{
			Retriever = retriever,
			RequireExplicitPolicy = true,
			InitialPolicies = [wanted, other]
		};

		await AssertValid(await Validate(validator, presented: [warmLeaf]), warmLeaf, intermediate.Certificate, root.Certificate);

		retriever[IssuerUri] = Encoded(conforming);

		using (Assert.Multiple())
		{
			await AssertValid(await Validate(validator, presented: [leaf, intermediate.Certificate]), leaf, conforming, root.Certificate);
			await Assert.That(retriever.Requests.Count).IsEqualTo(2);
		}
	}

	// A certificate that claims the name of another CA, and that no path verifies, names a URI: what the URI gives is not kept for that name, nor for any other.
	[Test]
	public async Task DoesNotKeepWhatACertificateOffThePathRetrieved()
	{
		const string url = "http://aia.victim.test/ca.cer";
		using Authority root = Authority.CreateRoot();
		using Authority victimCa = root.CreateIntermediate("CN=Victim CA");
		using Authority tenantCa = root.CreateIntermediate("CN=Tenant CA");
		using Authority impostor = Authority.CreateRoot("CN=Victim CA");
		Certificate forged = impostor.IssueLeaf("CN=Forged", more: [Aia(caIssuers: [url])]);
		Certificate tenantLeaf = tenantCa.IssueLeaf();
		Certificate victimLeaf = victimCa.IssueLeaf(more: [Aia(caIssuers: [url])]);
		FakeRetriever retriever = new() { [url] = Encoded(tenantCa.Certificate) };
		using TrustAnchorCertificateValidator validator = WithRetriever(retriever, root.Certificate);

		using (Assert.Multiple())
		{
			await AssertValid(await Validate(validator, presented: [tenantLeaf, forged]), tenantLeaf, tenantCa.Certificate, root.Certificate);
			await Assert.That(retriever.Requests.Count).IsEqualTo(1);

			await AssertValid(await Validate(validator, presented: [tenantLeaf, forged]), tenantLeaf, tenantCa.Certificate, root.Certificate);
			await Assert.That(retriever.Requests.Count).IsEqualTo(2);

			retriever[url] = Encoded(victimCa.Certificate);

			await AssertValid(await Validate(validator, presented: [victimLeaf]), victimLeaf, victimCa.Certificate, root.Certificate);
			await Assert.That(retriever.Requests.Count).IsEqualTo(3);
		}
	}

	// Anyone on the path of a plain http URI can add certificates to what it gives. Only the issuer that a path verified is kept, so that what was added does not fill, in a later validation, the room for the retrieved certificates that it needs.
	[Test]
	public async Task KeepsOnlyTheIssuerThatAPathVerifiedOfWhatAUriGave()
	{
		const string lowerUri = "http://ca.test/lower.p7c";
		const string middleUri = "http://ca.test/middle.p7c";
		const string upperUri = "http://ca.test/upper.cer";
		using Authority root = Authority.CreateRoot();
		using Authority upper = root.CreateIntermediate("CN=Upper");
		using Authority middle = upper.CreateIntermediate("CN=Middle", more: [Aia(caIssuers: [upperUri])]);
		using Authority lower = middle.CreateIntermediate("CN=Lower", more: [Aia(caIssuers: [middleUri])]);
		Certificate leaf = lower.IssueLeaf(more: [Aia(caIssuers: [lowerUri])]);

		// Each message fills half the room, so that two kept whole would fill it.
		byte[] Padded(Authority issuer)
		{
			return CertsOnly([Encoded(issuer.Certificate), .. Enumerable.Range(1, RetrievalBudget.MaxRetrievedIssuers / 2 - 1).Select(i => Encoded(root.IssueLeaf($"CN=Added {i}")))]);
		}

		FakeRetriever retriever = new()
		{
			[lowerUri] = Padded(lower),
			[middleUri] = Padded(middle),
			[upperUri] = Encoded(upper.Certificate)
		};
		using TrustAnchorCertificateValidator validator = WithRetriever(retriever, root.Certificate);

		await AssertValid(await Validate(validator, presented: [leaf, middle.Certificate, upper.Certificate]), leaf, lower.Certificate, middle.Certificate, upper.Certificate, root.Certificate);
		await AssertValid(await Validate(validator, presented: [lower.Certificate, upper.Certificate]), lower.Certificate, middle.Certificate, upper.Certificate, root.Certificate);

		using (Assert.Multiple())
		{
			await AssertValid(await Validate(validator, presented: [leaf]), leaf, lower.Certificate, middle.Certificate, upper.Certificate, root.Certificate);
			await Assert.That(retriever.Requests.Select(static request => request.Uri.AbsoluteUri)).IsEquivalentTo((string[])[lowerUri, middleUri, upperUri], CollectionOrdering.Matching);
		}
	}

	// A URI that gives the issuer with the certificates above it, which name no URI of their own, is retrieved once: every certificate of the message that the path used is kept.
	[Test]
	public async Task KeepsEveryCertificateThatAPathUsedOfWhatAUriGave()
	{
		using Authority root = Authority.CreateRoot();
		using Authority intermediate = root.CreateIntermediate();
		using Authority subCa = intermediate.CreateIntermediate("CN=Sub CA");
		Certificate leaf = subCa.IssueLeaf(more: [Aia(caIssuers: [IssuerUri])]);
		FakeRetriever retriever = new() { [IssuerUri] = CertsOnly(Encoded(subCa.Certificate), Encoded(intermediate.Certificate)) };
		using TrustAnchorCertificateValidator validator = WithRetriever(retriever, root.Certificate);

		using (Assert.Multiple())
		{
			await AssertValid(await Validate(validator, presented: [leaf]), leaf, subCa.Certificate, intermediate.Certificate, root.Certificate);
			await AssertValid(await Validate(validator, presented: [leaf]), leaf, subCa.Certificate, intermediate.Certificate, root.Certificate);
			await Assert.That(retriever.Requests.Count).IsEqualTo(1);
		}
	}

	// A URI can give the certificate of a new key of the issuer, which the old key issues, with the old key's own certificate: both are kept.
	[Test]
	public async Task KeepsTheCertificatesOfAKeyRolloverThatAUriGave()
	{
		using Authority root = Authority.CreateRoot();
		using Authority oldKey = root.CreateIntermediate("CN=CA");
		using Authority newKey = oldKey.CreateIntermediate("CN=CA");
		Certificate leaf = newKey.IssueLeaf(more: [Aia(caIssuers: [IssuerUri])]);
		FakeRetriever retriever = new() { [IssuerUri] = CertsOnly(Encoded(newKey.Certificate), Encoded(oldKey.Certificate)) };
		using TrustAnchorCertificateValidator validator = WithRetriever(retriever, root.Certificate);

		using (Assert.Multiple())
		{
			await AssertValid(await Validate(validator, presented: [leaf]), leaf, newKey.Certificate, oldKey.Certificate, root.Certificate);
			await AssertValid(await Validate(validator, presented: [leaf]), leaf, newKey.Certificate, oldKey.Certificate, root.Certificate);
			await Assert.That(retriever.Requests.Count).IsEqualTo(1);
		}
	}

	// A certificate that the URI gave is kept though the peer presented it too, so that a validation without it need not retrieve the URI again.
	[Test]
	public async Task KeepsWhatAUriGaveThatThePeerAlsoPresented()
	{
		using Authority root = Authority.CreateRoot();
		using Authority intermediate = root.CreateIntermediate();
		using Authority subCa = intermediate.CreateIntermediate("CN=Sub CA");
		Certificate leaf = subCa.IssueLeaf(more: [Aia(caIssuers: [IssuerUri])]);
		FakeRetriever retriever = new() { [IssuerUri] = CertsOnly(Encoded(subCa.Certificate), Encoded(intermediate.Certificate)) };
		using TrustAnchorCertificateValidator validator = WithRetriever(retriever, root.Certificate);

		using (Assert.Multiple())
		{
			await AssertValid(await Validate(validator, presented: [leaf, subCa.Certificate]), leaf, subCa.Certificate, intermediate.Certificate, root.Certificate);
			await AssertValid(await Validate(validator, presented: [leaf]), leaf, subCa.Certificate, intermediate.Certificate, root.Certificate);
			await AssertValid(await Validate(validator, presented: [leaf, subCa.Certificate]), leaf, subCa.Certificate, intermediate.Certificate, root.Certificate);
			await Assert.That(retriever.Requests.Count).IsEqualTo(1);
		}
	}

	// Of a message that the path used several certificates of, those that it did not use are still not kept: a certificate of another key of the name, which the URI gave too, takes a retrieval.
	[Test]
	public async Task DoesNotKeepWhatAUriGaveBesidesThePath()
	{
		using Authority root = Authority.CreateRoot();
		using Authority intermediate = root.CreateIntermediate();
		using Authority subCa = intermediate.CreateIntermediate("CN=Sub CA");
		using Authority otherKey = intermediate.CreateIntermediate("CN=Sub CA");
		Certificate leaf = subCa.IssueLeaf(more: [Aia(caIssuers: [IssuerUri])]);
		Certificate otherLeaf = otherKey.IssueLeaf("CN=Other", more: [Aia(caIssuers: [IssuerUri])]);
		FakeRetriever retriever = new() { [IssuerUri] = CertsOnly(Encoded(subCa.Certificate), Encoded(intermediate.Certificate), Encoded(otherKey.Certificate), Encoded(root.IssueLeaf("CN=Added"))) };
		using TrustAnchorCertificateValidator validator = WithRetriever(retriever, root.Certificate);

		using (Assert.Multiple())
		{
			await AssertValid(await Validate(validator, presented: [leaf]), leaf, subCa.Certificate, intermediate.Certificate, root.Certificate);
			await AssertValid(await Validate(validator, presented: [otherLeaf]), otherLeaf, otherKey.Certificate, intermediate.Certificate, root.Certificate);
			await Assert.That(retriever.Requests.Count).IsEqualTo(2);
		}
	}

	// A signature is verified once for each key of the issuer, however many validations use the CRL.
	[Test]
	public async Task VerifiesTheSignatureOfACrlOnce()
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf();
		KeyLog log = new();
		using TrustAnchorCertificateValidator validator = new([root.Certificate], log.Import)
		{
			RevocationMode = X509RevocationMode.Offline,
			RevocationLists = [DecodeCrl(root)]
		};

		await AssertValid(await Validate(validator, presented: [leaf]), leaf, root.Certificate);
		int first = log.Verifications;
		await AssertValid(await Validate(validator, presented: [leaf]), leaf, root.Certificate);

		// Each validation verifies the leaf; only the first also verifies the CRL.
		await Assert.That(log.Verifications).IsEqualTo(first + 1);
	}

	[Test]
	public async Task RetrievesNothingOnceTheDeadlineHasPassed()
	{
		using Authority root = Authority.CreateRoot();
		using Authority intermediate = root.CreateIntermediate();
		Certificate needsIssuer = intermediate.IssueLeaf(more: [Aia(caIssuers: [IssuerUri])]);
		Certificate needsRevocation = root.IssueLeaf(more: [Aia(ocsp: [OcspUri]), Cdp(CrlUri)]);
		FakeRetriever retriever = new()
		{
			[IssuerUri] = Encoded(intermediate.Certificate),
			Responder = Ocsp(needsRevocation, root, TestOcsp.Good)
		};
		using TrustAnchorCertificateValidator validator = Online(retriever, root.Certificate);
		using TrustAnchorCertificateValidator soft = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo)
		{
			Retriever = retriever,
			RevocationMode = X509RevocationMode.Online,
			IgnoreRevocationUnknown = true
		};

		using (Assert.Multiple())
		{
			await AssertInvalid(await Validate(validator, deadline: Now.AddSeconds(-1), presented: [needsIssuer]), [CertificateValidationError.UntrustedRoot], CertificatePathEnd.MissingIssuer, needsIssuer);
			await AssertInvalid(await Validate(validator, deadline: Now, presented: [needsRevocation]), [CertificateValidationError.RevocationUnknown], CertificatePathEnd.TrustAnchor, needsRevocation, root.Certificate);
			await AssertValid(await Validate(soft, deadline: Now.AddTicks(TimeSpan.TicksPerMillisecond - 1), presented: [needsRevocation]), needsRevocation, root.Certificate);
			await Assert.That(retriever.Requests).IsEmpty();
		}
	}

	// The retrieval is canceled at the deadline; what that retrieval would have told is then unknown.
	[Test]
	public async Task CancelsARetrievalAtTheDeadline()
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf(more: [Aia(ocsp: [OcspUri]), Cdp(CrlUri)]);
		CancellationToken observed = default;
		FakeRetriever retriever = new()
		{
			Hook = async (_, token) =>
			{
				observed = token;
				await Task.Delay(Timeout.Infinite, token);
			}
		};
		using TrustAnchorCertificateValidator validator = Online(retriever, root.Certificate);

		CertificateValidationResult result = await Validate(validator, deadline: Now.AddMilliseconds(50), presented: [leaf]);

		using (Assert.Multiple())
		{
			await AssertInvalid(result, [CertificateValidationError.RevocationUnknown], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
			await Assert.That(observed.CanBeCanceled).IsTrue();
			await Assert.That(retriever.Requests.Count).IsEqualTo(2);
		}
	}

	[Test]
	public async Task HonorsCancellationDuringARetrieval()
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf(more: [Aia(ocsp: [OcspUri])]);
		using CancellationTokenSource source = new();
		FakeRetriever retriever = new()
		{
			Hook = async (_, token) =>
			{
				await source.CancelAsync();
				await Task.Delay(Timeout.Infinite, token);
			}
		};
		using TrustAnchorCertificateValidator validator = Online(retriever, root.Certificate);

		await Assert.That(async () => await Validate(validator, cancellationToken: source.Token, presented: [leaf])).Throws<OperationCanceledException>();
	}

	// A timer cannot be as long as any deadline, so that one beyond what it can be waits for as long as it can; the retrieval then learns nothing, as at the deadline.
	[Test]
	public async Task CancelsARetrievalBeforeADeadlineBeyondTheLongestTimer()
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf(more: [Aia(ocsp: [OcspUri])]);
		TaskCompletionSource started = new(TaskCreationOptions.RunContinuationsAsynchronously);
		FakeRetriever retriever = new()
		{
			Hook = async (_, token) =>
			{
				if (started.TrySetResult())
				{
					await Task.Delay(Timeout.Infinite, token);
				}
			}
		};
		using TrustAnchorCertificateValidator validator = Online(retriever, root.Certificate);
		ManualTimers clock = new();
		using CancellationTokenSource abandon = new();

		try
		{
			Task<CertificateValidationResult> validation = Validate(validator, clock, Now.AddDays(40), cancellationToken: abandon.Token, presented: [leaf]);
			await started.Task.WaitAsync(TimeSpan.FromSeconds(10));
			clock.Advance(TimeSpan.FromDays(30));

			await AssertInvalid(await validation.WaitAsync(TimeSpan.FromSeconds(10)), [CertificateValidationError.RevocationUnknown], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
		}
		finally
		{
			await abandon.CancelAsync();
		}
	}

	// Only the cancellation of the validation throws; the retriever's own, such as a timeout, is a failed source.
	[Test]
	public async Task ARetrieversOwnCancellationIsAFailedRetrieval()
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf(more: [Aia(ocsp: [OcspUri])]);
		FakeRetriever retriever = new() { Hook = static (_, _) => throw new TaskCanceledException() };
		using TrustAnchorCertificateValidator validator = Online(retriever, root.Certificate);

		await AssertInvalid(await Validate(validator, presented: [leaf]), [CertificateValidationError.RevocationUnknown], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
	}

	// The contract is that a failure returns empty, so any other exception of a retriever is a defect that escapes.
	[Test]
	public async Task OtherExceptionsOfARetrieverEscape()
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf(more: [Aia(ocsp: [OcspUri])]);
		FakeRetriever retriever = new() { Hook = static (_, _) => throw new InvalidOperationException("A defect.") };
		using TrustAnchorCertificateValidator validator = Online(retriever, root.Certificate);

		await Assert.That(async () => await Validate(validator, presented: [leaf])).ThrowsExactly<InvalidOperationException>();
	}

	// One instance serves concurrent validations, which share the caches.
	[Test]
	public async Task RetrievesConcurrently()
	{
		using Authority root = Authority.CreateRoot();
		using Authority intermediate = root.CreateIntermediate();
		Certificate leaf = intermediate.IssueLeaf(more: [Aia(caIssuers: [IssuerUri], ocsp: [OcspUri]), Cdp(CrlUri)]);
		FakeRetriever retriever = new()
		{
			[IssuerUri] = Encoded(intermediate.Certificate),
			Responder = Ocsp(leaf, intermediate, TestOcsp.Good),
			Hook = static async (_, _) => await Task.Yield()
		};
		using TrustAnchorCertificateValidator validator = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo)
		{
			Retriever = retriever,
			RevocationMode = X509RevocationMode.Online,
			RevocationFlag = X509RevocationFlag.EndCertificateOnly
		};
		ConcurrentBag<CertificateValidationResult> results = [];

		await Parallel.ForEachAsync(Enumerable.Range(0, 64), new ParallelOptions { MaxDegreeOfParallelism = 16 }, async (_, _) => results.Add(await Validate(validator, presented: [leaf])));

		using (Assert.Multiple())
		{
			await Assert.That(results.Count).IsEqualTo(64);
			await Assert.That(results.All(static result => result.IsValid)).IsTrue();
		}
	}

	// RFC 5280, Sec. 4.2.1.13, leaves the criticality of the extension to the CA, and Sec. 4.2.2.1 forbids a critical authority information access extension.
	[Test]
	public async Task ACriticalDistributionPointsExtensionIsAccepted()
	{
		using Authority root = Authority.CreateRoot();
		CertificateExtension critical = new(TestCrl.CrlDistributionPointsOid, true, Cdp(CrlUri).Value.Span);
		Certificate leaf = root.IssueLeaf(more: [critical]);
		Certificate malformed = root.IssueLeaf(more: [new CertificateExtension(TestCrl.CrlDistributionPointsOid, true, new byte[] { 0x05, 0x00 })]);
		Certificate criticalAccess = root.IssueLeaf(more: [Aia(ocsp: [OcspUri], critical: true)]);
		FakeRetriever retriever = new() { [CrlUri] = EncodeCrl(root) };
		using TrustAnchorCertificateValidator none = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo);
		using TrustAnchorCertificateValidator online = Online(retriever, root.Certificate);

		using (Assert.Multiple())
		{
			await AssertValid(await Validate(none, presented: [leaf]), leaf, root.Certificate);
			await AssertValid(await Validate(online, presented: [leaf]), leaf, root.Certificate);
			await AssertInvalid(await Validate(none, presented: [malformed]), [CertificateValidationError.Malformed], CertificatePathEnd.TrustAnchor, malformed, root.Certificate);
			await AssertInvalid(await Validate(none, presented: [criticalAccess]), [CertificateValidationError.NotValidForUsage], CertificatePathEnd.TrustAnchor, criticalAccess, root.Certificate);
		}
	}

	// An extension that the validator reads only for retrieval names nothing if it is malformed.
	[Test]
	public async Task AMalformedExtensionNamesNothingToRetrieve()
	{
		using Authority root = Authority.CreateRoot();
		using Authority intermediate = root.CreateIntermediate();
		CertificateExtension malformedAccess = new("1.3.6.1.5.5.7.1.1", false, new byte[] { 0x05, 0x00 });
		CertificateExtension malformedPoints = new(TestCrl.CrlDistributionPointsOid, false, new byte[] { 0x05, 0x00 });
		Certificate noIssuer = intermediate.IssueLeaf(more: [malformedAccess]);
		Certificate noRevocation = root.IssueLeaf(more: [malformedAccess, malformedPoints]);
		FakeRetriever retriever = new();
		using TrustAnchorCertificateValidator validator = Online(retriever, root.Certificate);

		using (Assert.Multiple())
		{
			await AssertInvalid(await Validate(validator, presented: [noIssuer]), [CertificateValidationError.UntrustedRoot], CertificatePathEnd.MissingIssuer, noIssuer);
			await AssertInvalid(await Validate(validator, presented: [noRevocation]), [CertificateValidationError.RevocationUnknown], CertificatePathEnd.TrustAnchor, noRevocation, root.Certificate);
			await Assert.That(retriever.Requests).IsEmpty();
		}
	}

	// A certs-only message may hold other kinds of certificates, and its size is limited in elements, as each that does not decode is costly.
	[Test]
	public async Task ReadsCertsOnlyMessages()
	{
		using Authority root = Authority.CreateRoot();
		byte[] certificate = Encoded(root.IssueLeaf());
		byte[] attributeCertificate = Tlv(0xA1, Sequence());
		byte[] notACertificate = Sequence(Sequence());
		byte[][] atTheLimit = [.. Enumerable.Repeat(notACertificate, RetrievalBudget.MaxCertificatesPerRetrieval - 1), certificate];
		byte[][] overTheLimit = [.. Enumerable.Repeat(notACertificate, RetrievalBudget.MaxCertificatesPerRetrieval), certificate];
		byte[] wrongContent = Sequence(Oid("1.2.840.113549.1.7.1"), Tlv(0xA0, Sequence()));
		byte[] noCertificates = Sequence(Oid("1.2.840.113549.1.7.2"), Tlv(0xA0, Sequence([0x02, 0x01, 0x01], Tlv(0x31), Sequence(Oid("1.2.840.113549.1.7.1")), Tlv(0x31))));

		using (Assert.Multiple())
		{
			await Assert.That(Read(certificate)?.Length).IsEqualTo(1);
			await Assert.That(Read(CertsOnly(attributeCertificate, certificate, notACertificate))?.Length).IsEqualTo(1);
			await Assert.That(Read(CertsOnlyIndefinite(certificate))?.Length).IsEqualTo(1);
			await Assert.That(Read(CertsOnly(atTheLimit))?.Length).IsEqualTo(1);
			await Assert.That(Read(CertsOnly(overTheLimit))).IsNull();
			await Assert.That(Read(CertsOnly(notACertificate))).IsNull();
			await Assert.That(Read(wrongContent)).IsNull();
			await Assert.That(Read(noCertificates)).IsNull();
			await Assert.That(Read([.. certificate, 0x00])).IsNull();
			await Assert.That(Read([])).IsNull();
			await Assert.That(Read([0x30, 0x00])).IsNull();
		}

		static Certificate[]? Read(byte[] data)
		{
			return RetrievedCertificates.Read(data, RetrievalBudget.MaxCertificatesPerRetrieval);
		}
	}

	[Test]
	public async Task TheCacheIsBoundedInEntriesAndBytes()
	{
		RetrievalCache<string, string> entries = new(2, 1000, StringComparer.Ordinal);
		entries.Add("late", "A", 1, Now.AddHours(3), Now);
		entries.Add("early", "B", 1, Now.AddHours(1), Now);
		entries.Add("middle", "C", 1, Now.AddHours(2), Now);

		RetrievalCache<string, string> bytes = new(16, 20, StringComparer.Ordinal);
		bytes.Add("a", "A", 15, Now.AddHours(1), Now);
		bytes.Add("b", "B", 15, Now.AddHours(2), Now);

		RetrievalCache<string, string> rules = new(16, 20, StringComparer.Ordinal);
		rules.Add("expired", "A", 1, Now, Now);
		rules.Add("long", "B", 21, Now.AddHours(1), Now);
		rules.Add("kept", "C", 1, Now.AddHours(1), Now);
		rules.Add("kept", "D", 1, Now.AddHours(1), Now);

		using (Assert.Multiple())
		{
			await Assert.That(entries.TryGet("early", Now, out _)).IsFalse();
			await Assert.That(entries.TryGet("late", Now, out _)).IsTrue();
			await Assert.That(entries.TryGet("middle", Now, out _)).IsTrue();
			await Assert.That(bytes.TryGet("a", Now, out _)).IsFalse();
			await Assert.That(bytes.TryGet("b", Now, out _)).IsTrue();
			await Assert.That(rules.TryGet("expired", Now, out _)).IsFalse();
			await Assert.That(rules.TryGet("long", Now, out _)).IsFalse();
			await Assert.That(rules.TryGet("kept", Now, out string? value)).IsTrue();
			await Assert.That(value).IsEqualTo("D");
			await Assert.That(rules.TryGet("kept", Now.AddHours(1), out _)).IsFalse();
			await Assert.That(rules.TryGet("kept", Now, out _)).IsFalse();
		}
	}

	[Test]
	public async Task HttpRetrieverReturnsTheBody()
	{
		byte[] body = new byte[10_000];
		Random.Shared.NextBytes(body);
		using HttpClient declared = new(new StubHandler(_ => new HttpResponseMessage { Content = new StreamContent(new MemoryStream(body)) }));
		using HttpClient undeclared = new(new StubHandler(_ => new HttpResponseMessage { Content = new StreamContent(new CountingStream(body)) }));

		// Exactly at the limit, with a declared length and without one, whose buffer grows.
		ReadOnlyMemory<byte> first = await new HttpCertificateDataRetriever(declared).GetAsync(new Uri(IssuerUri), body.Length, default);
		ReadOnlyMemory<byte> second = await new HttpCertificateDataRetriever(undeclared).GetAsync(new Uri(IssuerUri), body.Length, default);

		using (Assert.Multiple())
		{
			await Assert.That(first.Span.SequenceEqual(body)).IsTrue();
			await Assert.That(second.Span.SequenceEqual(body)).IsTrue();
		}
	}

	[Test]
	public async Task HttpRetrieverPostsTheContent()
	{
		string? mediaType = null;
		byte[]? posted = null;
		HttpMethod? method = null;
		using HttpClient client = new
		(
			new StubHandler
			(request =>
				{
					method = request.Method;
					mediaType = request.Content?.Headers.ContentType?.MediaType;
					posted = request.Content?.ReadAsByteArrayAsync().GetAwaiter().GetResult();
					return new HttpResponseMessage { Content = new ByteArrayContent([1, 2, 3]) };
				}
			)
		);
		HttpCertificateDataRetriever retriever = new(client);

		ReadOnlyMemory<byte> response = await retriever.PostAsync(new Uri(OcspUri), new byte[] { 9, 8 }, "application/ocsp-request", 16, default);

		using (Assert.Multiple())
		{
			await Assert.That(response.ToArray()).IsEquivalentTo(new byte[] { 1, 2, 3 }, CollectionOrdering.Matching);
			await Assert.That(method).IsEqualTo(HttpMethod.Post);
			await Assert.That(mediaType).IsEqualTo("application/ocsp-request");
			await Assert.That(posted).IsEquivalentTo(new byte[] { 9, 8 }, CollectionOrdering.Matching);
		}
	}

	// A body longer than the limit fails, read only as far as one byte beyond it, with a declared length or not.
	[Test]
	public async Task HttpRetrieverFailsPastTheLimit()
	{
		CountingStream undeclared = new(new byte[1 << 20]);
		CountingStream declared = new(new byte[1 << 20]);
		using HttpClient undeclaredClient = new(new StubHandler(_ => new HttpResponseMessage { Content = new StreamContent(undeclared) }));
		using HttpClient declaredClient = new
		(
			new StubHandler
			(_ =>
				{
					StreamContent content = new(declared);
					content.Headers.ContentLength = 1 << 20;
					return new HttpResponseMessage { Content = content };
				}
			)
		);

		ReadOnlyMemory<byte> first = await new HttpCertificateDataRetriever(undeclaredClient).GetAsync(new Uri(IssuerUri), 1024, default);
		ReadOnlyMemory<byte> second = await new HttpCertificateDataRetriever(declaredClient).GetAsync(new Uri(IssuerUri), 1024, default);

		using (Assert.Multiple())
		{
			await Assert.That(first.IsEmpty).IsTrue();
			await Assert.That(second.IsEmpty).IsTrue();
			await Assert.That(undeclared.Consumed).IsEqualTo(1025);
			await Assert.That(declared.Consumed).IsEqualTo(0);
		}
	}

	// A limit beyond the longest array: a body that fills the longest buffer is whole only if nothing follows it, and fails otherwise rather than give its prefix.
	[Test]
	[Arguments(5000, false)]
	[Arguments(5000, true)]
	[Arguments(5001, false)]
	[Arguments(5001, true)]
	public async Task HttpRetrieverFailsPastTheLongestArray(int length, bool declared)
	{
		const int capacityLimit = 5000;
		byte[] body = new byte[length];
		Random.Shared.NextBytes(body);
		CountingStream stream = new(body);

		ReadOnlyMemory<byte> read = await HttpCertificateDataRetriever.ReadBodyAsync(stream, declared ? length : null, int.MaxValue, capacityLimit, default);

		using (Assert.Multiple())
		{
			await Assert.That(length <= capacityLimit ? read.Span.SequenceEqual(body) : read.IsEmpty).IsTrue();
			await Assert.That(stream.Consumed).IsEqualTo(Math.Min(length, capacityLimit + 1));
		}
	}

	[Test]
	public async Task HttpRetrieverGivesEmptyForFailures()
	{
		using HttpClient notFound = new(new StubHandler(static _ => new HttpResponseMessage(System.Net.HttpStatusCode.NotFound) { Content = new ByteArrayContent([1]) }));
		using HttpClient failing = new(new StubHandler(static _ => throw new HttpRequestException("Refused.")));
		using HttpClient timedOut = new(new StubHandler(static _ => throw new TaskCanceledException()));
		using HttpClient noCalls = new(new StubHandler(static _ => throw new InvalidOperationException("Called.")));

		using (Assert.Multiple())
		{
			await Assert.That((await new HttpCertificateDataRetriever(notFound).GetAsync(new Uri(IssuerUri), 16, default)).IsEmpty).IsTrue();
			await Assert.That((await new HttpCertificateDataRetriever(failing).GetAsync(new Uri(IssuerUri), 16, default)).IsEmpty).IsTrue();
			await Assert.That((await new HttpCertificateDataRetriever(timedOut).GetAsync(new Uri(IssuerUri), 16, default)).IsEmpty).IsTrue();
			await Assert.That((await new HttpCertificateDataRetriever(noCalls).GetAsync(new Uri("ftp://ca.test/ca.cer"), 16, default)).IsEmpty).IsTrue();
			await Assert.That((await new HttpCertificateDataRetriever(noCalls).PostAsync(new Uri("ldap://ca.test/"), new byte[] { 1 }, "application/ocsp-request", 16, default)).IsEmpty).IsTrue();
		}
	}

	[Test]
	public async Task HttpRetrieverHonorsCancellation()
	{
		using CancellationTokenSource source = new();
		await source.CancelAsync();
		using HttpClient client = new(new StubHandler(static _ => new HttpResponseMessage { Content = new ByteArrayContent([1]) }));
		HttpCertificateDataRetriever retriever = new(client);

		await Assert.That(async () => await retriever.GetAsync(new Uri(IssuerUri), 16, source.Token)).Throws<OperationCanceledException>();
	}

	// The headers arrive and the body never does: the timeout of the client applies to the whole retrieval, and gives an empty value.
	[Test]
	public async Task HttpRetrieverTimesOutOnABodyThatDoesNotArrive()
	{
		using HttpClient client = new(new StubHandler(static _ => new HttpResponseMessage { Content = new StreamContent(new StalledStream()) }));
		client.Timeout = TimeSpan.FromMilliseconds(100);
		HttpCertificateDataRetriever retriever = new(client);

		Task<ReadOnlyMemory<byte>> retrieval = retriever.GetAsync(new Uri(IssuerUri), 16, default).AsTask();
		Task finished = await Task.WhenAny(retrieval, Task.Delay(TimeSpan.FromSeconds(10)));

		using (Assert.Multiple())
		{
			await Assert.That(finished == retrieval).IsTrue();
			await Assert.That(retrieval.IsCompletedSuccessfully && retrieval.Result.IsEmpty).IsTrue();
		}
	}

	// A timeout of no limit sets none, and the caller's token still ends the retrieval of a body, which only it throws for.
	[Test]
	public async Task HttpRetrieverHonorsCancellationDuringTheBody()
	{
		using HttpClient client = new(new StubHandler(static _ => new HttpResponseMessage { Content = new StreamContent(new StalledStream()) }));
		client.Timeout = Timeout.InfiniteTimeSpan;
		HttpCertificateDataRetriever retriever = new(client);
		using CancellationTokenSource source = new();

		Task<ReadOnlyMemory<byte>> retrieval = retriever.GetAsync(new Uri(IssuerUri), 16, source.Token).AsTask();
		await source.CancelAsync();

		await Assert.That(async () => await retrieval).Throws<OperationCanceledException>();
	}

	[Test]
	public async Task HttpRetrieverChecksItsArguments()
	{
		using HttpClient client = new(new StubHandler(static _ => new HttpResponseMessage()));
		HttpCertificateDataRetriever retriever = new(client);

		using (Assert.Multiple())
		{
			await Assert.That(() => new HttpCertificateDataRetriever(null!)).ThrowsExactly<ArgumentNullException>();
			await Assert.That(async () => await retriever.GetAsync(null!, 1, default)).ThrowsExactly<ArgumentNullException>();
			await Assert.That(async () => await retriever.GetAsync(new Uri(IssuerUri), 0, default)).ThrowsExactly<ArgumentOutOfRangeException>();
			await Assert.That(async () => await retriever.PostAsync(new Uri(IssuerUri), default, "not a media type", 1, default)).Throws<FormatException>();
		}
	}

	// RFC 9608, Sec. 4: no source is needed for a certificate with either extension, and none is asked.
	[Test]
	[Arguments(NoRevAvailOid, X509RevocationMode.Online)]
	[Arguments(NoRevAvailOid, X509RevocationMode.Offline)]
	[Arguments(OcspNoCheckOid, X509RevocationMode.Online)]
	[Arguments(OcspNoCheckOid, X509RevocationMode.Offline)]
	public async Task SkipsTheRevocationCheckOfACertificateThatExemptsItself(string oid, X509RevocationMode mode)
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf(more: [NullExtension(oid)]);
		FakeRetriever retriever = new();
		using TrustAnchorCertificateValidator validator = Checking(mode, retriever, root.Certificate);

		await AssertValid(await Validate(validator, presented: [leaf]), leaf, root.Certificate);
		await Assert.That(retriever.Requests).IsEmpty();
	}

	[Test]
	[Arguments(X509RevocationMode.Online)]
	[Arguments(X509RevocationMode.Offline)]
	public async Task AStatusOfACertificateWithoutAnExemptionStaysUnknown(X509RevocationMode mode)
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf();
		using TrustAnchorCertificateValidator validator = Checking(mode, new FakeRetriever(), root.Certificate);

		await AssertInvalid(await Validate(validator, presented: [leaf]), [CertificateValidationError.RevocationUnknown], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
	}

	// RFC 9608, Sec. 6: all revocation checking is bypassed, so a CRL that lists the certificate does not count.
	[Test]
	[Arguments(NoRevAvailOid, X509RevocationMode.Online)]
	[Arguments(NoRevAvailOid, X509RevocationMode.Offline)]
	[Arguments(OcspNoCheckOid, X509RevocationMode.Online)]
	[Arguments(OcspNoCheckOid, X509RevocationMode.Offline)]
	public async Task IgnoresARevocationListThatNamesAnExemptCertificate(string oid, X509RevocationMode mode)
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf(more: [NullExtension(oid)]);
		FakeRetriever retriever = new();
		using TrustAnchorCertificateValidator validator = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo)
		{
			Retriever = retriever,
			RevocationMode = mode,
			RevocationLists = [DecodeCrl(root, leaf)]
		};

		await AssertValid(await Validate(validator, presented: [leaf]), leaf, root.Certificate);
		await Assert.That(retriever.Requests).IsEmpty();
	}

	// The rules of RFC 9608, Sec. 3, are for noRevAvail alone: ocsp-nocheck may come with locations, which are then not used.
	[Test]
	public async Task AsksNoSourceThatAnOcspNoCheckCertificateNames()
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf(more: [NullExtension(OcspNoCheckOid), Aia(ocsp: [OcspUri]), Cdp(CrlUri)]);
		FakeRetriever retriever = new()
		{
			Responder = Ocsp(leaf, root, TestOcsp.Revoked(Now.AddHours(-1), reason: 1)),
			[CrlUri] = EncodeCrl(root, leaf)
		};
		using TrustAnchorCertificateValidator validator = Online(retriever, root.Certificate);

		await AssertValid(await Validate(validator, presented: [leaf]), leaf, root.Certificate);
		await Assert.That(retriever.Requests).IsEmpty();
	}

	// Each certificate of the path answers for itself.
	[Test]
	public async Task SkipsTheCheckOfAnIntermediateCertificateWithOcspNoCheck()
	{
		using Authority root = Authority.CreateRoot();
		using Authority exempt = root.CreateIntermediate(more: [NullExtension(OcspNoCheckOid)]);
		using Authority checkedIntermediate = root.CreateIntermediate();
		Certificate leaf = exempt.IssueLeaf(more: [NullExtension(NoRevAvailOid)]);
		Certificate leafOfChecked = checkedIntermediate.IssueLeaf(more: [NullExtension(NoRevAvailOid)]);
		FakeRetriever retriever = new();
		using TrustAnchorCertificateValidator validator = Online(retriever, root.Certificate);

		using (Assert.Multiple())
		{
			await AssertValid(await Validate(validator, presented: [leaf, exempt.Certificate]), leaf, exempt.Certificate, root.Certificate);
			await AssertInvalid(await Validate(validator, presented: [leafOfChecked, checkedIntermediate.Certificate]), [CertificateValidationError.RevocationUnknown], CertificatePathEnd.TrustAnchor, leafOfChecked, checkedIntermediate.Certificate, root.Certificate);
			await Assert.That(retriever.Requests).IsEmpty();
		}
	}

	// RFC 9608, Sec. 3: these make the certificate invalid, so that they count without a revocation check too and nothing is retrieved for it.
	[Test]
	[Arguments(X509RevocationMode.NoCheck)]
	[Arguments(X509RevocationMode.Offline)]
	[Arguments(X509RevocationMode.Online)]
	public async Task RefusesNoRevAvailWithWhatItRules(X509RevocationMode mode)
	{
		byte[] distributionPoint = Sequence(TestCrl.FullName(0xA0, UniformResourceIdentifier(CrlUri)));
		(string Name, CertificateExtension Extension)[] cases =
		[
			("cA", BasicConstraints(true)),
			("CRL distribution points", Cdp(CrlUri)),
			("CRL distribution points that do not decode", new CertificateExtension(CrlDistributionPointsOid, false, [0x30, 0x01])),
			("freshest CRL", new CertificateExtension(FreshestCrlOid, false, Sequence(distributionPoint))),
			("freshest CRL that does not decode", new CertificateExtension(FreshestCrlOid, false, [0x30, 0x01])),
			("id-ad-ocsp URI", Aia(ocsp: [OcspUri])),
			("id-ad-ocsp beside id-ad-caIssuers", Aia(caIssuers: [IssuerUri], ocsp: [OcspUri])),
			("id-ad-ocsp directory name", new CertificateExtension(AiaOid, false, Sequence(Sequence(Oid("1.3.6.1.5.5.7.48.1"), DirectoryName("CN=Responder"))))),
			("authority information access truncated", new CertificateExtension(AiaOid, false, [0x30, 0x01])),
			("authority information access empty", new CertificateExtension(AiaOid, false, Sequence()))
		];
		using Authority root = Authority.CreateRoot();

		foreach ((string name, CertificateExtension extension) in cases)
		{
			Certificate leaf = root.IssueLeaf(more: [NullExtension(NoRevAvailOid), extension]);
			FakeRetriever retriever = new();
			using TrustAnchorCertificateValidator validator = Checking(mode, retriever, root.Certificate);

			await AssertInvalid(await Validate(validator, presented: [leaf]), [CertificateValidationError.Malformed], CertificatePathEnd.TrustAnchor, name, [leaf, root.Certificate]);
			await Assert.That(retriever.Requests).IsEmpty().Because(name);
		}
	}

	[Test]
	[Arguments(X509RevocationMode.NoCheck)]
	[Arguments(X509RevocationMode.Online)]
	public async Task AcceptsNoRevAvailWithWhatItAllows(X509RevocationMode mode)
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf(more: [NullExtension(NoRevAvailOid), BasicConstraints(false), Aia(caIssuers: [IssuerUri])]);
		FakeRetriever retriever = new();
		using TrustAnchorCertificateValidator validator = Checking(mode, retriever, root.Certificate);

		await AssertValid(await Validate(validator, presented: [leaf]), leaf, root.Certificate);
		await Assert.That(retriever.Requests).IsEmpty();
	}

	// RFC 9608, Sec. 3: certificates for CAs must not have the extension.
	[Test]
	[Arguments(X509RevocationMode.NoCheck)]
	[Arguments(X509RevocationMode.Online)]
	public async Task RefusesAnIntermediateCertificateWithNoRevAvail(X509RevocationMode mode)
	{
		using Authority root = Authority.CreateRoot();
		using Authority intermediate = root.CreateIntermediate(more: [NullExtension(NoRevAvailOid)]);
		Certificate leaf = intermediate.IssueLeaf(more: [NullExtension(NoRevAvailOid)]);
		FakeRetriever retriever = new();
		using TrustAnchorCertificateValidator validator = Checking(mode, retriever, root.Certificate);

		await AssertInvalid(await Validate(validator, presented: [leaf, intermediate.Certificate]), [CertificateValidationError.Malformed], CertificatePathEnd.TrustAnchor, leaf, intermediate.Certificate, root.Certificate);
		await Assert.That(retriever.Requests).IsEmpty();
	}

	// The extensions of a trust anchor do not count, as for the policy extensions, and neither do those of a pinned certificate.
	[Test]
	public async Task TheExtensionsOfATrustAnchorDoNotCount()
	{
		CertificateExtension[] extensions = [NullExtension(NoRevAvailOid), new(OcspNoCheckOid, false, [0x04, 0x00]), Cdp(CrlUri), new(FreshestCrlOid, false, [0x30, 0x01]), Aia(ocsp: [OcspUri])];
		CertificateExtension[] notDecoding = [new(NoRevAvailOid, false, [0x04, 0x00]), new(AiaOid, false, [0x30, 0x01])];

		foreach (CertificateExtension[] more in (CertificateExtension[][])[extensions, notDecoding])
		{
			using Authority root = Authority.CreateRoot(more: more);
			using Authority issuer = Authority.CreateRoot("CN=Issuer");
			Certificate leaf = root.IssueLeaf();
			Certificate pinned = issuer.IssueLeaf(more: more);
			using TrustAnchorCertificateValidator validator = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo);
			using TrustAnchorCertificateValidator pinning = new([pinned], SignatureKey.ImportSubjectPublicKeyInfo);

			using (Assert.Multiple())
			{
				await AssertValid(await Validate(validator, presented: [leaf]), leaf, root.Certificate);
				await AssertValid(await Validate(pinning, presented: [pinned]), pinned);
			}
		}
	}

	// A value that is not NULL must not bypass the check, nor be accepted without one.
	[Test]
	[Arguments(NoRevAvailOid, X509RevocationMode.NoCheck)]
	[Arguments(NoRevAvailOid, X509RevocationMode.Online)]
	[Arguments(OcspNoCheckOid, X509RevocationMode.NoCheck)]
	[Arguments(OcspNoCheckOid, X509RevocationMode.Online)]
	public async Task RefusesAValueThatIsNotNull(string oid, X509RevocationMode mode)
	{
		using Authority root = Authority.CreateRoot();

		foreach (byte[] value in (byte[][])[[], [0x04, 0x00], [0x05, 0x01, 0x00], [0x05, 0x00, 0x05, 0x00], [0x05]])
		{
			Certificate leaf = root.IssueLeaf(more: [new CertificateExtension(oid, false, value)]);
			FakeRetriever retriever = new();
			using TrustAnchorCertificateValidator validator = Checking(mode, retriever, root.Certificate);

			await AssertInvalid(await Validate(validator, presented: [leaf]), [CertificateValidationError.Malformed], CertificatePathEnd.TrustAnchor, Convert.ToHexString(value), [leaf, root.Certificate]);
			await Assert.That(retriever.Requests).IsEmpty();
		}
	}

	// RFC 9608, Sec. 2: noRevAvail must not be critical, and the validator does not process either extension as a critical one.
	[Test]
	[Arguments(NoRevAvailOid, X509RevocationMode.NoCheck)]
	[Arguments(NoRevAvailOid, X509RevocationMode.Online)]
	[Arguments(OcspNoCheckOid, X509RevocationMode.NoCheck)]
	[Arguments(OcspNoCheckOid, X509RevocationMode.Online)]
	public async Task RefusesACriticalExtension(string oid, X509RevocationMode mode)
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf(more: [NullExtension(oid, critical: true)]);
		FakeRetriever retriever = new();
		using TrustAnchorCertificateValidator validator = Checking(mode, retriever, root.Certificate);

		await AssertInvalid(await Validate(validator, presented: [leaf]), [CertificateValidationError.NotValidForUsage], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
		await Assert.That(retriever.Requests).IsEmpty();
	}

	// Answers from memory and records every call.
	private sealed class FakeRetriever : ICertificateDataRetriever
	{
		private readonly ConcurrentDictionary<string, byte[]> _bodies = new(StringComparer.Ordinal);

		public ConcurrentQueue<Request> Requests { get; } = new();

		// The answer to any URI under the OCSP responder, by GET or POST.
		public byte[]? Responder { get; set; }

		public Func<Uri, CancellationToken, Task>? Hook { get; init; }

		// The answers to any URI of a host, for several responders.
		public Dictionary<string, byte[]> ByHost { get; } = new(StringComparer.Ordinal);

		// The answers of an OCSP responder by the hash of the CertID of the request; null for a failed retrieval.
		public Dictionary<string, (byte[]? Sha256, byte[]? Sha1)> ByCertIdHash { get; } = new(StringComparer.Ordinal);

		// The answers to a URI in turn, one for each request, before those by URI apply.
		public Dictionary<string, Queue<byte[]>> Turns { get; } = new(StringComparer.Ordinal);

		public byte[] this[string uri]
		{
			set => _bodies[uri] = value;
		}

		public ValueTask<ReadOnlyMemory<byte>> GetAsync(Uri uri, int maxLength, CancellationToken cancellationToken)
		{
			return AnswerAsync(new Request("GET", uri, maxLength, null, null), cancellationToken);
		}

		public ValueTask<ReadOnlyMemory<byte>> PostAsync(Uri uri, ReadOnlyMemory<byte> content, string contentType, int maxLength, CancellationToken cancellationToken)
		{
			return AnswerAsync(new Request("POST", uri, maxLength, content.ToArray(), contentType), cancellationToken);
		}

		private async ValueTask<ReadOnlyMemory<byte>> AnswerAsync(Request request, CancellationToken cancellationToken)
		{
			Requests.Enqueue(request);

			if (Hook is { } hook)
			{
				await hook(request.Uri, cancellationToken);
			}

			if (ByCertIdHash.TryGetValue(request.Uri.Host, out (byte[]? Sha256, byte[]? Sha1) answers))
			{
				return (CertIdHashOf(request) is Sha1Oid ? answers.Sha1 : answers.Sha256) ?? default(ReadOnlyMemory<byte>);
			}

			if (Turns.TryGetValue(request.Uri.AbsoluteUri, out Queue<byte[]>? turns) && turns.TryDequeue(out byte[]? turn))
			{
				return turn;
			}

			if (_bodies.TryGetValue(request.Uri.AbsoluteUri, out byte[]? body) || ByHost.TryGetValue(request.Uri.Host, out body))
			{
				return body;
			}

			return request.Uri.Host is "ocsp.test" ? Responder ?? default(ReadOnlyMemory<byte>) : default;
		}

		public sealed record Request(string Method, Uri Uri, int MaxLength, byte[]? Content, string? ContentType);
	}

	private sealed class MovingClock : TimeProvider
	{
		public DateTimeOffset Time { get; set; } = Now;

		public override DateTimeOffset GetUtcNow()
		{
			return Time;
		}
	}

	// A clock whose time stands still for the validation, and whose timers fire only as the test advances them.
	private sealed class ManualTimers : TimeProvider
	{
		private readonly Lock _lock = new();
		private readonly List<Timer> _timers = [];
		private TimeSpan _elapsed;

		public override DateTimeOffset GetUtcNow()
		{
			return Now;
		}

		public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
		{
			Timer timer = new(this, callback, state);
			timer.Change(dueTime, period);
			return timer;
		}

		public void Advance(TimeSpan by)
		{
			List<Timer> due;

			lock (_lock)
			{
				_elapsed += by;
				due = [.. _timers.Where(timer => timer.Due <= _elapsed)];
				_timers.RemoveAll(due.Contains);
			}

			foreach (Timer timer in due)
			{
				timer.Fire();
			}
		}

		private sealed class Timer(ManualTimers clock, TimerCallback callback, object? state) : ITimer
		{
			public TimeSpan Due { get; private set; }

			public bool Change(TimeSpan dueTime, TimeSpan period)
			{
				lock (clock._lock)
				{
					clock._timers.Remove(this);

					if (dueTime != Timeout.InfiniteTimeSpan)
					{
						Due = clock._elapsed + dueTime;
						clock._timers.Add(this);
					}
				}

				return true;
			}

			public void Fire()
			{
				callback(state);
			}

			public void Dispose()
			{
				lock (clock._lock)
				{
					clock._timers.Remove(this);
				}
			}

			public ValueTask DisposeAsync()
			{
				Dispose();
				return ValueTask.CompletedTask;
			}
		}
	}

	private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
	{
		protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
		{
			cancellationToken.ThrowIfCancellationRequested();
			return Task.FromResult(respond(request));
		}
	}

	// A body that never arrives: a read ends only with its token.
	private sealed class StalledStream : MemoryStream
	{
		public override bool CanSeek => false;

		public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
		{
			await Task.Delay(Timeout.Infinite, cancellationToken);
			return 0;
		}
	}

	// A stream that counts what is read of it, and that cannot seek, so that StreamContent declares no length.
	private sealed class CountingStream(byte[] data) : MemoryStream(data)
	{
		public int Consumed { get; private set; }

		public override bool CanSeek => false;

		public override int Read(Span<byte> buffer)
		{
			int read = base.Read(buffer);
			Consumed += read;
			return read;
		}

		public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
		{
			int read = base.Read(buffer.Span);
			Consumed += read;
			return ValueTask.FromResult(read);
		}
	}
}
