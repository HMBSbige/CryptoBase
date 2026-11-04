using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures;
using CryptoBase.Signatures.Ecdsa;
using CryptoBase.Signatures.EdDsa;
using CryptoBase.Signatures.MLDsa;
using CryptoBase.Signatures.Rsa;
using CryptoBase.Tests.Signatures.Rsa;
using CryptoBase.X509;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using static CryptoBase.Tests.Signatures.SignatureTestUtils;
using static CryptoBase.Tests.TestUtils;
using static CryptoBase.Tests.X509.TestPki;
using static CryptoBase.Tests.X509.X509TestUtils;

namespace CryptoBase.Tests.X509;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class TrustAnchorCertificateValidatorTest
{
	private const string CodeSigningOid = "1.3.6.1.5.5.7.3.3";

	[Test]
	public async Task ValidatesAPathToATrustAnchor()
	{
		using Authority root = Authority.CreateRoot();
		using Authority intermediate = root.CreateIntermediate();
		Certificate leaf = intermediate.IssueLeaf();
		Certificate direct = root.IssueLeaf();

		CertificateValidationResult result = await Validate([root.Certificate], [leaf, intermediate.Certificate], hostName: "example.com");

		using (Assert.Multiple())
		{
			await AssertValid(result, leaf, intermediate.Certificate, root.Certificate);
			await Assert.That(result.Message).IsNull();
			await AssertValid(await Validate([root.Certificate], [direct]), direct, root.Certificate);
		}
	}

	// RFC 5280, Sec. 6.1.1: the trust anchor's key is trusted, so its own signature is not verified, and a peer's certificate that is a trust anchor needs no issuer.
	[Test]
	public async Task TrustsTheKeysOfTheTrustAnchorsWithoutTheirSignatures()
	{
		using EcdsaP256 key = EcdsaP256.GenerateKey();
		Certificate pinned = SelfSigned(key, SignatureAlgorithm.EcdsaSha256, "CN=Pinned", new CertificateExtension("2.5.29.17", false, X509TestUtils.SubjectAlternativeName("example.com").RawData), BasicConstraints(true), KeyUsage(X509KeyUsageFlags.DigitalSignature));
		Certificate broken = WithBrokenSignature(pinned);
		using Authority root = Authority.CreateRoot();
		Certificate brokenRoot = WithBrokenSignature(root.Certificate);
		Certificate leaf = root.IssueLeaf();

		using (Assert.Multiple())
		{
			await AssertValid(await Validate([pinned], [pinned], hostName: "example.com"), pinned);
			await AssertValid(await Validate([broken], [broken], hostName: "example.com"), broken);
			await AssertValid(await Validate([brokenRoot], [leaf]), leaf, brokenRoot);
		}
	}

	[Test]
	public async Task ReportsAPathWhoseIssuerIsMissing()
	{
		using Authority root = Authority.CreateRoot();
		using Authority intermediate = root.CreateIntermediate();
		Certificate leaf = intermediate.IssueLeaf();

		await AssertInvalid(await Validate([root.Certificate], [leaf]), [CertificateValidationError.UntrustedRoot], CertificatePathEnd.MissingIssuer, leaf);
	}

	[Test]
	public async Task ReportsAPathToARootThatIsNotTrusted()
	{
		using Authority trusted = Authority.CreateRoot("CN=Trusted");
		using Authority other = Authority.CreateRoot("CN=Other");
		using Authority intermediate = other.CreateIntermediate();
		Certificate leaf = intermediate.IssueLeaf();
		using EcdsaP256 key = EcdsaP256.GenerateKey();
		Certificate selfSigned = SelfSigned(key, SignatureAlgorithm.EcdsaSha256, "CN=Self", new CertificateExtension("2.5.29.17", false, X509TestUtils.SubjectAlternativeName("example.com").RawData));

		using (Assert.Multiple())
		{
			await AssertInvalid(await Validate([trusted.Certificate], [leaf, other.Certificate, intermediate.Certificate]), [CertificateValidationError.UntrustedRoot], CertificatePathEnd.UntrustedRoot, leaf, intermediate.Certificate, other.Certificate);
			await AssertInvalid(await Validate([trusted.Certificate], [selfSigned]), [CertificateValidationError.UntrustedRoot], CertificatePathEnd.UntrustedRoot, selfSigned);
		}
	}

	// A path ends at a self-signed certificate only if the certificate is self-issued and its own key verifies its signature. A certificate for a new key of a CA, which the old key signs, ends a path whose issuer is missing, whether it lacks key identifiers or they name the new key, as does one whose algorithm the validator does not verify.
	[Test]
	public async Task EndsAtASelfSignedCertificateOnlyIfItsOwnKeyVerifiesIt()
	{
		using Authority trusted = Authority.CreateRoot("CN=Trusted");
		using EcdsaP256 oldKey = EcdsaP256.GenerateKey();
		using EcdsaP256 newKey = EcdsaP256.GenerateKey();
		byte[] name = Name("CN=Rollover");
		byte[] newKeyInfo = ExportSubjectPublicKeyInfo(newKey);
		Template ca = new() { Subject = name, SubjectPublicKeyInfo = newKeyInfo, Extensions = [BasicConstraints(true), KeyUsage(X509KeyUsageFlags.KeyCertSign)] };
		Certificate withoutIdentifiers = Sign(ca, name, oldKey, SignatureAlgorithm.EcdsaSha256);
		Certificate withMisleadingIdentifiers = Sign(ca with { Extensions = [.. CaExtensions(newKeyInfo), AuthorityKeyIdentifier(KeyIdentifierOf(newKeyInfo))] }, name, oldKey, SignatureAlgorithm.EcdsaSha256);
		Certificate unsupported = Sign(ca, name, Sequence(Oid("1.3.101.113"), [0x05, 0x00]), static _ => new byte[114]);
		Certificate selfSigned = Sign(ca, name, newKey, SignatureAlgorithm.EcdsaSha256);
		Certificate leaf = Sign(new Template { Subject = Name("CN=Leaf"), SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(EcdsaP256.GenerateKey()), Extensions = [SubjectAlternativeNames("example.com")] }, name, newKey, SignatureAlgorithm.EcdsaSha256);

		using (Assert.Multiple())
		{
			await AssertInvalid(await Validate([trusted.Certificate], [leaf, withoutIdentifiers]), [CertificateValidationError.UntrustedRoot], CertificatePathEnd.MissingIssuer, leaf, withoutIdentifiers);
			await AssertInvalid(await Validate([trusted.Certificate], [leaf, withMisleadingIdentifiers]), [CertificateValidationError.UntrustedRoot], CertificatePathEnd.MissingIssuer, leaf, withMisleadingIdentifiers);
			await AssertInvalid(await Validate([trusted.Certificate], [leaf, unsupported]), [CertificateValidationError.UnsupportedAlgorithm, CertificateValidationError.UntrustedRoot], CertificatePathEnd.MissingIssuer, leaf, unsupported);
			await AssertInvalid(await Validate([trusted.Certificate], [leaf, selfSigned]), [CertificateValidationError.UntrustedRoot], CertificatePathEnd.UntrustedRoot, leaf, selfSigned);

			// The peer's certificate alone.
			await AssertInvalid(await Validate([trusted.Certificate], [withoutIdentifiers]), [CertificateValidationError.UntrustedRoot], CertificatePathEnd.MissingIssuer, withoutIdentifiers);
			await AssertInvalid(await Validate([trusted.Certificate], [selfSigned]), [CertificateValidationError.UntrustedRoot], CertificatePathEnd.UntrustedRoot, selfSigned);
		}
	}

	// The check of whether the certificate that ends a path is self-signed counts as a candidate: after the failing candidates and the two of the path, 97 leave one for it, and 98 none, which stops the search.
	[Test]
	[Arguments(97, CertificatePathEnd.UntrustedRoot)]
	[Arguments(98, CertificatePathEnd.MissingIssuer)]
	public async Task CountsTheCheckOfASelfSignatureAsACandidate(int count, CertificatePathEnd end)
	{
		using Authority trusted = Authority.CreateRoot("CN=Trusted");
		using Authority untrusted = Authority.CreateRoot("CN=Untrusted");
		using Authority intermediate = untrusted.CreateIntermediate();
		using Authority nowhere = Authority.CreateRoot("CN=Nowhere");

		// Without an authority key identifier, the peer's certificate takes its candidates in the order given: expired certificates for the intermediate CA's key, whose issuer is missing, before the intermediate CA.
		Certificate leaf = intermediate.IssueLeaf(extensions: [SubjectAlternativeNames("example.com")]);
		byte[] keyInfo = intermediate.Certificate.PublicKeyInfo.Encoded.ToArray();
		Certificate[] failing = [.. Enumerable.Range(0, count).Select(i => nowhere.Issue(new Template { SerialNumber = [(byte)(i + 2)], Subject = intermediate.Name, SubjectPublicKeyInfo = keyInfo, NotBefore = Now.AddDays(-2), NotAfter = Now.AddDays(-1), Extensions = CaExtensions(keyInfo) }))];

		CertificateValidationResult result = await Validate([trusted.Certificate], [leaf, .. failing, intermediate.Certificate, untrusted.Certificate]);

		CertificateValidationError[] errors = end is CertificatePathEnd.UntrustedRoot ? [CertificateValidationError.UntrustedRoot] : [CertificateValidationError.UntrustedRoot, CertificateValidationError.Unspecified];
		await AssertInvalid(result, errors, end, leaf, intermediate.Certificate, untrusted.Certificate);
	}

	// The search ends paths at each problem it meets, and reports the one that reaches a trust anchor, here through an expired intermediate certificate, rather than one that ends earlier.
	[Test]
	public async Task ReportsTheBestPathWithItsErrors()
	{
		using Authority root = Authority.CreateRoot();
		using Authority expired = root.CreateIntermediate(notBefore: Now.AddDays(-30), notAfter: Now.AddDays(-1));
		Certificate leaf = expired.IssueLeaf();
		using Authority stranger = Authority.CreateRoot("CN=Stranger");
		using Authority dangling = stranger.CreateIntermediate(subject: expired.Name);
		Certificate unsigned = Authority.CreateRoot().IssueLeaf();
		// Two certificates for one CA key, both expired, one also for the wrong usage.
		using Authority onlyExpired = root.CreateIntermediate("CN=Two paths", notAfter: Now.AddDays(-1));
		Certificate wrongUsage = root.Issue(new Template
		{
			Subject = onlyExpired.Name,
			SubjectPublicKeyInfo = onlyExpired.Certificate.PublicKeyInfo.Encoded.ToArray(),
			NotAfter = Now.AddDays(-1),
			Extensions = [.. CaExtensions(onlyExpired.Certificate.PublicKeyInfo.Encoded.Span), ExtendedKeyUsage(CodeSigningOid)]
		});
		Certificate twoPaths = onlyExpired.IssueLeaf();

		using (Assert.Multiple())
		{
			await AssertInvalid(await Validate([root.Certificate], [leaf, dangling.Certificate, expired.Certificate]), [CertificateValidationError.Expired], CertificatePathEnd.TrustAnchor, leaf, expired.Certificate, root.Certificate);
			await AssertInvalid(await Validate([root.Certificate], [ReissuedBy(unsigned, root)]), [CertificateValidationError.InvalidSignature], CertificatePathEnd.TrustAnchor, null, root.Certificate);

			// Both paths reach the trust anchor; the one with fewer errors is reported, whatever the order of the candidates.
			await AssertInvalid(await Validate([root.Certificate], [twoPaths, wrongUsage, onlyExpired.Certificate]), [CertificateValidationError.Expired], CertificatePathEnd.TrustAnchor, twoPaths, onlyExpired.Certificate, root.Certificate);
			await AssertInvalid(await Validate([root.Certificate], [twoPaths, onlyExpired.Certificate, wrongUsage]), [CertificateValidationError.Expired], CertificatePathEnd.TrustAnchor, twoPaths, onlyExpired.Certificate, root.Certificate);
		}
	}

	// RFC 5280, Sec. 6.1.3 (a)(2), at the time truncated to the second, with both ends included.
	[Test]
	public async Task ChecksTheValidityPeriodToTheSecond()
	{
		DateTimeOffset notBefore = Now.AddDays(-1);
		DateTimeOffset notAfter = Now.AddDays(1);
		using Authority root = Authority.CreateRoot(notBefore: Now.AddDays(-2), notAfter: Now.AddDays(2));
		Certificate leaf = root.IssueLeaf(notBefore: notBefore, notAfter: notAfter);
		using Authority expiredRoot = Authority.CreateRoot("CN=Expired", notBefore: Now.AddDays(-2), notAfter: Now.AddDays(-1));
		Certificate leafOfExpiredRoot = expiredRoot.IssueLeaf();

		using (Assert.Multiple())
		{
			await AssertInvalid(await Validate([expiredRoot.Certificate], [leafOfExpiredRoot]), [CertificateValidationError.Expired], CertificatePathEnd.TrustAnchor, leafOfExpiredRoot, expiredRoot.Certificate);
			await AssertValid(await Validate([root.Certificate], [leaf], time: notBefore), leaf, root.Certificate);
			await AssertValid(await Validate([root.Certificate], [leaf], time: notAfter), leaf, root.Certificate);
			await AssertValid(await Validate([root.Certificate], [leaf], time: notAfter.AddTicks(TimeSpan.TicksPerSecond - 1)), leaf, root.Certificate);
			await AssertInvalid(await Validate([root.Certificate], [leaf], time: notAfter.AddSeconds(1)), [CertificateValidationError.Expired], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
			await AssertInvalid(await Validate([root.Certificate], [leaf], time: notBefore.AddTicks(-1)), [CertificateValidationError.Expired], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
			await AssertInvalid(await Validate([root.Certificate], [leaf], time: Now.AddDays(3)), [CertificateValidationError.Expired], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
		}
	}

	[Test]
	public async Task BuildsThePathWhateverTheOrderOfTheCertificates()
	{
		using Authority root = Authority.CreateRoot();
		using Authority first = root.CreateIntermediate("CN=First");
		using Authority second = first.CreateIntermediate("CN=Second");
		Certificate leaf = second.IssueLeaf();
		Certificate copyOfRoot = Certificate.Decode(root.Certificate.Encoded.Span);
		using Authority unrelated = Authority.CreateRoot("CN=Unrelated");

		await AssertValid(await Validate([unrelated.Certificate, root.Certificate], [leaf, copyOfRoot, first.Certificate, unrelated.Certificate, second.Certificate, leaf]), leaf, second.Certificate, first.Certificate, root.Certificate);
	}

	// A cross-certificate that leads nowhere gives way to the one that leads to the trust anchor.
	[Test]
	public async Task BacktracksPastIssuersThatFail()
	{
		using Authority root = Authority.CreateRoot();
		using Authority old = Authority.CreateRoot("CN=Old root");
		using Authority intermediate = root.CreateIntermediate();
		Certificate crossCertificate = Issue(intermediate, old.Key, old.Name);
		Certificate constrained = Issue(intermediate, root.Key, root.Name, NameConstraints(null, [DnsName("example.com")]));
		Certificate leaf = intermediate.IssueLeaf();

		using (Assert.Multiple())
		{
			await AssertValid(await Validate([root.Certificate], [leaf, crossCertificate, old.Certificate, intermediate.Certificate]), leaf, intermediate.Certificate, root.Certificate);
			await AssertValid(await Validate([root.Certificate], [leaf, constrained, intermediate.Certificate]), leaf, intermediate.Certificate, root.Certificate);
		}
	}

	// RFC 5280, Sec. 4.2.1.1: the candidate whose subject key identifier matches the authority key identifier comes first, so a single verification finds the issuer. Both intermediates have the same default name.
	[Test]
	public async Task TriesTheIssuerThatTheKeyIdentifierNamesFirst()
	{
		using Authority root = Authority.CreateRoot();
		using Authority decoy = root.CreateIntermediate();
		using Authority intermediate = root.CreateIntermediate();
		Certificate leaf = intermediate.IssueLeaf();
		Certificate withoutIdentifier = intermediate.IssueLeaf(extensions: [SubjectAlternativeNames("example.com")]);
		KeyLog identified = new();
		KeyLog unidentified = new();

		using (Assert.Multiple())
		{
			await AssertValid(await Validate([root.Certificate], [leaf, decoy.Certificate, intermediate.Certificate], log: identified), leaf, intermediate.Certificate, root.Certificate);
			await Assert.That(identified.Verifications).IsEqualTo(2);
			await AssertValid(await Validate([root.Certificate], [withoutIdentifier, decoy.Certificate, intermediate.Certificate], log: unidentified), withoutIdentifier, intermediate.Certificate, root.Certificate);
			await Assert.That(unidentified.Verifications).IsEqualTo(3);
		}
	}

	[Test]
	public async Task DoesNotFollowCycles()
	{
		using Authority root = Authority.CreateRoot();
		using EcdsaP256 firstKey = EcdsaP256.GenerateKey();
		using EcdsaP256 secondKey = EcdsaP256.GenerateKey();
		byte[] firstName = Name("CN=First");
		byte[] secondName = Name("CN=Second");
		Certificate first = Sign(new Template { Subject = firstName, SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(firstKey), Extensions = CaExtensions(ExportSubjectPublicKeyInfo(firstKey)) }, secondName, secondKey, SignatureAlgorithm.EcdsaSha256);
		Certificate second = Sign(new Template { Subject = secondName, SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(secondKey), Extensions = CaExtensions(ExportSubjectPublicKeyInfo(secondKey)) }, firstName, firstKey, SignatureAlgorithm.EcdsaSha256);
		Certificate leaf = Sign(new Template { Subject = Name("CN=Leaf"), SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(EcdsaP256.GenerateKey()), Extensions = [SubjectAlternativeNames("example.com")] }, firstName, firstKey, SignatureAlgorithm.EcdsaSha256);
		KeyLog log = new();

		CertificateValidationResult result = await Validate([root.Certificate], [leaf, first, second], log: log);

		using (Assert.Multiple())
		{
			await AssertInvalid(result, [CertificateValidationError.UntrustedRoot], CertificatePathEnd.MissingIssuer, leaf, first, second);
			await Assert.That(log.Verifications).IsLessThanOrEqualTo(4);
		}
	}

	// RFC 5280, Sec. 6.1.4 (k): whatever its version, an intermediate certificate must be a CA certificate.
	[Test]
	public async Task RequiresIntermediateCertificatesToBeCertificateAuthorities()
	{
		using Authority root = Authority.CreateRoot();

		foreach ((string name, CertificateExtension[] extensions, int version) in ((string, CertificateExtension[], int)[])
		[
			("no basic constraints", [KeyUsage(X509KeyUsageFlags.KeyCertSign)], 3),
			("cA false", [BasicConstraints(false), KeyUsage(X509KeyUsageFlags.KeyCertSign)], 3),
			("version 1", [], 1)
		])
		{
			using EcdsaP256 key = EcdsaP256.GenerateKey();
			byte[] subject = Name("CN=Intermediate");
			Certificate intermediate = root.Issue(new Template { Version = version, Subject = subject, SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(key), Extensions = extensions });
			Certificate leaf = Sign(new Template { Subject = Name("CN=Leaf"), SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(EcdsaP256.GenerateKey()), Extensions = [SubjectAlternativeNames("example.com")] }, subject, key, SignatureAlgorithm.EcdsaSha256);

			await AssertInvalid(await Validate([root.Certificate], [leaf, intermediate]), [CertificateValidationError.NotValidForUsage], CertificatePathEnd.TrustAnchor, name, [leaf, intermediate, root.Certificate]);
		}
	}

	// Any certificate may be a trust anchor, a version 1 certificate included, but one that has basic constraints must assert cA; the extension need not be critical.
	[Test]
	public async Task AcceptsTrustAnchorsWithoutBasicConstraints()
	{
		using EcdsaP256 key = EcdsaP256.GenerateKey();
		byte[] name = Name("CN=Anchor");
		byte[] subjectPublicKeyInfo = ExportSubjectPublicKeyInfo(key);
		Certificate version1 = Sign(new Template { Version = 1, Subject = name, SubjectPublicKeyInfo = subjectPublicKeyInfo }, name, key, SignatureAlgorithm.EcdsaSha256);
		Certificate nonCritical = Sign(new Template { Subject = name, SubjectPublicKeyInfo = subjectPublicKeyInfo, Extensions = [BasicConstraints(true, critical: false)] }, name, key, SignatureAlgorithm.EcdsaSha256);
		Certificate notCa = Sign(new Template { Subject = name, SubjectPublicKeyInfo = subjectPublicKeyInfo, Extensions = [BasicConstraints(false)] }, name, key, SignatureAlgorithm.EcdsaSha256);
		Certificate leaf = Sign(new Template { Subject = Name("CN=Leaf"), SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(EcdsaP256.GenerateKey()), Extensions = [SubjectAlternativeNames("example.com")] }, name, key, SignatureAlgorithm.EcdsaSha256);

		using (Assert.Multiple())
		{
			await AssertValid(await Validate([version1], [leaf]), leaf, version1);
			await AssertValid(await Validate([nonCritical], [leaf]), leaf, nonCritical);
			await AssertInvalid(await Validate([notCa], [leaf]), [CertificateValidationError.NotValidForUsage], CertificatePathEnd.TrustAnchor, leaf, notCa);
		}
	}

	// RFC 5280 allows a CA certificate at the end of a path, so the peer's certificate may assert cA and keyCertSign; its key usage is the caller's to check.
	[Test]
	public async Task LeavesTheConstraintsOfThePeersCertificateToItsUse()
	{
		using Authority root = Authority.CreateRoot();
		Certificate ca = root.IssueLeaf(more: [BasicConstraints(true, 0), KeyUsage(X509KeyUsageFlags.KeyCertSign)]);
		Certificate encipherment = root.IssueLeaf(more: [KeyUsage(X509KeyUsageFlags.KeyEncipherment)]);

		using (Assert.Multiple())
		{
			await AssertValid(await Validate([root.Certificate], [ca]), ca, root.Certificate);
			await AssertValid(await Validate([root.Certificate], [encipherment]), encipherment, root.Certificate);
		}
	}

	// RFC 5280, Sec. 6.1.4 (l) and (m): pathLenConstraint counts the intermediate certificates below that are not self-issued, the trust anchor's as well.
	[Test]
	public async Task EnforcesPathLengthConstraints()
	{
		using Authority root = Authority.CreateRoot();
		using Authority none = root.CreateIntermediate("CN=Zero", CaExtensionsOf(0));
		using Authority below = none.CreateIntermediate("CN=Below");
		Certificate leaf = below.IssueLeaf();
		using Authority one = root.CreateIntermediate("CN=One", CaExtensionsOf(1));
		using Authority belowOne = one.CreateIntermediate("CN=Below");
		Certificate leafOfOne = belowOne.IssueLeaf();

		// A self-issued certificate below the one with pathLenConstraint 0, as for a key rollover, does not count.
		using Authority rollover = none.CreateIntermediate(subject: none.Name);
		Certificate leafOfRollover = rollover.IssueLeaf();

		using Authority anchor = Authority.CreateRoot("CN=Anchor", CaExtensionsOf(0));
		using Authority belowAnchor = anchor.CreateIntermediate();
		Certificate leafOfAnchor = belowAnchor.IssueLeaf();

		using (Assert.Multiple())
		{
			await AssertInvalid(await Validate([root.Certificate], [leaf, below.Certificate, none.Certificate]), [CertificateValidationError.NotValidForUsage], CertificatePathEnd.TrustAnchor, leaf, below.Certificate, none.Certificate, root.Certificate);
			await AssertValid(await Validate([root.Certificate], [leafOfOne, belowOne.Certificate, one.Certificate]), leafOfOne, belowOne.Certificate, one.Certificate, root.Certificate);
			await AssertValid(await Validate([root.Certificate], [leafOfRollover, rollover.Certificate, none.Certificate]), leafOfRollover, rollover.Certificate, none.Certificate, root.Certificate);
			await AssertInvalid(await Validate([anchor.Certificate], [leafOfAnchor, belowAnchor.Certificate]), [CertificateValidationError.NotValidForUsage], CertificatePathEnd.TrustAnchor, leafOfAnchor, belowAnchor.Certificate, anchor.Certificate);
			await AssertValid(await Validate([anchor.Certificate], [anchor.IssueLeaf()]), null, anchor.Certificate);
		}
	}

	[Test]
	public async Task MaxPathLengthBoundsTheIntermediateCertificates()
	{
		using Authority root = Authority.CreateRoot();
		List<Authority> chain = [root];

		for (int i = 0; i < 9; ++i)
		{
			chain.Add(chain[^1].CreateIntermediate($"CN=Intermediate {i}"));
		}

		Certificate[] intermediates = [.. chain.Skip(1).Select(static authority => authority.Certificate)];
		Certificate nine = chain[^1].IssueLeaf();
		Certificate eight = chain[^2].IssueLeaf();
		Certificate direct = root.IssueLeaf();
		using Authority rollover = chain[1].CreateIntermediate(subject: chain[1].Name);
		Certificate leafOfRollover = rollover.IssueLeaf();

		try
		{
			using (Assert.Multiple())
			{
				await Assert.That((await Validate([root.Certificate], [eight, .. intermediates])).IsValid).IsTrue();
				await AssertInvalid(await Validate([root.Certificate], [nine, .. intermediates]), [CertificateValidationError.NotValidForUsage], CertificatePathEnd.TrustAnchor, [nine, .. intermediates.Reverse(), root.Certificate]);
				await Assert.That((await Validate([root.Certificate], [nine, .. intermediates], maxPathLength: 9)).IsValid).IsTrue();
				await AssertValid(await Validate([root.Certificate], [direct], maxPathLength: 0), direct, root.Certificate);
				await AssertInvalid(await Validate([root.Certificate], [chain[1].IssueLeaf(), chain[1].Certificate], maxPathLength: 0), [CertificateValidationError.NotValidForUsage], CertificatePathEnd.TrustAnchor, null, chain[1].Certificate, root.Certificate);
				await AssertValid(await Validate([root.Certificate], [leafOfRollover, rollover.Certificate, chain[1].Certificate], maxPathLength: 1), leafOfRollover, rollover.Certificate, chain[1].Certificate, root.Certificate);
				await Assert.That(() => new TrustAnchorCertificateValidator([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo) { MaxPathLength = -1 }).ThrowsExactly<ArgumentOutOfRangeException>();
			}
		}
		finally
		{
			foreach (Authority authority in chain.Skip(1))
			{
				authority.Dispose();
			}
		}
	}

	// Self-issued certificates do not count, so zero allows one that rolls over the key of the trust anchor between it and the peer's certificate.
	[Test]
	public async Task MaxPathLengthOfZeroAllowsSelfIssuedIntermediateCertificates()
	{
		using Authority root = Authority.CreateRoot();
		using Authority rollover = root.CreateIntermediate(subject: root.Name);
		Certificate leaf = rollover.IssueLeaf();

		await AssertValid(await Validate([root.Certificate], [leaf, rollover.Certificate], maxPathLength: 0), leaf, rollover.Certificate, root.Certificate);
	}

	// RFC 5280, Sec. 6.1.4 (n), for the trust anchor as well.
	[Test]
	public async Task RequiresKeyCertSignOfIssuers()
	{
		using Authority root = Authority.CreateRoot();
		using Authority intermediate = root.CreateIntermediate(extensions: [BasicConstraints(true), KeyUsage(X509KeyUsageFlags.DigitalSignature)]);
		Certificate leaf = intermediate.IssueLeaf();
		using Authority anchor = Authority.CreateRoot("CN=Anchor", [BasicConstraints(true), KeyUsage(X509KeyUsageFlags.CrlSign)]);
		Certificate leafOfAnchor = anchor.IssueLeaf();

		using (Assert.Multiple())
		{
			await AssertInvalid(await Validate([root.Certificate], [leaf, intermediate.Certificate]), [CertificateValidationError.NotValidForUsage], CertificatePathEnd.TrustAnchor, leaf, intermediate.Certificate, root.Certificate);
			await AssertInvalid(await Validate([anchor.Certificate], [leafOfAnchor]), [CertificateValidationError.NotValidForUsage], CertificatePathEnd.TrustAnchor, leafOfAnchor, anchor.Certificate);
		}
	}

	// RFC 5280, Sec. 4.2.1.12: the peer's certificate needs the usage itself, anyExtendedKeyUsage not standing for it; a CA may have either; an empty extension is malformed.
	[Test]
	[Arguments(new[] { ServerAuthenticationOid }, CertificateUsage.ServerAuthentication, null, null)]
	[Arguments(new string[0], CertificateUsage.ServerAuthentication, null, null)]
	[Arguments(new[] { ClientAuthenticationOid, ServerAuthenticationOid }, CertificateUsage.ClientAuthentication, null, null)]
	[Arguments(new[] { ClientAuthenticationOid }, CertificateUsage.ServerAuthentication, null, CertificateValidationError.NotValidForUsage)]
	[Arguments(new[] { AnyExtendedKeyUsageOid }, CertificateUsage.ServerAuthentication, null, CertificateValidationError.NotValidForUsage)]
	[Arguments(new[] { ServerAuthenticationOid }, CertificateUsage.ServerAuthentication, new[] { AnyExtendedKeyUsageOid }, null)]
	[Arguments(new[] { ServerAuthenticationOid }, CertificateUsage.ServerAuthentication, new[] { ServerAuthenticationOid, CodeSigningOid }, null)]
	[Arguments(new[] { ServerAuthenticationOid }, CertificateUsage.ServerAuthentication, new[] { ClientAuthenticationOid }, CertificateValidationError.NotValidForUsage)]
	[Arguments(new[] { ClientAuthenticationOid }, CertificateUsage.ClientAuthentication, new[] { ServerAuthenticationOid }, CertificateValidationError.NotValidForUsage)]
	public async Task ChecksTheExtendedKeyUsage(string[] leafPurposes, CertificateUsage usage, string[]? caPurposes, CertificateValidationError? error)
	{
		using Authority root = Authority.CreateRoot();
		using Authority intermediate = root.CreateIntermediate(more: caPurposes is null ? [] : [ExtendedKeyUsage(caPurposes)]);
		Certificate leaf = intermediate.IssueLeaf(more: leafPurposes.Length is 0 ? [] : [ExtendedKeyUsage(leafPurposes)]);

		CertificateValidationResult result = await Validate([root.Certificate], [leaf, intermediate.Certificate], usage);

		if (error is { } expected)
		{
			await AssertInvalid(result, [expected], CertificatePathEnd.TrustAnchor, leaf, intermediate.Certificate, root.Certificate);
		}
		else
		{
			await AssertValid(result, leaf, intermediate.Certificate, root.Certificate);
		}
	}

	[Test]
	public async Task ChecksTheExtendedKeyUsageOfTheTrustAnchor()
	{
		using Authority server = Authority.CreateRoot("CN=Server", more: [ExtendedKeyUsage(ServerAuthenticationOid)]);
		using Authority code = Authority.CreateRoot("CN=Code", more: [ExtendedKeyUsage(CodeSigningOid)]);
		Certificate empty = code.IssueLeaf(more: [new CertificateExtension("2.5.29.37", false, Sequence())]);

		using (Assert.Multiple())
		{
			await Assert.That((await Validate([server.Certificate], [server.IssueLeaf()])).IsValid).IsTrue();
			await AssertInvalid(await Validate([code.Certificate], [code.IssueLeaf()]), [CertificateValidationError.NotValidForUsage], CertificatePathEnd.TrustAnchor, null, code.Certificate);
			await AssertInvalid(await Validate([code.Certificate], [empty]), [CertificateValidationError.Malformed, CertificateValidationError.NotValidForUsage], CertificatePathEnd.TrustAnchor, empty, code.Certificate);
		}
	}

	// RFC 5280, Sec. 4.2: a critical extension that the validator does not process fails the path, wherever it is in the path; one in a certificate off the path does not.
	[Test]
	public async Task RefusesCriticalExtensionsThatItDoesNotProcess()
	{
		CertificateExtension unknown = new("1.3.6.1.4.1.55738.666.1", true, [0x05, 0x00]);
		CertificateExtension policies = new(CertificatePoliciesOid, true, Sequence(Sequence(Oid("2.5.29.32.0"))));
		using Authority root = Authority.CreateRoot();
		using Authority criticalRoot = Authority.CreateRoot("CN=Critical", more: [unknown]);
		using Authority intermediate = root.CreateIntermediate(more: [unknown]);
		using Authority plain = root.CreateIntermediate("CN=Plain");
		using Authority unrelated = root.CreateIntermediate("CN=Unrelated", more: [unknown]);
		Certificate unknownLeaf = root.IssueLeaf(more: [unknown]);
		Certificate policyLeaf = root.IssueLeaf(more: [policies]);
		Certificate nonCriticalLeaf = root.IssueLeaf(more: [new CertificateExtension("1.3.6.1.4.1.55738.666.1", false, [0x05, 0x00]), new CertificateExtension(CertificatePoliciesOid, false, policies.Value.Span)]);
		Certificate leafOfIntermediate = intermediate.IssueLeaf();
		Certificate leafOfCriticalRoot = criticalRoot.IssueLeaf();
		Certificate leafOfPlain = plain.IssueLeaf();

		using (Assert.Multiple())
		{
			await AssertInvalid(await Validate([root.Certificate], [unknownLeaf]), [CertificateValidationError.NotValidForUsage], CertificatePathEnd.TrustAnchor, unknownLeaf, root.Certificate);
			await AssertInvalid(await Validate([root.Certificate], [policyLeaf]), [CertificateValidationError.NotValidForUsage], CertificatePathEnd.TrustAnchor, policyLeaf, root.Certificate);
			await AssertInvalid(await Validate([root.Certificate], [leafOfIntermediate, intermediate.Certificate]), [CertificateValidationError.NotValidForUsage], CertificatePathEnd.TrustAnchor, leafOfIntermediate, intermediate.Certificate, root.Certificate);
			await AssertInvalid(await Validate([criticalRoot.Certificate], [leafOfCriticalRoot]), [CertificateValidationError.NotValidForUsage], CertificatePathEnd.TrustAnchor, leafOfCriticalRoot, criticalRoot.Certificate);
			await AssertValid(await Validate([root.Certificate], [nonCriticalLeaf]), nonCriticalLeaf, root.Certificate);
			await AssertValid(await Validate([root.Certificate], [leafOfPlain, unrelated.Certificate, plain.Certificate]), leafOfPlain, plain.Certificate, root.Certificate);
		}
	}

	// RFC 5280, Secs. 4.2.1.1 and 4.2.1.2: the key identifier extensions must not be critical; and every extension that the validator reads must decode.
	[Test]
	public async Task RequiresTheExtensionsToBeWellFormed()
	{
		using Authority root = Authority.CreateRoot();
		using Authority badConstraints = root.CreateIntermediate("CN=Bad", [new CertificateExtension("2.5.29.19", true, [0x30, 0x03, 0x01, 0x01, 0x00]), KeyUsage(X509KeyUsageFlags.KeyCertSign)]);
		Certificate leafOfBad = badConstraints.IssueLeaf();
		using Authority badAnchor = Authority.CreateRoot("CN=Bad anchor", more: [new CertificateExtension("2.5.29.35", false, [0x04, 0x00])]);
		Certificate leafOfBadAnchor = badAnchor.IssueLeaf();

		foreach ((string name, CertificateExtension extension) in ((string, CertificateExtension)[])
		[
			("critical authority key identifier", AuthorityKeyIdentifier(root.KeyIdentifier, critical: true)),
			("critical subject key identifier", SubjectKeyIdentifier([1, 2, 3], critical: true)),
			("subject key identifier that is not an OCTET STRING", new CertificateExtension("2.5.29.14", false, [0x05, 0x00])),
			("subject alternative name that does not decode", new CertificateExtension("2.5.29.17", false, "example.com"u8))
		])
		{
			Certificate leaf = root.IssueLeaf(extensions: [extension]);
			await AssertInvalid(await Validate([root.Certificate], [leaf]), [CertificateValidationError.Malformed], CertificatePathEnd.TrustAnchor, name, [leaf, root.Certificate]);
		}

		using (Assert.Multiple())
		{
			await AssertInvalid(await Validate([root.Certificate], [leafOfBad, badConstraints.Certificate]), [CertificateValidationError.Malformed], CertificatePathEnd.TrustAnchor, leafOfBad, badConstraints.Certificate, root.Certificate);
			await AssertInvalid(await Validate([badAnchor.Certificate], [leafOfBadAnchor]), [CertificateValidationError.Malformed], CertificatePathEnd.TrustAnchor, leafOfBadAnchor, badAnchor.Certificate);
		}
	}

	// RFC 5280, Sec. 4.1.2.4: an empty issuer name links to nothing, even to a CA with an empty subject.
	[Test]
	public async Task RefusesAnEmptyIssuerName()
	{
		using EcdsaP256 key = EcdsaP256.GenerateKey();
		byte[] empty = [0x30, 0x00];
		Certificate anchor = Sign(new Template { Subject = empty, SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(key), Extensions = CaExtensions(ExportSubjectPublicKeyInfo(key)) }, Name("CN=Somebody"), key, SignatureAlgorithm.EcdsaSha256);
		Certificate leaf = Sign(new Template { Subject = Name("CN=Leaf"), SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(EcdsaP256.GenerateKey()), Extensions = [SubjectAlternativeNames("example.com")] }, empty, key, SignatureAlgorithm.EcdsaSha256);

		await AssertInvalid(await Validate([anchor], [leaf]), [CertificateValidationError.Malformed], CertificatePathEnd.TrustAnchor, leaf, anchor);
	}

	// RFC 9525: the subject alternative names identify the host, never the common name.
	[Test]
	public async Task ChecksTheHostName()
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf(extensions: [SubjectAlternativeNames("example.com", "192.0.2.1")]);
		Certificate commonName = root.IssueLeaf("CN=example.com", []);
		Certificate malformed = root.IssueLeaf(extensions: [new CertificateExtension("2.5.29.17", false, [0x30, 0x03, 0x82, 0x01, 0xFF])]);

		using (Assert.Multiple())
		{
			await AssertValid(await Validate([root.Certificate], [leaf], hostName: "EXAMPLE.com."), leaf, root.Certificate);
			await AssertValid(await Validate([root.Certificate], [leaf], hostName: "192.0.2.1"), leaf, root.Certificate);
			await AssertInvalid(await Validate([root.Certificate], [leaf], hostName: "other.example"), [CertificateValidationError.NameMismatch], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
			await AssertInvalid(await Validate([root.Certificate], [leaf], hostName: "127.1"), [CertificateValidationError.NameMismatch], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
			await AssertInvalid(await Validate([root.Certificate], [commonName], hostName: "example.com"), [CertificateValidationError.NameMismatch], CertificatePathEnd.TrustAnchor, commonName, root.Certificate);
			await AssertInvalid(await Validate([root.Certificate], [malformed], hostName: "example.com"), [CertificateValidationError.Malformed], CertificatePathEnd.TrustAnchor, malformed, root.Certificate);
			await AssertValid(await Validate([root.Certificate], [commonName]), commonName, root.Certificate);
		}
	}

	// Text that the peer controls reaches the message with its control characters, line and paragraph separators and unpaired surrogates written as \uXXXX, so that the message is one line that any encoding can write:
	// the subject of a certificate, here with a common name of each string type that can hold such characters, a DNS name that name constraints cannot check, and a host name that is not one.
	[Test]
	public async Task EscapesTextOfThePeerInTheMessage()
	{
		using Authority root = Authority.CreateRoot();
		using Authority constrained = Authority.CreateRoot("CN=Constrained", more: [NameConstraints([DnsName("example.com")])]);
		Certificate badDnsName = constrained.IssueLeaf(extensions: [SubjectAlternativeNames(false, DnsName("a\nb.example.com"))]);
		Certificate leaf = root.IssueLeaf();

		using (Assert.Multiple())
		{
			foreach ((string type, byte[] commonName) in ((string, byte[])[])
			[
				("UniversalString", Tlv(0x1C, [0x00, 0x00, 0xD8, 0x00])),
				("BMPString", Tlv(0x1E, [0x00, 0x61, 0xDC, 0x00, 0x00, 0x0A])),
				("UTF8String", Tlv(0x0C, System.Text.Encoding.UTF8.GetBytes("line\nbreak\r\u0085\u2028\u2029\u0000")))
			])
			{
				Certificate expired = root.Issue(new Template { Subject = Sequence(Tlv(0x31, Sequence(Oid("2.5.4.3"), commonName))), SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(EcdsaP256.GenerateKey()), NotBefore = Now.AddDays(-2), NotAfter = Now.AddDays(-1), Extensions = [SubjectAlternativeNames("example.com")] });
				CertificateValidationResult result = await Validate([root.Certificate], [expired]);

				await AssertInvalid(result, [CertificateValidationError.Expired], CertificatePathEnd.TrustAnchor, type, [expired, root.Certificate]);
				await AssertOneEncodableLine(result.Message, type);
			}

			CertificateValidationResult dnsName = await Validate([constrained.Certificate], [badDnsName]);
			await AssertInvalid(dnsName, [CertificateValidationError.Malformed], CertificatePathEnd.TrustAnchor, badDnsName, constrained.Certificate);
			await Assert.That(dnsName.Message).Contains("\"a\\u000Ab.example.com\"");
			await AssertOneEncodableLine(dnsName.Message, "DNS name");

			CertificateValidationResult hostName = await Validate([root.Certificate], [leaf], hostName: "bad\u2028host\uD800");
			await AssertInvalid(hostName, [CertificateValidationError.NameMismatch], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
			await Assert.That(hostName.Message).Contains("bad\\u2028host\\uD800");
			await AssertOneEncodableLine(hostName.Message, "host name");
		}
	}

	// A surrogate pair stays as it is, and only the braces of a format string are doubled; text without such characters is returned as it is.
	[Test]
	public async Task EscapesTextForMessages()
	{
		const string plain = "CN=Example, O=\"Quoted\"";

		using (Assert.Multiple())
		{
			await Assert.That(PathProblem.EscapeText("a\nb\uD800c\u2029\uD83D\uDE00\uDC00\u007F\uD83D")).IsEqualTo("a\\u000Ab\\uD800c\\u2029\uD83D\uDE00\\uDC00\\u007F\\uD83D");
			await Assert.That(PathProblem.Escape("{0}\t}")).IsEqualTo("{{0}}\\u0009}}");
			await Assert.That(PathProblem.EscapeText(plain)).IsSameReferenceAs(plain);
		}
	}

	// An importer without RSA leaves RSA keys to PlatformRsaKey; RSASSA-PKCS1-v1_5 and RSASSA-PSS verify.
	[Test]
	[Arguments(SignatureAlgorithm.RsaPkcs1Sha256)]
	[Arguments(SignatureAlgorithm.RsaPssSha384)]
	public async Task VerifiesRsaSignaturesWithoutAnRsaImporter(SignatureAlgorithm algorithm)
	{
		using Authority root = RsaRoot(2048, algorithm);
		using Authority intermediate = root.CreateIntermediate();
		Certificate leaf = intermediate.IssueLeaf();
		Certificate tampered = Tamper(leaf);

		using (Assert.Multiple())
		{
			await Assert.That(() => ImportWithoutRsa(root.Certificate.PublicKeyInfo.Encoded.Span)).ThrowsExactly<NotSupportedException>();
			await AssertValid(await Validate([root.Certificate], [leaf, intermediate.Certificate], importPublicKey: ImportWithoutRsa), leaf, intermediate.Certificate, root.Certificate);
			await AssertInvalid(await Validate([root.Certificate], [ReissuedBy(Tamper(intermediate.Certificate), root)], importPublicKey: ImportWithoutRsa), [CertificateValidationError.InvalidSignature], CertificatePathEnd.TrustAnchor, null, root.Certificate);
			await AssertInvalid(await Validate([root.Certificate], [tampered, intermediate.Certificate], importPublicKey: ImportWithoutRsa), [CertificateValidationError.InvalidSignature], CertificatePathEnd.TrustAnchor, tampered, intermediate.Certificate, root.Certificate);
		}
	}

	// Paths of RSA CAs, whose keys are rsaEncryption or id-RSASSA-PSS, without parameters or with those of one hash: RsaKey, which SignatureKey imports, and PlatformRsaKey, to which an importer
	// without RSA leaves them, give the same results. The keys of a CA also sign the certificates below with an algorithm that their AlgorithmIdentifier does not allow, which fails the path.
	[Test]
	[Arguments(false, null, SignatureAlgorithm.RsaPkcs1Sha256, null)]
	[Arguments(false, null, SignatureAlgorithm.RsaPkcs1Sha512, null)]
	[Arguments(false, null, SignatureAlgorithm.RsaPssSha384, null)]
	[Arguments(true, null, SignatureAlgorithm.RsaPssSha512, SignatureAlgorithm.RsaPkcs1Sha512)]
	[Arguments(true, Sha256Oid, SignatureAlgorithm.RsaPssSha256, SignatureAlgorithm.RsaPssSha384)]
	public async Task RsaKeyAndPlatformRsaKeyValidateAlike(bool rsassaPss, string? hash, SignatureAlgorithm algorithm, SignatureAlgorithm? refused)
	{
		byte[] identifier = (rsassaPss, hash) switch
		{
			(false, _) => RsaTestUtils.RsaEncryption,
			(true, null) => RsassaPssIdentifier(withParameters: false),
			(true, { } name) => RsassaPssIdentifier(hash: name, maskHash: name)
		};

		using RsaKey rootKey = ImportRsaKey(RsaTestUtils.Pkcs8PrivateKey(), identifier);
		using RsaKey intermediateKey = ImportRsaKey(RsaTestUtils.OtherKey2048, identifier);
		using EcdsaP256 leafKey = EcdsaP256.GenerateKey();
		byte[] rootName = Name("CN=RSA root");
		byte[] intermediateName = Name("CN=RSA intermediate");
		byte[] rootPublicKey = ExportSubjectPublicKeyInfo(rootKey);
		byte[] intermediatePublicKey = ExportSubjectPublicKeyInfo(intermediateKey);
		Certificate root = Sign(new Template { Subject = rootName, SubjectPublicKeyInfo = rootPublicKey, Extensions = CaExtensions(rootPublicKey) }, rootName, rootKey, algorithm);
		Certificate intermediate = Sign(new Template { Subject = intermediateName, SubjectPublicKeyInfo = intermediatePublicKey, Extensions = [.. CaExtensions(intermediatePublicKey), AuthorityKeyIdentifier(KeyIdentifierOf(rootPublicKey))] }, rootName, rootKey, algorithm);
		Template leafTemplate = new() { Subject = Name("CN=Leaf"), SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(leafKey), Extensions = [SubjectAlternativeNames("example.com"), AuthorityKeyIdentifier(KeyIdentifierOf(intermediatePublicKey))] };
		Certificate leaf = Sign(leafTemplate, intermediateName, intermediateKey, algorithm);
		List<(string Case, Certificate[] Presented, CertificateValidationError[] Errors)> cases =
		[
			("valid", [leaf, intermediate], []),
			("leaf tampered", [Tamper(leaf), intermediate], [CertificateValidationError.InvalidSignature]),
			("intermediate tampered", [leaf, Tamper(intermediate)], [CertificateValidationError.InvalidSignature])
		];

		if (refused is { } other)
		{
			// The same private key with rsaEncryption makes a valid signature of the algorithm that the CA's key refuses.
			using RsaKey unrestricted = ImportRsaKey(RsaTestUtils.OtherKey2048, RsaTestUtils.RsaEncryption);
			cases.Add(("refused algorithm", [Sign(leafTemplate, intermediateName, unrestricted, other), intermediate], [CertificateValidationError.InvalidSignature]));
		}

		int rsaKeys = 0;

		using (Assert.Multiple())
		{
			await Assert.That(() => ImportWithoutRsa(rootPublicKey)).ThrowsExactly<NotSupportedException>();

			foreach ((string @case, Certificate[] presented, CertificateValidationError[] errors) in cases)
			{
				CertificateValidationResult core = await Validate([root], presented, hostName: "example.com", importPublicKey: ImportCountingRsaKeys);
				CertificateValidationResult platform = await Validate([root], presented, hostName: "example.com", importPublicKey: ImportWithoutRsa);

				await Assert.That(core.Errors).IsEquivalentTo(errors, CollectionOrdering.Matching).Because($"{@case}: {core.Message}");
				await Assert.That(platform.Errors).IsEquivalentTo(core.Errors, CollectionOrdering.Matching).Because($"{@case}: {platform.Message}");
				await Assert.That(platform.PathEnd).IsEqualTo(core.PathEnd).Because(@case);
				await Assert.That(platform.Path.Select(static certificate => Convert.ToHexString(certificate.Encoded.Span))).IsEquivalentTo(core.Path.Select(static certificate => Convert.ToHexString(certificate.Encoded.Span)), CollectionOrdering.Matching).Because(@case);
				await Assert.That(platform.Message).IsEqualTo(core.Message).Because(@case);
			}

			// SignatureKey imported the keys of the root and of the intermediate as RsaKey.
			await Assert.That(rsaKeys).IsGreaterThanOrEqualTo(2);
		}

		ISignatureKey ImportCountingRsaKeys(ReadOnlySpan<byte> subjectPublicKeyInfo)
		{
			ISignatureKey key = SignatureKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo);

			if (key is RsaKey)
			{
				Interlocked.Increment(ref rsaKeys);
			}

			return key;
		}
	}

	// The keys that the importer supports it imports, RSA included; the fallback is only for RSA keys that it does not.
	[Test]
	public async Task ImportsKeysWithTheImporter()
	{
		using Authority root = RsaRoot(2048, SignatureAlgorithm.RsaPssSha256);
		Certificate leaf = root.IssueLeaf();
		KeyLog log = new();
		using Authority ecRoot = Authority.CreateRoot();
		Certificate leafOfEcRoot = ecRoot.IssueLeaf();

		using (Assert.Multiple())
		{
			await AssertValid(await Validate([root.Certificate], [leaf], log: log), leaf, root.Certificate);
			await Assert.That(log.Verifications).IsEqualTo(1);
			await AssertInvalid(await Validate([ecRoot.Certificate], [leafOfEcRoot], importPublicKey: static _ => throw new NotSupportedException("No EC.")), [CertificateValidationError.UnsupportedAlgorithm], CertificatePathEnd.TrustAnchor, leafOfEcRoot, ecRoot.Certificate);
			await AssertInvalid(await Validate([ecRoot.Certificate], [leafOfEcRoot], importPublicKey: static _ => throw new ArgumentException("Bad key.")), [CertificateValidationError.Malformed], CertificatePathEnd.TrustAnchor, leafOfEcRoot, ecRoot.Certificate);
			await Assert.That(() => new TrustAnchorCertificateValidator([ecRoot.Certificate], static _ => null!)).ThrowsExactly<InvalidOperationException>();
		}
	}

	// MD2, MD4 and MD5 are forbidden, and SHA-1, SHA-224 and DSA refused, as WeakAlgorithm; algorithms that are not known are unsupported, as are id-Ed25519 and id-Ed448 with parameters, which RFC 8410, Sec. 6, forbids. A trust anchor's own signature does not count.
	[Test]
	[Arguments("1.2.840.113549.1.1.4", true, CertificateValidationError.WeakAlgorithm)]
	[Arguments("1.2.840.113549.1.1.2", true, CertificateValidationError.WeakAlgorithm)]
	[Arguments("1.2.840.113549.1.1.5", true, CertificateValidationError.WeakAlgorithm)]
	[Arguments("1.2.840.113549.1.1.14", true, CertificateValidationError.WeakAlgorithm)]
	[Arguments("1.3.14.3.2.29", true, CertificateValidationError.WeakAlgorithm)]
	[Arguments("1.2.840.10045.4.1", false, CertificateValidationError.WeakAlgorithm)]
	[Arguments("1.2.840.10045.4.3.1", false, CertificateValidationError.WeakAlgorithm)]
	[Arguments("1.2.840.10040.4.3", false, CertificateValidationError.WeakAlgorithm)]
	[Arguments("2.16.840.1.101.3.4.3.2", false, CertificateValidationError.WeakAlgorithm)]
	[Arguments("1.2.840.113549.1.1.10", false, CertificateValidationError.WeakAlgorithm)]
	[Arguments("2.16.840.1.101.3.4.3.10", false, CertificateValidationError.UnsupportedAlgorithm)]
	[Arguments("1.3.101.112", true, CertificateValidationError.UnsupportedAlgorithm)]
	[Arguments("1.3.101.113", true, CertificateValidationError.UnsupportedAlgorithm)]
	public async Task RefusesSignatureAlgorithmsThatItDoesNotVerify(string oid, bool nullParameters, CertificateValidationError error)
	{
		using Authority root = Authority.CreateRoot();
		byte[] identifier = Sequence([Oid(oid), .. nullParameters ? (byte[][])[[0x05, 0x00]] : []]);
		Certificate leaf = Sign(new Template { Subject = Name("CN=Leaf"), SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(EcdsaP256.GenerateKey()), Extensions = [SubjectAlternativeNames("example.com")] }, root.Name, identifier, static _ => new byte[64]);
		using EcdsaP256 anchorKey = EcdsaP256.GenerateKey();
		byte[] anchorName = Name("CN=Weak anchor");
		Certificate weakAnchor = Sign(new Template { Subject = anchorName, SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(anchorKey), Extensions = CaExtensions(ExportSubjectPublicKeyInfo(anchorKey)) }, anchorName, identifier, static _ => new byte[64]);
		Certificate leafOfWeakAnchor = Sign(new Template { Subject = Name("CN=Leaf"), SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(EcdsaP256.GenerateKey()), Extensions = [SubjectAlternativeNames("example.com")] }, anchorName, anchorKey, SignatureAlgorithm.EcdsaSha256);

		using (Assert.Multiple())
		{
			await AssertInvalid(await Validate([root.Certificate], [leaf]), [error], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
			await AssertValid(await Validate([weakAnchor], [leafOfWeakAnchor]), leafOfWeakAnchor, weakAnchor);
		}
	}

	// RSASSA-PSS whose hash or MGF1 hash is SHA-1 or SHA-224 is weak; with SHA-256 but another salt length, unsupported.
	[Test]
	[Arguments(Sha256Oid, Sha256Oid, 32, null)]
	[Arguments("1.3.14.3.2.26", "1.3.14.3.2.26", 20, CertificateValidationError.WeakAlgorithm)]
	[Arguments(Sha256Oid, "2.16.840.1.101.3.4.2.4", 32, CertificateValidationError.WeakAlgorithm)]
	[Arguments(null, null, null, CertificateValidationError.WeakAlgorithm)]
	[Arguments(Sha256Oid, Sha256Oid, 20, CertificateValidationError.UnsupportedAlgorithm)]
	public async Task ClassifiesRsassaPssParameters(string? hash, string? maskHash, int? saltLength, CertificateValidationError? error)
	{
		using Authority root = RsaRoot(2048, SignatureAlgorithm.RsaPssSha256);
		Certificate valid = root.IssueLeaf();
		byte[] identifier = RsassaPssIdentifier(hash: hash, maskHash: maskHash, saltLength: saltLength);
		Certificate leaf = Sign(new Template { Subject = Name("CN=Leaf"), SubjectPublicKeyInfo = valid.PublicKeyInfo.Encoded.ToArray(), Extensions = [SubjectAlternativeNames("example.com")] }, root.Name, identifier, tbs => CryptoBase.Tests.Signatures.SignatureTestUtils.Sign(root.Key, SignatureAlgorithm.RsaPssSha256, tbs));

		CertificateValidationResult result = await Validate([root.Certificate], [leaf]);

		if (error is { } expected)
		{
			await AssertInvalid(result, [expected], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
		}
		else
		{
			await AssertValid(result, leaf, root.Certificate);
		}
	}

	// RFC 9881: an ML-DSA-44 root signs for an ML-DSA-44 leaf.
	[Test]
	public async Task VerifiesMLDsaChains()
	{
		using MLDsa44 rootKey = MLDsa44.GenerateKey();
		using MLDsa44 leafKey = MLDsa44.GenerateKey();
		byte[] name = Name("CN=ML-DSA root");
		Certificate root = Sign(new Template { Subject = name, SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(rootKey), Extensions = CaExtensions(ExportSubjectPublicKeyInfo(rootKey)) }, name, rootKey, SignatureAlgorithm.MLDsa44);
		Certificate leaf = Sign(new Template { Subject = Name("CN=Leaf"), SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(leafKey), Extensions = [SubjectAlternativeNames("example.com")] }, name, rootKey, SignatureAlgorithm.MLDsa44);
		Certificate tampered = Tamper(leaf);

		using (Assert.Multiple())
		{
			await AssertValid(await Validate([root], [leaf], hostName: "example.com"), leaf, root);
			await AssertInvalid(await Validate([root], [tampered]), [CertificateValidationError.InvalidSignature], CertificatePathEnd.TrustAnchor, tampered, root);
		}
	}

	// RFC 8410: an Ed25519 root signs for an Ed25519 leaf.
	[Test]
	public async Task VerifiesEd25519Chains()
	{
		using Ed25519 rootKey = Ed25519.GenerateKey();
		using Ed25519 leafKey = Ed25519.GenerateKey();
		byte[] name = Name("CN=Ed25519 root");
		Certificate root = Sign(new Template { Subject = name, SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(rootKey), Extensions = CaExtensions(ExportSubjectPublicKeyInfo(rootKey)) }, name, rootKey, SignatureAlgorithm.Ed25519);
		Certificate leaf = Sign(new Template { Subject = Name("CN=Leaf"), SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(leafKey), Extensions = [SubjectAlternativeNames("example.com")] }, name, rootKey, SignatureAlgorithm.Ed25519);
		Certificate tampered = Tamper(leaf);
		Certificate openSslRoot = Certificate.DecodePem(OpenSslCertificates.Ed25519Root);
		Certificate openSslLeaf = Certificate.DecodePem(OpenSslCertificates.Ed25519Leaf);

		using (Assert.Multiple())
		{
			await AssertValid(await Validate([root], [leaf], hostName: "example.com"), leaf, root);
			await AssertInvalid(await Validate([root], [tampered]), [CertificateValidationError.InvalidSignature], CertificatePathEnd.TrustAnchor, tampered, root);
			await AssertValid(await Validate([openSslRoot], [openSslLeaf], hostName: "example.com", time: openSslLeaf.NotBefore), openSslLeaf, openSslRoot);
		}
	}

	[Test]
	public async Task VerifiesEd448Chains()
	{
		using Ed448 rootKey = Ed448.GenerateKey();
		using Ed448 leafKey = Ed448.GenerateKey();
		byte[] name = Name("CN=Ed448 root");
		Certificate root = Sign(new Template { Subject = name, SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(rootKey), Extensions = CaExtensions(ExportSubjectPublicKeyInfo(rootKey)) }, name, rootKey, SignatureAlgorithm.Ed448);
		Certificate leaf = Sign(new Template { Subject = Name("CN=Leaf"), SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(leafKey), Extensions = [SubjectAlternativeNames("example.com")] }, name, rootKey, SignatureAlgorithm.Ed448);
		Certificate tampered = Tamper(leaf);
		Certificate externalRoot = Certificate.DecodePem(ExternalCertificates.Ed448Root);
		Certificate externalLeaf = Certificate.DecodePem(ExternalCertificates.Ed448Leaf);

		using (Assert.Multiple())
		{
			await AssertValid(await Validate([root], [leaf], hostName: "example.com"), leaf, root);
			await AssertInvalid(await Validate([root], [tampered]), [CertificateValidationError.InvalidSignature], CertificatePathEnd.TrustAnchor, tampered, root);
			await AssertValid(await Validate([externalRoot], [externalLeaf], hostName: "example.com", time: externalLeaf.NotBefore), externalLeaf, externalRoot);
		}
	}

	// The policy on keys, for the peer's certificate and the trust anchor as well: RSA moduli of MinRsaKeySize to 16384 bits in whole bytes with exponents of at most 33 bits, and EC keys on P-256, P-384 or P-521 by name.
	[Test]
	public async Task AppliesThePolicyToTheKeys()
	{
		using Authority root = Authority.CreateRoot();
		RSAParameters rsa2048 = RsaPrivateParameters();
		using RSA rsa1024 = RSA.Create(1024);
		byte[] secp256k1 = Sequence(Sequence(Oid("1.2.840.10045.2.1"), Oid("1.3.132.0.10")), Tlv(0x03, [0x00, 0x04, .. new byte[64]]));
		byte[] explicitCurve = Sequence(Sequence(Oid("1.2.840.10045.2.1"), Sequence([0x02, 0x01, 0x01])), Tlv(0x03, [0x00, 0x04, .. new byte[64]]));
		byte[] dsa = Sequence(Sequence(Oid("1.2.840.10040.4.1"), Sequence([0x02, 0x01, 0x03], [0x02, 0x01, 0x05], [0x02, 0x01, 0x07])), Tlv(0x03, [0x00, 0x02, 0x01, 0x09]));
		byte[] x448 = Sequence(Sequence(Oid("1.3.101.111")), Tlv(0x03, [0x00, .. new byte[56]]));
		using EcdsaP384 p384 = EcdsaP384.GenerateKey();

		using (Assert.Multiple())
		{
			await AssertKey(root, RsaSubjectPublicKeyInfo(rsa2048.Modulus!, rsa2048.Exponent!), null);
			await AssertKey(root, rsa1024.ExportSubjectPublicKeyInfo(), CertificateValidationError.WeakAlgorithm);
			await AssertKey(root, rsa1024.ExportSubjectPublicKeyInfo(), null, minRsaKeySize: 1024);
			await AssertKey(root, RsaSubjectPublicKeyInfo(rsa2048.Modulus!, rsa2048.Exponent!), CertificateValidationError.WeakAlgorithm, minRsaKeySize: 3072);
			await AssertKey(root, RsaSubjectPublicKeyInfo(OddInteger(2052), [0x01, 0x00, 0x01]), CertificateValidationError.WeakAlgorithm);
			await AssertKey(root, RsaSubjectPublicKeyInfo(OddInteger(16392), [0x01, 0x00, 0x01]), CertificateValidationError.WeakAlgorithm);
			await AssertKey(root, RsaSubjectPublicKeyInfo(rsa2048.Modulus!, [0x02, 0x00, 0x00, 0x00, 0x01]), CertificateValidationError.WeakAlgorithm);
			await AssertKey(root, RsaSubjectPublicKeyInfo(rsa2048.Modulus!, [0x01, 0x00, 0x00, 0x00, 0x01]), null);
			await AssertKey(root, RsaSubjectPublicKeyInfo(rsa2048.Modulus!, [0x01, 0x00, 0x00]), CertificateValidationError.Malformed);
			await AssertKey(root, secp256k1, CertificateValidationError.WeakAlgorithm);
			await AssertKey(root, explicitCurve, CertificateValidationError.UnsupportedAlgorithm);
			await AssertKey(root, dsa, CertificateValidationError.WeakAlgorithm);
			await AssertKey(root, x448, CertificateValidationError.UnsupportedAlgorithm);
			await AssertKey(root, ExportSubjectPublicKeyInfo(p384), null);
			await Assert.That(() => new TrustAnchorCertificateValidator([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo) { MinRsaKeySize = 1023 }).ThrowsExactly<ArgumentOutOfRangeException>();
			await Assert.That(() => new TrustAnchorCertificateValidator([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo) { MinRsaKeySize = 16385 }).ThrowsExactly<ArgumentOutOfRangeException>();
		}

		// A trust anchor's key counts as well, as it verifies the next certificate.
		using RSA weakRoot = RSA.Create(1024);
		using Authority weak = new(Name("CN=Weak"), new PlatformRsaKey(weakRoot), RsaSelfSigned(weakRoot), SignatureAlgorithm.RsaPkcs1Sha256);
		Certificate leafOfWeak = weak.IssueLeaf();
		await AssertInvalid(await Validate([weak.Certificate], [leafOfWeak]), [CertificateValidationError.WeakAlgorithm], CertificatePathEnd.TrustAnchor, leafOfWeak, weak.Certificate);
	}

	// At most 100 candidate issuers, each a signature check, so that intermediate certificates that share a name cannot make the search work without bound.
	[Test]
	public async Task StopsAfterOneHundredCandidates()
	{
		using Authority root = Authority.CreateRoot();
		using Authority intermediate = root.CreateIntermediate();
		Certificate leaf = intermediate.IssueLeaf(extensions: [SubjectAlternativeNames("example.com")]);
		List<Certificate> decoys = [];

		for (int i = 0; i < 120; ++i)
		{
			using Authority decoy = root.CreateIntermediate();
			decoys.Add(decoy.Certificate);
		}

		KeyLog log = new();
		CertificateValidationResult stopped = await Validate([root.Certificate], [leaf, .. decoys], log: log);
		KeyLog enough = new();
		CertificateValidationResult found = await Validate([root.Certificate], [leaf, .. decoys.Take(90), intermediate.Certificate], log: enough);

		using (Assert.Multiple())
		{
			// The second search, with a limit of its own, reports a path through a decoy to the trust anchor.
			await AssertInvalid(stopped, [CertificateValidationError.InvalidSignature, CertificateValidationError.Unspecified], CertificatePathEnd.TrustAnchor, leaf, decoys[0], root.Certificate);
			await Assert.That(log.Verifications).IsLessThanOrEqualTo(2 * CertificatePathSearch.MaxCandidates);
			await Assert.That(found.IsValid).IsTrue().Because(found.Message ?? "");
		}
	}

	// Each search has limits of its own. Expired certificates for the key of one intermediate CA, each the first of a path to the trust anchor, stop the first search at 101 and the second, which considers two candidates for each, at 51; a limit of either adds Unspecified to the errors of the best path that the second search ended.
	[Test]
	[Arguments(1, false)]
	[Arguments(50, false)]
	[Arguments(51, true)]
	[Arguments(60, true)]
	[Arguments(99, true)]
	[Arguments(101, true)]
	public async Task ReportsTheLimitsOfBothSearches(int count, bool stopped)
	{
		using Authority root = Authority.CreateRoot();
		using EcdsaP256 key = EcdsaP256.GenerateKey();
		byte[] keyInfo = ExportSubjectPublicKeyInfo(key);
		byte[] name = Name("CN=Intermediate");
		Certificate[] expired = [.. Enumerable.Range(0, count).Select(i => root.Issue(new Template { SerialNumber = [(byte)(i + 2)], Subject = name, SubjectPublicKeyInfo = keyInfo, NotBefore = Now.AddDays(-2), NotAfter = Now.AddDays(-1), Extensions = [.. CaExtensions(keyInfo), AuthorityKeyIdentifier(root.KeyIdentifier)] }))];
		Certificate leaf = Sign(new Template { Subject = Name("CN=Leaf"), SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(EcdsaP256.GenerateKey()), Extensions = [SubjectAlternativeNames("example.com"), AuthorityKeyIdentifier(KeyIdentifierOf(keyInfo))] }, name, key, SignatureAlgorithm.EcdsaSha256);

		CertificateValidationResult result = await Validate([root.Certificate], [leaf, .. expired]);

		await AssertInvalid(result, stopped ? [CertificateValidationError.Expired, CertificateValidationError.Unspecified] : [CertificateValidationError.Expired], CertificatePathEnd.TrustAnchor, leaf, expired[0], root.Certificate);
	}

	// The second search stops at its limit of name comparisons too, on a path that the first search does not follow, and reports the best path that it ended before.
	[Test]
	public async Task ReportsTheLimitOfNameComparisonsOfTheSecondSearch()
	{
		string[] names = [.. Enumerable.Range(0, 1024).Select(static i => $"host{i}.example.com")];
		byte[][] subtrees = [.. Enumerable.Range(0, 1025).Select(static i => DnsName($"host{i}.example.com"))];
		using Authority first = Authority.CreateRoot("CN=First");
		using Authority second = Authority.CreateRoot("CN=Second", more: [NameConstraints(subtrees)]);
		using EcdsaP256 key = EcdsaP256.GenerateKey();
		byte[] keyInfo = ExportSubjectPublicKeyInfo(key);
		byte[] name = Name("CN=Intermediate");
		Template expired = new() { Subject = name, SubjectPublicKeyInfo = keyInfo, NotBefore = Now.AddDays(-2), NotAfter = Now.AddDays(-1), Extensions = CaExtensions(keyInfo) };
		Certificate ofFirst = first.Issue(expired);
		Certificate ofSecond = second.Issue(expired);
		Certificate leaf = Sign(new Template { Subject = Name("CN=Leaf"), SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(EcdsaP256.GenerateKey()), Extensions = [SubjectAlternativeNames(names)] }, name, key, SignatureAlgorithm.EcdsaSha256);

		using (Assert.Multiple())
		{
			await AssertInvalid(await Validate([first.Certificate, second.Certificate], [leaf, ofFirst, ofSecond]), [CertificateValidationError.Expired, CertificateValidationError.Unspecified], CertificatePathEnd.TrustAnchor, leaf, ofFirst, first.Certificate);
			await AssertInvalid(await Validate([first.Certificate, second.Certificate], [leaf, ofFirst]), [CertificateValidationError.Expired], CertificatePathEnd.TrustAnchor, leaf, ofFirst, first.Certificate);
		}
	}

	// At most 2^20 comparisons of a name with a subtree.
	[Test]
	public async Task StopsBeforeTooManyNameComparisons()
	{
		string[] names = [.. Enumerable.Range(0, 1024).Select(static i => $"host{i}.example.com")];
		byte[][] subtrees = [.. Enumerable.Range(0, 1024).Select(static i => DnsName($"host{i}.example.com"))];
		using Authority root = Authority.CreateRoot(more: [NameConstraints(subtrees)]);
		using Authority over = Authority.CreateRoot("CN=Over", more: [NameConstraints([.. subtrees, DnsName("example.com")])]);
		Certificate leaf = root.IssueLeaf(extensions: [SubjectAlternativeNames(names)]);
		Certificate leafOfOver = over.IssueLeaf(extensions: [SubjectAlternativeNames(names)]);

		using (Assert.Multiple())
		{
			await AssertValid(await Validate([root.Certificate], [leaf]), leaf, root.Certificate);
			await Assert.That((await Validate([over.Certificate], [leafOfOver])).Errors).Contains(CertificateValidationError.Unspecified);
		}
	}

	[Test]
	public async Task HonorsCancellation()
	{
		using Authority root = Authority.CreateRoot();
		using Authority intermediate = root.CreateIntermediate();
		using Authority other = root.CreateIntermediate();
		Certificate leaf = intermediate.IssueLeaf(extensions: [SubjectAlternativeNames("example.com")]);
		using CancellationTokenSource canceled = new();
		await canceled.CancelAsync();
		using CancellationTokenSource during = new();
		KeyLog log = new() { OnVerify = during.Cancel };
		using TrustAnchorCertificateValidator validator = new([root.Certificate], log.Import);
		CertificateValidationContext context = new([leaf, other.Certificate, intermediate.Certificate], CertificateUsage.ServerAuthentication);

		using (Assert.Multiple())
		{
			await Assert.That(async () => await validator.ValidateAsync(context, canceled.Token)).Throws<OperationCanceledException>();
			await Assert.That(async () => await validator.ValidateAsync(context, during.Token)).Throws<OperationCanceledException>();
			await Assert.That(log.Verifications).IsEqualTo(1);
		}
	}

	// One instance serves concurrent validations, which share the keys of the trust anchors.
	[Test]
	public async Task ValidatesConcurrently()
	{
		using Authority root = Authority.CreateRoot();
		using Authority intermediate = root.CreateIntermediate();
		using Authority expired = root.CreateIntermediate("CN=Expired", notAfter: Now.AddDays(-1));
		Certificate[][] chains = [[intermediate.IssueLeaf(), intermediate.Certificate], [expired.IssueLeaf(), expired.Certificate], [root.IssueLeaf()], [Authority.CreateRoot().IssueLeaf()]];
		bool[] expected = [true, false, true, false];
		using TrustAnchorCertificateValidator validator = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo);

		bool[] results = await Task.WhenAll(Enumerable.Range(0, 64).Select(i => Task.Run(async () => (await validator.ValidateAsync(new CertificateValidationContext(chains[i % chains.Length], CertificateUsage.ServerAuthentication))).IsValid)));

		await Assert.That(results).IsEquivalentTo(Enumerable.Range(0, 64).Select(i => expected[i % expected.Length]), CollectionOrdering.Matching);
	}

	// The validator owns the keys that it imports: those of the trust anchors until it is disposed, and the others for one validation.
	[Test]
	public async Task DisposesTheKeysThatItImports()
	{
		using Authority root = Authority.CreateRoot();
		using Authority intermediate = root.CreateIntermediate();
		Certificate leaf = intermediate.IssueLeaf();
		KeyLog log = new();
		TrustAnchorCertificateValidator validator = new([root.Certificate, root.Certificate], log.Import);
		int anchorImports = log.Imports;
		CertificateValidationContext context = new([leaf, intermediate.Certificate], CertificateUsage.ServerAuthentication);

		CertificateValidationResult result = await validator.ValidateAsync(context);
		int afterValidation = log.Disposals;
		validator.Dispose();
		validator.Dispose();

		using (Assert.Multiple())
		{
			await Assert.That(result.IsValid).IsTrue();
			await Assert.That(anchorImports).IsEqualTo(1);
			await Assert.That(afterValidation).IsEqualTo(log.Imports - 1);
			await Assert.That(log.Disposals).IsEqualTo(log.Imports);
			await Assert.That(async () => await validator.ValidateAsync(context)).ThrowsExactly<ObjectDisposedException>();
		}
	}

	[Test]
	public async Task ChecksItsArguments()
	{
		using Authority root = Authority.CreateRoot();
		using TrustAnchorCertificateValidator validator = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo);

		using (Assert.Multiple())
		{
			await Assert.That(() => new TrustAnchorCertificateValidator(null!, SignatureKey.ImportSubjectPublicKeyInfo)).ThrowsExactly<ArgumentNullException>();
			await Assert.That(() => new TrustAnchorCertificateValidator([root.Certificate], null!)).ThrowsExactly<ArgumentNullException>();
			await Assert.That(() => new TrustAnchorCertificateValidator([], SignatureKey.ImportSubjectPublicKeyInfo)).ThrowsExactly<ArgumentException>().WithParameterName("trustAnchors");
			await Assert.That(() => new TrustAnchorCertificateValidator([null!], SignatureKey.ImportSubjectPublicKeyInfo)).ThrowsExactly<ArgumentException>().WithParameterName("trustAnchors");
			await Assert.That(async () => await validator.ValidateAsync(null!)).ThrowsExactly<ArgumentNullException>();
			await Assert.That(validator.MaxPathLength).IsEqualTo(8);
			await Assert.That(validator.MinRsaKeySize).IsEqualTo(2048);
		}
	}

	// The validator uses no network, so the deadline does not matter.
	[Test]
	public async Task IgnoresTheDeadline()
	{
		using Authority root = Authority.CreateRoot();
		Certificate leaf = root.IssueLeaf();
		using TrustAnchorCertificateValidator validator = new([root.Certificate], SignatureKey.ImportSubjectPublicKeyInfo);

		CertificateValidationResult result = await validator.ValidateAsync(new CertificateValidationContext([leaf], CertificateUsage.ServerAuthentication) { Deadline = DateTimeOffset.UtcNow.AddDays(-1) });

		await AssertValid(result, leaf, root.Certificate);
	}

	internal static async Task<CertificateValidationResult> Validate(IEnumerable<Certificate> anchors, Certificate[] presented, CertificateUsage usage = CertificateUsage.ServerAuthentication, string? hostName = null, int maxPathLength = 8, int minRsaKeySize = 2048, DateTimeOffset? time = null, KeyLog? log = null, Func<ReadOnlySpan<byte>, ISignatureKey>? importPublicKey = null)
	{
		using TrustAnchorCertificateValidator validator = new(anchors, importPublicKey ?? (log is null ? SignatureKey.ImportSubjectPublicKeyInfo : log.Import)) { MaxPathLength = maxPathLength, MinRsaKeySize = minRsaKeySize };
		return await validator.ValidateAsync(new CertificateValidationContext(presented, usage) { HostName = hostName, TimeProvider = time is { } at ? new FixedTimeProvider(at) : TimeProvider.System });
	}

	internal static async Task AssertValid(CertificateValidationResult result, params Certificate?[] path)
	{
		using (Assert.Multiple())
		{
			await Assert.That(result.IsValid).IsTrue().Because($"[{string.Join(", ", result.Errors)}] {result.Message}");
			await Assert.That(result.PathEnd).IsEqualTo(CertificatePathEnd.TrustAnchor);
			await AssertPath(result, path);
		}
	}

	// A null in path stands for a certificate that the test does not hold, such as one that a helper made.
	internal static Task AssertInvalid(CertificateValidationResult result, CertificateValidationError[] errors, CertificatePathEnd end, params Certificate?[] path)
	{
		return AssertInvalid(result, errors, end, "", path);
	}

	internal static async Task AssertInvalid(CertificateValidationResult result, CertificateValidationError[] errors, CertificatePathEnd end, string because, Certificate?[] path)
	{
		using (Assert.Multiple())
		{
			await Assert.That(result.Errors).IsEquivalentTo(errors, CollectionOrdering.Matching).Because($"{because}: {result.Message}");
			await Assert.That(result.PathEnd).IsEqualTo(end).Because(because);
			await Assert.That(result.Message).IsNotNull();
			await AssertPath(result, path);
		}
	}

	private static async Task AssertPath(CertificateValidationResult result, Certificate?[] path)
	{
		await Assert.That(result.Path.Count).IsEqualTo(path.Length);

		for (int i = 0; i < Math.Min(path.Length, result.Path.Count); ++i)
		{
			if (path[i] is { } expected)
			{
				await Assert.That(result.Path[i].Encoded.Span.SequenceEqual(expected.Encoded.Span)).IsTrue().Because($"certificate {i} of the path");
			}
		}
	}

	// No control character, line or paragraph separator, or unpaired surrogate, which UTF-8 cannot encode.
	private static async Task AssertOneEncodableLine(string? message, string because)
	{
		string text = message ?? "";

		await Assert.That(text.Any(static c => char.IsControl(c) || c is '\u2028' or '\u2029')).IsFalse().Because($"{because}: {text}");
		await Assert.That(() => new System.Text.UTF8Encoding(false, true).GetByteCount(text)).ThrowsNothing().Because(because);
	}

	private static async Task AssertKey(Authority root, byte[] subjectPublicKeyInfo, CertificateValidationError? error, int minRsaKeySize = 2048)
	{
		Certificate leaf = root.Issue(new Template { Subject = Name("CN=Leaf"), SubjectPublicKeyInfo = subjectPublicKeyInfo, Extensions = [SubjectAlternativeNames("example.com")] });
		CertificateValidationResult result = await Validate([root.Certificate], [leaf], minRsaKeySize: minRsaKeySize);

		if (error is { } expected)
		{
			await AssertInvalid(result, [expected], CertificatePathEnd.TrustAnchor, leaf, root.Certificate);
		}
		else
		{
			await AssertValid(result, leaf, root.Certificate);
		}
	}

	private static CertificateExtension[] CaExtensionsOf(int pathLength)
	{
		return [BasicConstraints(true, pathLength), KeyUsage(X509KeyUsageFlags.KeyCertSign)];
	}

	// A certificate with the subject and key of a CA, which another key signs as issuer.
	private static Certificate Issue(Authority subject, ISignatureKey issuerKey, byte[]? issuer = null, params CertificateExtension[] more)
	{
		Template template = new()
		{
			Subject = subject.Name,
			SubjectPublicKeyInfo = subject.Certificate.PublicKeyInfo.Encoded.ToArray(),
			Extensions = [.. CaExtensions(subject.Certificate.PublicKeyInfo.Encoded.Span), .. more]
		};

		return Sign(template, issuer ?? subject.Certificate.Issuer.ToArray(), issuerKey, SignatureAlgorithm.EcdsaSha256);
	}

	// The certificate with the issuer name of a CA and its signature unchanged, so that the CA's key does not verify it.
	private static Certificate ReissuedBy(Certificate certificate, Authority issuer)
	{
		Template template = new()
		{
			Subject = certificate.Subject.ToArray(),
			SubjectPublicKeyInfo = certificate.PublicKeyInfo.Encoded.ToArray(),
			Extensions = [.. certificate.Extensions]
		};

		return Sign(template, issuer.Name, certificate.SignatureAlgorithm.Encoded.ToArray(), _ => certificate.Signature.ToArray());
	}

	// The certificate with the last byte of its signature changed.
	private static Certificate Tamper(Certificate certificate)
	{
		byte[] encoded = certificate.Encoded.ToArray();
		encoded[^1] ^= 0x01;
		return Certificate.Decode(encoded);
	}

	private static Certificate WithBrokenSignature(Certificate certificate)
	{
		return Tamper(certificate);
	}

	private static Authority RsaRoot(int bits, SignatureAlgorithm algorithm)
	{
		RSA key = CreateRsa(bits);
		return new Authority(Name("CN=RSA root"), new PlatformRsaKey(key, [algorithm]), RsaSelfSigned(key, algorithm), algorithm);
	}

	private static Certificate RsaSelfSigned(RSA key, SignatureAlgorithm algorithm = SignatureAlgorithm.RsaPkcs1Sha256)
	{
		(HashAlgorithmName hash, RSASignaturePadding padding) = RsaParametersOf(algorithm);
		byte[] name = Name(key.KeySize is 1024 ? "CN=Weak" : "CN=RSA root");
		byte[] subjectPublicKeyInfo = key.ExportSubjectPublicKeyInfo();
		Template template = new() { Subject = name, SubjectPublicKeyInfo = subjectPublicKeyInfo, Extensions = CaExtensions(subjectPublicKeyInfo) };
		return Sign(template, name, AlgorithmIdentifier.FromSignatureAlgorithm(algorithm).Encoded.ToArray(), tbs => key.SignData(tbs, hash, padding));
	}

	// The RSAPrivateKey of a PKCS #8 key, imported with another AlgorithmIdentifier.
	private static RsaKey ImportRsaKey(byte[] pkcs8, byte[] identifier)
	{
		using RsaKey key = RsaKey.ImportPkcs8PrivateKey(pkcs8);
		return RsaKey.ImportPkcs8PrivateKey(RsaTestUtils.PrivateKeyInfo(identifier, RsaTestUtils.ExportRsaPrivateKey(key)));
	}

	// SignatureKey without RSA, so that the validator imports RSA keys with PlatformRsaKey.
	private static ISignatureKey ImportWithoutRsa(ReadOnlySpan<byte> subjectPublicKeyInfo)
	{
		ISignatureKey key = SignatureKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo);

		if (key is RsaKey)
		{
			key.Dispose();
			throw new NotSupportedException("No RSA.");
		}

		return key;
	}

	private static byte[] RsaSubjectPublicKeyInfo(byte[] modulus, byte[] exponent)
	{
		AsnWriter key = new(AsnEncodingRules.DER);

		using (key.PushSequence())
		{
			key.WriteIntegerUnsigned(modulus);
			key.WriteIntegerUnsigned(exponent);
		}

		AsnWriter writer = new(AsnEncodingRules.DER);

		using (writer.PushSequence())
		{
			writer.WriteEncodedValue(Sequence(Oid("1.2.840.113549.1.1.1"), [0x05, 0x00]));
			writer.WriteBitString(key.Encode());
		}

		return writer.Encode();
	}

	// An odd number of the given bit length, as the modulus of a key that is never used.
	private static byte[] OddInteger(int bits)
	{
		BigInteger value = BigInteger.One << bits - 1 | BigInteger.One;
		return value.ToByteArray(isUnsigned: true, isBigEndian: true);
	}
}
