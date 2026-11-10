using CryptoBase.Signatures.Ecdsa;
using CryptoBase.X509;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;
using static CryptoBase.Tests.TestUtils;
using static CryptoBase.Tests.X509.TestCrl;
using static CryptoBase.Tests.X509.X509TestUtils;

namespace CryptoBase.Tests.X509;

public class RevocationCheckerCrlTest
{
	private const CrlReasonFlags AllReasons = RevocationChecker.AllReasons;

	private sealed class Fixture : IDisposable
	{
		public TestPki.Authority Authority { get; } = TestPki.Authority.CreateRoot("CN=CRL Issuer");

		public Certificate Leaf => field ??= Authority.IssueLeaf();

		public byte[] LeafSerial => SerialNumberOf(Leaf);

		public void Dispose()
		{
			Authority.Dispose();
		}
	}

	private static async Task AssertStatusAsync(RevocationResult result, RevocationStatus expected)
	{
		await Assert.That(result.Status).IsEqualTo(expected).Because(result.Detail ?? "");
	}

	[Test]
	public async Task AnUnlistedCertificateIsGood()
	{
		using Fixture fixture = new();
		RevocationResult result = Check(Conforming(fixture.Authority).Decode(fixture.Authority), fixture.Leaf, fixture.Authority);

		using (Assert.Multiple())
		{
			await AssertStatusAsync(result, RevocationStatus.Good);
			await Assert.That(result.CoveredReasons).IsEqualTo(AllReasons);
			await Assert.That(result.Reason).IsNull();
		}
	}

	[Test]
	public async Task AListedCertificateIsRevokedWithItsReasonAndTime()
	{
		using Fixture fixture = new();
		DateTimeOffset revoked = Now.AddDays(-2);
		CertificateRevocationList crl = Conforming(fixture.Authority, [Entry(fixture.LeafSerial, revoked, ReasonCode(1))]).Decode(fixture.Authority);

		RevocationResult result = Check(crl, fixture.Leaf, fixture.Authority);

		using (Assert.Multiple())
		{
			await AssertStatusAsync(result, RevocationStatus.Revoked);
			await Assert.That(result.Reason).IsEqualTo(X509RevocationReason.KeyCompromise);
			await Assert.That(result.RevocationTime).IsEqualTo(revoked);
		}
	}

	// Sec. 6.3.3 (i)(2) and (j): an entry without a reason code has the status unspecified.
	[Test]
	public async Task AnEntryWithoutAReasonIsUnspecified()
	{
		using Fixture fixture = new();
		CertificateRevocationList crl = Conforming(fixture.Authority, [Entry(fixture.LeafSerial)]).Decode(fixture.Authority);

		RevocationResult result = Check(crl, fixture.Leaf, fixture.Authority);

		using (Assert.Multiple())
		{
			await AssertStatusAsync(result, RevocationStatus.Revoked);
			await Assert.That(result.Reason).IsEqualTo(X509RevocationReason.Unspecified);
		}
	}

	// Sec. 5.3.1: all reason codes but removeFromCRL mean revoked, certificateHold included; removeFromCRL may appear only in delta CRLs.
	[Test]
	public async Task HoldIsRevokedAndRemoveFromCrlIsInvalid()
	{
		using Fixture fixture = new();
		CertificateRevocationList held = Conforming(fixture.Authority, [Entry(fixture.LeafSerial, null, ReasonCode(6))]).Decode(fixture.Authority);
		CertificateRevocationList removed = Conforming(fixture.Authority, [Entry(fixture.LeafSerial, null, ReasonCode(8))]).Decode(fixture.Authority);
		RevocationResult heldResult = Check(held, fixture.Leaf, fixture.Authority);

		using (Assert.Multiple())
		{
			await AssertStatusAsync(heldResult, RevocationStatus.Revoked);
			await Assert.That(heldResult.Reason).IsEqualTo(X509RevocationReason.CertificateHold);
			await AssertStatusAsync(Check(removed, fixture.Leaf, fixture.Authority), RevocationStatus.Invalid);
		}
	}

	[Test]
	public async Task AnotherIssuerIsNotApplicableWhateverTheSerialNumber()
	{
		using Fixture fixture = new();
		using TestPki.Authority other = TestPki.Authority.CreateRoot("CN=Other Issuer");
		Template template = Conforming(other, [Entry(fixture.LeafSerial)]);

		await AssertStatusAsync(Check(template.Decode(other), fixture.Leaf, fixture.Authority), RevocationStatus.NotApplicable);
	}

	[Test]
	public async Task TheValidityPeriodIncludesThisUpdateAndExcludesNextUpdate()
	{
		using Fixture fixture = new();
		DateTimeOffset thisUpdate = Now.AddHours(-1);
		DateTimeOffset nextUpdate = Now.AddHours(1);
		CertificateRevocationList crl = (Conforming(fixture.Authority) with { ThisUpdate = Time(thisUpdate), NextUpdate = Time(nextUpdate) }).Decode(fixture.Authority);

		using (Assert.Multiple())
		{
			await AssertStatusAsync(Check(crl, fixture.Leaf, fixture.Authority, thisUpdate), RevocationStatus.Good);
			await AssertStatusAsync(Check(crl, fixture.Leaf, fixture.Authority, thisUpdate.AddSeconds(-1)), RevocationStatus.Invalid);
			await AssertStatusAsync(Check(crl, fixture.Leaf, fixture.Authority, nextUpdate.AddSeconds(-1)), RevocationStatus.Good);
			await AssertStatusAsync(Check(crl, fixture.Leaf, fixture.Authority, nextUpdate), RevocationStatus.Invalid);
			await AssertStatusAsync(Check(crl, fixture.Leaf, fixture.Authority, nextUpdate.AddSeconds(1)), RevocationStatus.Invalid);
		}
	}

	[Test]
	public async Task ACrlWithoutNextUpdateIsInvalid()
	{
		using Fixture fixture = new();

		await AssertStatusAsync(Check((Conforming(fixture.Authority) with { NextUpdate = null }).Decode(fixture.Authority), fixture.Leaf, fixture.Authority), RevocationStatus.Invalid);
	}

	// Sec. 6.3.3 (f).
	[Test]
	[Arguments(X509KeyUsageFlags.KeyCertSign, false)]
	[Arguments(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true)]
	[Arguments(X509KeyUsageFlags.CrlSign, true)]
	public async Task TheIssuersKeyUsageMustAllowCrlSigning(X509KeyUsageFlags usage, bool allowed)
	{
		using TestPki.Authority authority = TestPki.Authority.CreateRoot(extensions: [TestPki.BasicConstraints(true), TestPki.KeyUsage(usage)]);
		Certificate leaf = authority.IssueLeaf();

		await AssertStatusAsync(Check(Conforming(authority).Decode(authority), leaf, authority), allowed ? RevocationStatus.Good : RevocationStatus.Invalid);
	}

	// RFC 5280, Sec. 6.3.3 (f), as RFC 10007, Sec. 4, amends it.
	[Test]
	public async Task AVersion3IssuerWithoutKeyUsageMayNotSign()
	{
		using TestPki.Authority authority = TestPki.Authority.CreateRoot(extensions: [TestPki.BasicConstraints(true)]);
		Certificate leaf = authority.IssueLeaf();

		await AssertStatusAsync(Check(Conforming(authority).Decode(authority), leaf, authority), RevocationStatus.Invalid);
	}

	// RFC 5280, Sec. 6.3.3 (f), as RFC 10007, Sec. 4, amends it: a certificate before version 3 has no extensions, so the check does not apply.
	[Test]
	[Arguments(1)]
	[Arguments(2)]
	public async Task AnIssuerBeforeVersion3NeedsNoKeyUsage(int version)
	{
		EcdsaP256 key = EcdsaP256.GenerateKey();
		byte[] name = Name("CN=Earlier Issuer");
		TestPki.Template template = new() { Version = version, Subject = name, SubjectPublicKeyInfo = Signatures.SignatureTestUtils.ExportSubjectPublicKeyInfo(key) };
		using TestPki.Authority authority = new(name, key, TestPki.Sign(template, name, key, Abstractions.Signatures.SignatureAlgorithm.EcdsaSha256));
		Certificate leaf = authority.IssueLeaf();

		await AssertStatusAsync(Check(Conforming(authority).Decode(authority), leaf, authority), RevocationStatus.Good);
	}

	// Sec. 5.2.3: every version 2 CRL needs a non-critical CRL number; a version 1 CRL has no extensions, and Sec. 5 requires applications to process it.
	[Test]
	public async Task CrlNumbersMustBePresentAndNotCritical()
	{
		using Fixture fixture = new();
		Template missing = new() { Issuer = fixture.Authority.Name, Extensions = [AuthorityKeyIdentifier(fixture.Authority.KeyIdentifier)] };
		Template noExtensions = new() { Issuer = fixture.Authority.Name };
		Template critical = new() { Issuer = fixture.Authority.Name, Extensions = [AuthorityKeyIdentifier(fixture.Authority.KeyIdentifier), CrlNumber(1, Critical)] };
		Template malformed = new() { Issuer = fixture.Authority.Name, Extensions = [AuthorityKeyIdentifier(fixture.Authority.KeyIdentifier), Extension(CrlNumberOid, [0x05, 0x00])] };
		Template version1 = new() { Issuer = fixture.Authority.Name, Version = null };

		using (Assert.Multiple())
		{
			await AssertStatusAsync(Check(missing.Decode(fixture.Authority), fixture.Leaf, fixture.Authority), RevocationStatus.Invalid);
			await AssertStatusAsync(Check(noExtensions.Decode(fixture.Authority), fixture.Leaf, fixture.Authority), RevocationStatus.Invalid);
			await AssertStatusAsync(Check(critical.Decode(fixture.Authority), fixture.Leaf, fixture.Authority), RevocationStatus.Invalid);
			await AssertStatusAsync(Check(malformed.Decode(fixture.Authority), fixture.Leaf, fixture.Authority), RevocationStatus.Invalid);
			await AssertStatusAsync(Check(version1.Decode(fixture.Authority), fixture.Leaf, fixture.Authority), RevocationStatus.Good);
		}
	}

	[Test]
	public async Task AuthorityKeyIdentifiersMustNameTheIssuersKey()
	{
		using Fixture fixture = new();
		Template mismatch = new() { Issuer = fixture.Authority.Name, Extensions = [AuthorityKeyIdentifier(new byte[20]), CrlNumber(1)] };
		Template absent = new() { Issuer = fixture.Authority.Name, Extensions = [CrlNumber(1)] };
		Template malformed = new() { Issuer = fixture.Authority.Name, Extensions = [Extension(AuthorityKeyIdentifierOid, [0x05, 0x00]), CrlNumber(1)] };
		Template issuerSerialOnly = new() { Issuer = fixture.Authority.Name, Extensions = [Extension(AuthorityKeyIdentifierOid, Sequence(Tlv(0xA1, Tlv(0xA4, fixture.Authority.Name)), Tlv(0x82, [0x09]))), CrlNumber(1)] };

		using (Assert.Multiple())
		{
			await AssertStatusAsync(Check(mismatch.Decode(fixture.Authority), fixture.Leaf, fixture.Authority), RevocationStatus.Invalid);
			await AssertStatusAsync(Check(absent.Decode(fixture.Authority), fixture.Leaf, fixture.Authority), RevocationStatus.Good);
			await AssertStatusAsync(Check(malformed.Decode(fixture.Authority), fixture.Leaf, fixture.Authority), RevocationStatus.Invalid);
			await AssertStatusAsync(Check(issuerSerialOnly.Decode(fixture.Authority), fixture.Leaf, fixture.Authority), RevocationStatus.Good);
		}
	}

	[Test]
	public async Task AnIssuerWithoutASubjectKeyIdentifierMatchesAnyAuthorityKeyIdentifier()
	{
		using TestPki.Authority authority = TestPki.Authority.CreateRoot(extensions: [TestPki.BasicConstraints(true), TestPki.KeyUsage(X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.KeyCertSign)]);
		Certificate leaf = authority.IssueLeaf();

		await AssertStatusAsync(Check(Conforming(authority).Decode(authority), leaf, authority), RevocationStatus.Good);
	}

	// Sec. 5.2: an extension that is not understood forbids the use of the CRL only if it is critical.
	[Test]
	public async Task UnknownCriticalExtensionsMakeTheCrlInvalid()
	{
		using Fixture fixture = new();
		CertificateRevocationList critical = Conforming(fixture.Authority, null, Extension(PrivateOid, [0x05, 0x00], Critical)).Decode(fixture.Authority);
		CertificateRevocationList noncritical = Conforming(fixture.Authority, null, Extension(PrivateOid, [0x05, 0x00])).Decode(fixture.Authority);
		CertificateRevocationList criticalFreshest = Conforming(fixture.Authority, null, Extension("2.5.29.46", [0x05, 0x00], Critical)).Decode(fixture.Authority);
		CertificateRevocationList criticalAccess = Conforming(fixture.Authority, null, Extension("1.3.6.1.5.5.7.1.1", [0x05, 0x00], Critical)).Decode(fixture.Authority);

		using (Assert.Multiple())
		{
			await AssertStatusAsync(Check(critical, fixture.Leaf, fixture.Authority), RevocationStatus.Invalid);
			await AssertStatusAsync(Check(noncritical, fixture.Leaf, fixture.Authority), RevocationStatus.Good);
			await AssertStatusAsync(Check(criticalFreshest, fixture.Leaf, fixture.Authority), RevocationStatus.Invalid);
			await AssertStatusAsync(Check(criticalAccess, fixture.Leaf, fixture.Authority), RevocationStatus.Invalid);
		}
	}

	[Test]
	public async Task CriticalExtensionsThatTheCheckerProcessesAreAccepted()
	{
		using Fixture fixture = new();
		Template authorityKey = new() { Issuer = fixture.Authority.Name, Extensions = [AuthorityKeyIdentifier(fixture.Authority.KeyIdentifier, Critical), CrlNumber(1)] };
		byte[] processedForms = GeneralNames(TestPki.OtherName(), TestPki.Rfc822Name("crl@example.com"), DnsName("crl.example"), TestPki.DirectoryName("CN=Other"), TestPki.UniformResourceIdentifier("http://crl.example/"), IPAddressName("192.0.2.1"), Tlv(0x88, [0x2A, 0x03]));
		Template issuerName = Conforming(fixture.Authority, null, Extension(IssuerAlternativeNameOid, processedForms, Critical));

		using (Assert.Multiple())
		{
			await AssertStatusAsync(Check(authorityKey.Decode(fixture.Authority), fixture.Leaf, fixture.Authority), RevocationStatus.Good);
			await AssertStatusAsync(Check(issuerName.Decode(fixture.Authority), fixture.Leaf, fixture.Authority), RevocationStatus.Good);
		}
	}

	// Sec. 5.2: a critical issuer alternative name is processed only if it decodes as GeneralNames; a noncritical one that does not is ignored, as one not understood.
	[Test]
	[Arguments(new byte[] { 0x05, 0x00 })]
	[Arguments(new byte[] { })]
	[Arguments(new byte[] { 0x30, 0x00 })]
	public async Task CriticalIssuerAlternativeNamesMustDecode(byte[] value)
	{
		using Fixture fixture = new();
		RevocationResult critical = Check(Conforming(fixture.Authority, null, Extension(IssuerAlternativeNameOid, value, Critical)).Decode(fixture.Authority), fixture.Leaf, fixture.Authority);
		RevocationResult noncritical = Check(Conforming(fixture.Authority, null, Extension(IssuerAlternativeNameOid, value)).Decode(fixture.Authority), fixture.Leaf, fixture.Authority);

		using (Assert.Multiple())
		{
			await AssertStatusAsync(critical, RevocationStatus.Invalid);
			await Assert.That(critical.Detail).IsEqualTo($"The CRL has the critical extension {IssuerAlternativeNameOid}, whose value does not decode.");
			await AssertStatusAsync(noncritical, RevocationStatus.Good);
		}
	}

	public static IEnumerable<Func<(string Case, string Form, byte[] Value)>> UnprocessedIssuerAlternativeNames()
	{
		byte[] partyName = Tlv(0xA1, Tlv(0x0C, "EDI party"u8.ToArray()));

		yield return () => ("x400Address", "X400Address", GeneralNames(Tlv(0xA3, Sequence())));
		yield return () => ("x400Address holding NULL", "X400Address", GeneralNames(Tlv(0xA3, NullValue)));
		yield return () => ("ediPartyName", "EdiPartyName", GeneralNames(Tlv(0xA5, partyName)));
		yield return () => ("ediPartyName with a NULL partyName", "EdiPartyName", GeneralNames(Tlv(0xA5, Tlv(0xA1, NullValue))));
		yield return () => ("ediPartyName with a BMPString of an odd length", "EdiPartyName", GeneralNames(Tlv(0xA5, Tlv(0xA1, Tlv(0x1E, [0x00, 0x41, 0x00])))));
		yield return () => ("ediPartyName after a dNSName", "EdiPartyName", GeneralNames(DnsName("crl.example"), Tlv(0xA5, partyName)));
	}

	// Sec. 5.2.2: the checker does not process the ORAddress of an x400Address or the DirectoryStrings of an ediPartyName, so a critical issuer alternative name with either is refused, well formed or not; a noncritical one is ignored.
	[Test]
	[MethodDataSource(nameof(UnprocessedIssuerAlternativeNames))]
	public async Task CriticalIssuerAlternativeNamesMustHaveOnlyProcessedForms(string @case, string form, byte[] value)
	{
		using Fixture fixture = new();
		RevocationResult critical = Check(Conforming(fixture.Authority, null, Extension(IssuerAlternativeNameOid, value, Critical)).Decode(fixture.Authority), fixture.Leaf, fixture.Authority);
		RevocationResult noncritical = Check(Conforming(fixture.Authority, null, Extension(IssuerAlternativeNameOid, value)).Decode(fixture.Authority), fixture.Leaf, fixture.Authority);

		using (Assert.Multiple())
		{
			await Assert.That(critical.Status).IsEqualTo(RevocationStatus.Invalid).Because(@case);
			await Assert.That(critical.Detail).IsEqualTo($"The CRL has the critical extension {IssuerAlternativeNameOid}, with a name of the form {form}, which the checker does not process.").Because(@case);
			await Assert.That(noncritical.Status).IsEqualTo(RevocationStatus.Good).Because(@case);
		}
	}

	// Sec. 5.3: a critical entry extension that is not understood forbids the use of the CRL for any certificate, not just the entry's.
	[Test]
	public async Task EntryExtensionsAreCheckedForEveryEntry()
	{
		using Fixture fixture = new();
		byte[] unknownCritical = Extension(PrivateOid, [0x05, 0x00], Critical);
		byte[] unknownNoncritical = Extension(PrivateOid, [0x05, 0x00]);
		CertificateRevocationList leafEntry = Conforming(fixture.Authority, [Entry(fixture.LeafSerial, null, unknownCritical)]).Decode(fixture.Authority);
		CertificateRevocationList otherEntry = Conforming(fixture.Authority, [Entry([0x7F], null, unknownCritical)]).Decode(fixture.Authority);
		CertificateRevocationList noncritical = Conforming(fixture.Authority, [Entry(fixture.LeafSerial, null, unknownNoncritical)]).Decode(fixture.Authority);
		CertificateRevocationList certificateIssuer = Conforming(fixture.Authority, [Entry([0x7F], null, Extension("2.5.29.29", Sequence(Tlv(0xA4, Name("CN=Other"))), Critical))]).Decode(fixture.Authority);
		CertificateRevocationList criticalReason = Conforming(fixture.Authority, [Entry(fixture.LeafSerial, null, ReasonCode(1, Critical))]).Decode(fixture.Authority);

		using (Assert.Multiple())
		{
			await AssertStatusAsync(Check(leafEntry, fixture.Leaf, fixture.Authority), RevocationStatus.Invalid);
			await AssertStatusAsync(Check(otherEntry, fixture.Leaf, fixture.Authority), RevocationStatus.Invalid);
			await AssertStatusAsync(Check(noncritical, fixture.Leaf, fixture.Authority), RevocationStatus.Revoked);
			await AssertStatusAsync(Check(certificateIssuer, fixture.Leaf, fixture.Authority), RevocationStatus.Invalid);
			await AssertStatusAsync(Check(criticalReason, fixture.Leaf, fixture.Authority), RevocationStatus.Revoked);
		}
	}

	[Test]
	[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "The delegate runs before the key is disposed.")]
	public async Task SignaturesAreVerifiedUnderThePolicy()
	{
		using Fixture fixture = new();
		using EcdsaP256 attacker = EcdsaP256.GenerateKey();
		Template template = Conforming(fixture.Authority);
		byte[] sha1Oid = Sequence(Oid("1.2.840.113549.1.1.5"), [0x05, 0x00]);
		byte[] unknownOid = Sequence(Oid("1.2.840.113549.1.1.2"), [0x05, 0x00]);
		CertificateRevocationList wrongKey = CertificateRevocationList.Decode(template.Encode(tbs => Signatures.SignatureTestUtils.Sign(attacker, Abstractions.Signatures.SignatureAlgorithm.EcdsaSha256, tbs)));
		CertificateRevocationList weak = (template with { InnerSignature = sha1Oid, OuterSignature = sha1Oid }).Decode(fixture.Authority);
		CertificateRevocationList unsupported = (template with { InnerSignature = Sequence(Oid("1.2.3.4")), OuterSignature = Sequence(Oid("1.2.3.4")) }).Decode(fixture.Authority);
		CertificateRevocationList md5 = (template with { InnerSignature = unknownOid, OuterSignature = unknownOid }).Decode(fixture.Authority);
		RevocationResult weakResult = Check(weak, fixture.Leaf, fixture.Authority);
		RevocationResult md5Result = Check(md5, fixture.Leaf, fixture.Authority);

		using (Assert.Multiple())
		{
			await AssertStatusAsync(Check(wrongKey, fixture.Leaf, fixture.Authority), RevocationStatus.Invalid);
			await AssertStatusAsync(weakResult, RevocationStatus.Invalid);
			await AssertStatusAsync(md5Result, RevocationStatus.Invalid);
			await AssertStatusAsync(Check(unsupported, fixture.Leaf, fixture.Authority), RevocationStatus.Invalid);
			await Assert.That(weakResult.Detail).Contains("refuses");
			await Assert.That(md5Result.Detail).Contains("refuses");
		}
	}

	// Sec. 5.2.4 and 5.2.5: a delta or an indirect CRL does not say that a certificate is good, even if it lists it.
	[Test]
	public async Task DeltaAndIndirectCrlsAreNotApplicable()
	{
		using Fixture fixture = new();
		byte[] entry = Entry(fixture.LeafSerial);
		CertificateRevocationList delta = Conforming(fixture.Authority, [entry], Extension(DeltaCrlIndicatorOid, [0x02, 0x01, 0x01], Critical)).Decode(fixture.Authority);
		CertificateRevocationList indirect = Conforming(fixture.Authority, [entry], IssuingDistributionPoint(Tlv(0x84, [0xFF]))).Decode(fixture.Authority);
		CertificateRevocationList nonCriticalDelta = Conforming(fixture.Authority, null, Extension(DeltaCrlIndicatorOid, [0x02, 0x01, 0x01])).Decode(fixture.Authority);

		using (Assert.Multiple())
		{
			await AssertStatusAsync(Check(delta, fixture.Leaf, fixture.Authority), RevocationStatus.NotApplicable);
			await AssertStatusAsync(Check(indirect, fixture.Leaf, fixture.Authority), RevocationStatus.NotApplicable);
			await AssertStatusAsync(Check(nonCriticalDelta, fixture.Leaf, fixture.Authority), RevocationStatus.NotApplicable);
		}
	}

	// Sec. 6.3.3 (b)(2) (ii) to (iv).
	[Test]
	public async Task TheScopeOfTheCrlLimitsTheCertificatesItCovers()
	{
		using Fixture fixture = new();
		Certificate caCertificate = fixture.Authority.Issue(new TestPki.Template { Subject = Name("CN=Sub"), SubjectPublicKeyInfo = fixture.Authority.Certificate.PublicKeyInfo.Encoded.ToArray(), Extensions = [TestPki.BasicConstraints(true)] });
		CertificateRevocationList userOnly = Conforming(fixture.Authority, null, IssuingDistributionPoint(Tlv(0x81, [0xFF]))).Decode(fixture.Authority);
		CertificateRevocationList caOnly = Conforming(fixture.Authority, null, IssuingDistributionPoint(Tlv(0x82, [0xFF]))).Decode(fixture.Authority);
		CertificateRevocationList attributeOnly = Conforming(fixture.Authority, null, IssuingDistributionPoint(Tlv(0x85, [0xFF]))).Decode(fixture.Authority);

		using (Assert.Multiple())
		{
			await AssertStatusAsync(Check(userOnly, fixture.Leaf, fixture.Authority), RevocationStatus.Good);
			await AssertStatusAsync(Check(userOnly, caCertificate, fixture.Authority), RevocationStatus.NotApplicable);
			await AssertStatusAsync(Check(caOnly, caCertificate, fixture.Authority), RevocationStatus.Good);
			await AssertStatusAsync(Check(caOnly, fixture.Leaf, fixture.Authority), RevocationStatus.NotApplicable);
			await AssertStatusAsync(Check(attributeOnly, fixture.Leaf, fixture.Authority), RevocationStatus.NotApplicable);
		}
	}

	// Sec. 6.3.3 (d) and (j): the reasons that the CRL covers; a listed certificate is revoked whatever they are.
	[Test]
	public async Task OnlySomeReasonsAreReported()
	{
		using Fixture fixture = new();
		byte[] onlyKeyCompromise = Tlv(0x83, [0x06, 0x40]);
		CertificateRevocationList partial = Conforming(fixture.Authority, null, IssuingDistributionPoint(onlyKeyCompromise)).Decode(fixture.Authority);
		CertificateRevocationList listed = Conforming(fixture.Authority, [Entry(fixture.LeafSerial)], IssuingDistributionPoint(onlyKeyCompromise)).Decode(fixture.Authority);
		RevocationResult partialResult = Check(partial, fixture.Leaf, fixture.Authority);

		using (Assert.Multiple())
		{
			await AssertStatusAsync(partialResult, RevocationStatus.NotApplicable);
			await Assert.That(partialResult.CoveredReasons).IsEqualTo(CrlReasonFlags.KeyCompromise);
			await AssertStatusAsync(Check(listed, fixture.Leaf, fixture.Authority), RevocationStatus.Revoked);
		}
	}

	// Sec. 6.3.3 (b)(2)(i): a distributionPoint in the extension must match a name of a distribution point of the certificate.
	[Test]
	public async Task DistributionPointNamesMustMatch()
	{
		using Fixture fixture = new();
		byte[] uri = TestPki.UniformResourceIdentifier("http://crl.example.test/ca.crl");
		byte[] otherUri = TestPki.UniformResourceIdentifier("http://other.example.test/ca.crl");
		Certificate leaf = fixture.Authority.IssueLeaf(more: [DistributionPoints(Sequence(FullName(0xA0, uri)))]);
		CertificateRevocationList matching = Conforming(fixture.Authority, null, IssuingDistributionPoint(FullName(0xA0, uri))).Decode(fixture.Authority);
		CertificateRevocationList other = Conforming(fixture.Authority, null, IssuingDistributionPoint(FullName(0xA0, otherUri))).Decode(fixture.Authority);
		CertificateRevocationList issuerName = Conforming(fixture.Authority, null, IssuingDistributionPoint(FullName(0xA0, TestPki.DirectoryName("CN=CRL Issuer")))).Decode(fixture.Authority);

		using (Assert.Multiple())
		{
			await AssertStatusAsync(Check(matching, leaf, fixture.Authority), RevocationStatus.Good);
			await AssertStatusAsync(Check(other, leaf, fixture.Authority), RevocationStatus.NotApplicable);

			// The last paragraph of Sec. 6.3.3 assumes a distribution point named by the certificate's issuer.
			await AssertStatusAsync(Check(issuerName, leaf, fixture.Authority), RevocationStatus.Good);
		}
	}

	// A name relative to the CRL issuer is the fragment appended to the CRL issuer's name (Sec. 4.2.1.13), which must equal the name in the DP.
	[Test]
	public async Task RelativeNamesAreExpandedAgainstTheIssuer()
	{
		using TestPki.Authority authority = TestPki.Authority.CreateRoot("CN=CRL Issuer, O=Example, C=US");
		byte[] relativeIdp = RelativeName(0xA0, CommonName("Partition 1"));
		byte[] fullEquivalent = TestPki.DirectoryName("CN=Partition 1, CN=CRL Issuer, O=Example, C=US");
		Certificate relativeLeaf = authority.IssueLeaf(more: [DistributionPoints(Sequence(RelativeName(0xA0, CommonName("Partition 1"))))]);
		Certificate fullLeaf = authority.IssueLeaf(more: [DistributionPoints(Sequence(FullName(0xA0, fullEquivalent)))]);
		Certificate otherLeaf = authority.IssueLeaf(more: [DistributionPoints(Sequence(RelativeName(0xA0, CommonName("Partition 2"))))]);
		CertificateRevocationList relative = Conforming(authority, null, IssuingDistributionPoint(relativeIdp)).Decode(authority);
		CertificateRevocationList full = Conforming(authority, null, IssuingDistributionPoint(FullName(0xA0, fullEquivalent))).Decode(authority);

		using (Assert.Multiple())
		{
			await AssertStatusAsync(Check(relative, relativeLeaf, authority), RevocationStatus.Good);
			await AssertStatusAsync(Check(relative, fullLeaf, authority), RevocationStatus.Good);
			await AssertStatusAsync(Check(full, relativeLeaf, authority), RevocationStatus.Good);
			await AssertStatusAsync(Check(relative, otherLeaf, authority), RevocationStatus.NotApplicable);
		}
	}

	// Sec. 6.3.3 (d)(1) and (e): the reasons of the matching distribution point restrict those of the CRL, and the assumed distribution point covers the issuer's own name only.
	[Test]
	public async Task DistributionPointReasonsRestrictTheScope()
	{
		using Fixture fixture = new();
		byte[] uri = TestPki.UniformResourceIdentifier("http://crl.example.test/ca.crl");
		byte[] keyCompromise = Tlv(0x81, [0x06, 0x40]);
		byte[] affiliationChanged = [0x83, 0x02, 0x04, 0x10];
		Certificate leaf = fixture.Authority.IssueLeaf(more: [DistributionPoints(Sequence(FullName(0xA0, uri), keyCompromise))]);
		CertificateRevocationList disjoint = Conforming(fixture.Authority, null, IssuingDistributionPoint(FullName(0xA0, uri), affiliationChanged)).Decode(fixture.Authority);
		CertificateRevocationList intersecting = Conforming(fixture.Authority, null, IssuingDistributionPoint(FullName(0xA0, uri), Tlv(0x83, [0x04, 0x50]))).Decode(fixture.Authority);
		RevocationResult intersectingResult = Check(intersecting, leaf, fixture.Authority);

		using (Assert.Multiple())
		{
			await AssertStatusAsync(Check(disjoint, leaf, fixture.Authority), RevocationStatus.NotApplicable);
			await Assert.That(intersectingResult.CoveredReasons).IsEqualTo(CrlReasonFlags.KeyCompromise);
			await AssertStatusAsync(intersectingResult, RevocationStatus.NotApplicable);
		}
	}

	// Sec. 6.3.3 (b)(1): a distribution point with a cRLIssuer is for an indirect CRL, which the checker does not support.
	[Test]
	public async Task DistributionPointsOfAnotherCrlIssuerAreSkipped()
	{
		using Fixture fixture = new();
		byte[] uri = TestPki.UniformResourceIdentifier("http://crl.example.test/ca.crl");
		byte[] crlIssuer = Tlv(0xA2, TestPki.DirectoryName("CN=Other"));
		Certificate leaf = fixture.Authority.IssueLeaf(more: [DistributionPoints(Sequence(FullName(0xA0, uri), crlIssuer))]);
		CertificateRevocationList named = Conforming(fixture.Authority, null, IssuingDistributionPoint(FullName(0xA0, uri))).Decode(fixture.Authority);
		CertificateRevocationList unnamed = Conforming(fixture.Authority).Decode(fixture.Authority);

		using (Assert.Multiple())
		{
			await AssertStatusAsync(Check(named, leaf, fixture.Authority), RevocationStatus.NotApplicable);

			// No IDP: the CRL of the certificate's issuer applies, by the last paragraph of Sec. 6.3.3.
			await AssertStatusAsync(Check(unnamed, leaf, fixture.Authority), RevocationStatus.Good);
		}
	}

	[Test]
	public async Task MalformedExtensionsOfTheCertificateMakeTheCheckInvalid()
	{
		using Fixture fixture = new();
		Certificate leaf = fixture.Authority.IssueLeaf(more: [new CertificateExtension(CrlDistributionPointsOid, false, (byte[])[0x05, 0x00])]);
		CertificateRevocationList crl = Conforming(fixture.Authority, null, IssuingDistributionPoint(FullName(0xA0, TestPki.UniformResourceIdentifier("http://crl.example.test/")))).Decode(fixture.Authority);

		await AssertStatusAsync(Check(crl, leaf, fixture.Authority), RevocationStatus.Invalid);
	}

	[Test]
	public async Task IssuingDistributionPointsAreDecoded()
	{
		using Fixture fixture = new();
		byte[] uri = TestPki.UniformResourceIdentifier("http://crl.example.test/ca.crl");
		byte[] onlySomeReasons = Tlv(0x83, [0x06, 0x40]);
		CertificateRevocationList crl = Conforming(fixture.Authority, null, IssuingDistributionPoint(FullName(0xA0, uri), Tlv(0x81, [0xFF]), onlySomeReasons)).Decode(fixture.Authority);

		IssuingDistributionPoint? value = crl.GetIssuingDistributionPoint();

		using (Assert.Multiple())
		{
			await Assert.That(value).IsNotNull();
			await Assert.That(value?.DistributionPoint?.Uris).IsEquivalentTo((string[])["http://crl.example.test/ca.crl"], CollectionOrdering.Matching);
			await Assert.That(value?.OnlyContainsUserCertificates).IsTrue();
			await Assert.That(value?.OnlyContainsCACertificates).IsFalse();
			await Assert.That(value?.IndirectCrl).IsFalse();
			await Assert.That(value?.OnlySomeReasons).IsEqualTo(CrlReasonFlags.KeyCompromise);
		}
	}

	// Sec. 5.2.5: the rules of the extension's syntax, which decoding checks.
	[Test]
	public async Task IssuingDistributionPointsMustBeWellFormed()
	{
		using Fixture fixture = new();
		byte[] empty = IssuingDistributionPoint();
		byte[] two = IssuingDistributionPoint(Tlv(0x81, [0xFF]), Tlv(0x82, [0xFF]));
		byte[] explicitFalse = IssuingDistributionPoint(Tlv(0x81, [0x00]));
		byte[] trailing = IssuingDistributionPoint(Tlv(0x81, [0xFF]), [0x05, 0x00]);
		byte[] undefinedBit = IssuingDistributionPoint(Tlv(0x83, [0x06, 0x00, 0x40]));

		using (Assert.Multiple())
		{
			foreach (byte[] extension in (byte[][])[empty, two, explicitFalse, trailing, undefinedBit])
			{
				CertificateRevocationList crl = Conforming(fixture.Authority, null, extension).Decode(fixture.Authority);

				await Assert.That(() => crl.GetIssuingDistributionPoint()).Throws<System.Security.Cryptography.CryptographicException>();
				await AssertStatusAsync(Check(crl, fixture.Leaf, fixture.Authority), RevocationStatus.Invalid);
			}
		}
	}
}
