using CryptoBase.X509;
using System.Security.Cryptography;
using static CryptoBase.Tests.TestUtils;
using static CryptoBase.Tests.X509.X509TestUtils;

namespace CryptoBase.Tests.X509;

public class AccessExtensionsTest
{
	private static readonly byte[] OcspMethod = Oid("1.3.6.1.5.5.7.48.1");
	private static readonly byte[] CAIssuersMethod = Oid("1.3.6.1.5.5.7.48.2");

	private static Certificate WithExtension(string oid, byte[] value)
	{
		return WithExtensions(Extension(oid, value));
	}

	private static Certificate WithAccess(params byte[][] descriptions)
	{
		return WithExtension("1.3.6.1.5.5.7.1.1", Sequence(descriptions));
	}

	private static Certificate WithPoints(params byte[][] points)
	{
		return WithExtension(TestCrl.CrlDistributionPointsOid, Sequence(points));
	}

	// The certificates of the vectors hold the two extensions, with several values.
	[Test]
	public async Task OpenSslExtensionsDecode()
	{
		Certificate certificate = Certificate.DecodePem(OcspVectors.Good);

		AuthorityInformationAccess access = certificate.GetAuthorityInformationAccess() ?? throw new InvalidOperationException();
		IReadOnlyList<CrlDistributionPoint> points = certificate.GetCrlDistributionPoints() ?? throw new InvalidOperationException();

		using (Assert.Multiple())
		{
			await Assert.That(access.OcspUris).IsEquivalentTo((string[])["http://ocsp.example.test/"], CollectionOrdering.Matching);
			await Assert.That(access.CAIssuersUris).IsEquivalentTo((string[])["http://ca.example.test/ca.cer", "ldap://ca.example.test/cn=ca"], CollectionOrdering.Matching);
			await Assert.That(access.Descriptions.Count).IsEqualTo(3);
			await Assert.That(points.Count).IsEqualTo(2);
			await Assert.That(points[0].DistributionPoint?.Uris).IsEquivalentTo((string[])["http://crl.example.test/ca.crl"], CollectionOrdering.Matching);
			await Assert.That(points[1].DistributionPoint?.Uris).IsEquivalentTo((string[])["ldap://crl.example.test/cn=ca"], CollectionOrdering.Matching);
			await Assert.That(points[0].Reasons).IsNull();
			await Assert.That(points[0].CrlIssuerDirectoryNames).IsEmpty();
			await Assert.That(points[0].CrlIssuer).IsNull();
			await Assert.That(points[0].DistributionPoint).IsTypeOf<DistributionPointName.FullName>();
		}
	}

	[Test]
	public async Task ACertificateWithoutTheExtensionsHasNoValues()
	{
		Certificate certificate = SelfSignedP256();

		using (Assert.Multiple())
		{
			await Assert.That(certificate.GetAuthorityInformationAccess()).IsNull();
			await Assert.That(certificate.GetCrlDistributionPoints()).IsNull();
		}
	}

	// Sec. 4.2.2.1: access methods and locations that are not URIs are kept; only the URIs of the two methods appear in the lists.
	[Test]
	public async Task EveryAccessDescriptionIsKept()
	{
		byte[] directoryName = TestPki.DirectoryName("CN=Repository");
		byte[] http = TestPki.UniformResourceIdentifier("http://ca.example.test/ca.cer");
		byte[] ocsp = TestPki.UniformResourceIdentifier("http://ocsp.example.test/");
		Certificate certificate = WithAccess(Sequence(OcspMethod, directoryName), Sequence(CAIssuersMethod, http), Sequence(Oid("1.3.6.1.5.5.7.48.3"), ocsp), Sequence(OcspMethod, ocsp));

		AuthorityInformationAccess access = certificate.GetAuthorityInformationAccess() ?? throw new InvalidOperationException();

		using (Assert.Multiple())
		{
			await Assert.That(access.OcspUris).IsEquivalentTo((string[])["http://ocsp.example.test/"], CollectionOrdering.Matching);
			await Assert.That(access.CAIssuersUris).IsEquivalentTo((string[])["http://ca.example.test/ca.cer"], CollectionOrdering.Matching);
			await Assert.That(access.Descriptions.Count).IsEqualTo(4);
			await Assert.That(access.Descriptions[0].Location.Type).IsEqualTo(GeneralNameType.DirectoryName);
			await Assert.That(access.Descriptions[2].Method).IsEqualTo("1.3.6.1.5.5.7.48.3");
		}
	}

	[Test]
	public async Task MalformedAccessExtensionsThrowWhenAskedFor()
	{
		byte[] ocsp = TestPki.UniformResourceIdentifier("http://ocsp.example.test/");
		Certificate empty = WithExtension("1.3.6.1.5.5.7.1.1", Sequence());
		Certificate notOid = WithAccess(Sequence(Tlv(0x04, [0x01]), ocsp));
		Certificate badLocation = WithAccess(Sequence(OcspMethod, Tlv(0x8F, [0x01])));
		Certificate badAddress = WithAccess(Sequence(OcspMethod, Tlv(0x87, [0x01, 0x02])));
		Certificate extra = WithAccess(Sequence(OcspMethod, ocsp, [0x05, 0x00]));
		Certificate nonAscii = WithAccess(Sequence(OcspMethod, Tlv(0x86, [0xFF])));

		using (Assert.Multiple())
		{
			foreach (Certificate certificate in (Certificate[])[empty, notOid, badLocation, badAddress, extra, nonAscii])
			{
				await Assert.That(() => certificate.GetAuthorityInformationAccess()).Throws<CryptographicException>();
			}
		}
	}

	[Test]
	public async Task DistributionPointsDecodeTheirFields()
	{
		byte[] uri = TestPki.UniformResourceIdentifier("http://crl.example.test/ca.crl");
		byte[] directoryName = TestPki.DirectoryName("CN=CRL Directory");
		byte[] crlIssuerName = TestPki.DirectoryName("CN=CRL Issuer");
		byte[] reasons = Tlv(0x81, [0x06, 0x40]);
		byte[] allNine = Tlv(0x81, [0x07, 0x7F, 0x80]);
		Certificate certificate = WithPoints(
			Sequence(TestCrl.FullName(0xA0, uri, directoryName), reasons, Tlv(0xA2, crlIssuerName)),
			Sequence(TestCrl.RelativeName(0xA0, TestCrl.CommonName("Partition 1"))),
			Sequence(Tlv(0xA2, crlIssuerName)),
			Sequence(TestCrl.FullName(0xA0, uri), allNine));

		IReadOnlyList<CrlDistributionPoint> points = certificate.GetCrlDistributionPoints() ?? throw new InvalidOperationException();

		using (Assert.Multiple())
		{
			await Assert.That(points.Count).IsEqualTo(4);
			await Assert.That(points[0].DistributionPoint?.Uris).IsEquivalentTo((string[])["http://crl.example.test/ca.crl"], CollectionOrdering.Matching);
			await Assert.That((points[0].DistributionPoint as DistributionPointName.FullName)?.Names.Count).IsEqualTo(2);
			await Assert.That(points[0].Reasons).IsEqualTo(CrlReasonFlags.KeyCompromise);
			await Assert.That(points[0].CrlIssuer?.Count).IsEqualTo(1);
			await Assert.That(points[0].CrlIssuerDirectoryNames.Single()).IsEquivalentTo(Name("CN=CRL Issuer"), CollectionOrdering.Matching);
			await Assert.That(points[1].DistributionPoint?.Uris).IsEmpty();
			await Assert.That((points[1].DistributionPoint as DistributionPointName.RelativeToCrlIssuer)?.RelativeName.ToArray()).IsEquivalentTo(TestCrl.CommonName("Partition 1"), CollectionOrdering.Matching);
			await Assert.That(points[2].DistributionPoint).IsNull();
			await Assert.That(points[3].Reasons).IsEqualTo(CrlReasonFlags.KeyCompromise | CrlReasonFlags.CACompromise | CrlReasonFlags.AffiliationChanged | CrlReasonFlags.Superseded | CrlReasonFlags.CessationOfOperation | CrlReasonFlags.CertificateHold | CrlReasonFlags.PrivilegeWithdrawn | CrlReasonFlags.AACompromise);
		}
	}

	[Test]
	public async Task MalformedDistributionPointsThrowWhenAskedFor()
	{
		byte[] uri = TestPki.UniformResourceIdentifier("http://crl.example.test/ca.crl");
		byte[] reasons = Tlv(0x81, [0x06, 0x40]);
		Certificate empty = WithExtension(TestCrl.CrlDistributionPointsOid, Sequence());
		Certificate reasonsOnly = WithPoints(Sequence(reasons));
		Certificate nothing = WithPoints(Sequence());
		Certificate emptyFullName = WithPoints(Sequence(Tlv(0xA0, Tlv(0xA0))));
		Certificate emptyRelative = WithPoints(Sequence(Tlv(0xA0, Tlv(0xA1))));
		Certificate relativeNotAttribute = WithPoints(Sequence(Tlv(0xA0, Tlv(0xA1, [0x05, 0x00]))));
		Certificate bothNames = WithPoints(Sequence(Tlv(0xA0, Tlv(0xA0, uri), Tlv(0xA1, TestCrl.CommonName("Partition")))));
		Certificate undefinedReason = WithPoints(Sequence(TestCrl.FullName(0xA0, uri), Tlv(0x81, [0x06, 0x00, 0x40])));
		Certificate outOfOrder = WithPoints(Sequence(reasons, TestCrl.FullName(0xA0, uri)));

		using (Assert.Multiple())
		{
			foreach (Certificate certificate in (Certificate[])[empty, reasonsOnly, nothing, emptyFullName, emptyRelative, relativeNotAttribute, bothNames, undefinedReason, outOfOrder])
			{
				await Assert.That(() => certificate.GetCrlDistributionPoints()).Throws<CryptographicException>();
			}
		}
	}

	[Test]
	public async Task ReasonsAcceptTrailingZeros()
	{
		byte[] uri = TestPki.UniformResourceIdentifier("http://crl.example.test/ca.crl");
		Certificate certificate = WithPoints(Sequence(TestCrl.FullName(0xA0, uri), Tlv(0x81, [0x00, 0x40, 0x00])));

		await Assert.That(certificate.GetCrlDistributionPoints()?[0].Reasons).IsEqualTo(CrlReasonFlags.KeyCompromise);
	}
}
