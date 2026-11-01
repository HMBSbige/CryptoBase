using CryptoBase.X509;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using static CryptoBase.Tests.TestUtils;
using static CryptoBase.Tests.X509.X509TestUtils;

namespace CryptoBase.Tests.X509;

// The authority and subject key identifier extensions (RFC 5280, Sec. 4.2.1.1 and 4.2.1.2).
public class KeyIdentifierTest
{
	private const string AuthorityKeyIdentifierOid = "2.5.29.35";
	private const string SubjectKeyIdentifierOid = "2.5.29.14";

	[Test]
	public async Task AuthorityKeyIdentifiersDecodeAsTheBclEncodes()
	{
		byte[] keyIdentifier = RandomNumberGenerator.GetBytes(20);
		byte[] serialNumber = [0x00, 0x8F, 0x01];
		X500DistinguishedName issuer = new("CN=Issuer, O=CryptoBase");
		X509AuthorityKeyIdentifierExtension all = X509AuthorityKeyIdentifierExtension.Create(keyIdentifier, issuer, serialNumber);
		X509AuthorityKeyIdentifierExtension keyOnly = X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(keyIdentifier);
		X509AuthorityKeyIdentifierExtension issuerOnly = X509AuthorityKeyIdentifierExtension.CreateFromIssuerNameAndSerialNumber(issuer, serialNumber);

		AuthorityKeyIdentifier decoded = AuthorityKeyIdentifier.Decode(all.RawData);

		using (Assert.Multiple())
		{
			await Assert.That(decoded.KeyIdentifier?.ToArray()).IsEquivalentTo(keyIdentifier, CollectionOrdering.Matching);
			await Assert.That(decoded.AuthorityCertIssuer?.Single() is { Type: GeneralNameType.DirectoryName } name && name.Value.Span.SequenceEqual(issuer.RawData)).IsTrue();
			await Assert.That(decoded.AuthorityCertSerialNumber?.ToArray()).IsEquivalentTo(all.SerialNumber?.ToArray() ?? [], CollectionOrdering.Matching);
			await Assert.That(AuthorityKeyIdentifier.Decode(keyOnly.RawData) is { KeyIdentifier: not null, AuthorityCertIssuer: null, AuthorityCertSerialNumber: null }).IsTrue();
			await Assert.That(AuthorityKeyIdentifier.Decode(issuerOnly.RawData) is { KeyIdentifier: null, AuthorityCertIssuer.Count: 1, AuthorityCertSerialNumber: not null }).IsTrue();
		}
	}

	// Every field is optional, a key identifier may be empty, and the serial number may be negative, as a certificate's may.
	[Test]
	public async Task AuthorityKeyIdentifiersMayOmitTheirFields()
	{
		AuthorityKeyIdentifier empty = AuthorityKeyIdentifier.Decode(Sequence());
		AuthorityKeyIdentifier emptyKeyIdentifier = AuthorityKeyIdentifier.Decode(Sequence(Tlv(0x80)));
		AuthorityKeyIdentifier negativeSerialNumber = AuthorityKeyIdentifier.Decode(Sequence(Tlv(0xA1, Tlv(0xA4, Name("CN=Issuer"))), Tlv(0x82, [0xFF])));

		using (Assert.Multiple())
		{
			await Assert.That(empty is { KeyIdentifier: null, AuthorityCertIssuer: null, AuthorityCertSerialNumber: null }).IsTrue();
			await Assert.That(emptyKeyIdentifier.KeyIdentifier is { IsEmpty: true }).IsTrue();
			await Assert.That(negativeSerialNumber.AuthorityCertSerialNumber?.ToArray()).IsEquivalentTo((byte[])[0xFF], CollectionOrdering.Matching);
		}
	}

	public static IEnumerable<Func<(string Case, byte[] Encoding)>> MalformedAuthorityKeyIdentifiers()
	{
		byte[] valid = Sequence(Tlv(0x80, [0x01, 0x02]));

		yield return () => ("empty", []);
		yield return () => ("not a SEQUENCE", Tlv(0x04, [0x01]));
		yield return () => ("trailing byte", [.. valid, 0x00]);
		yield return () => ("length in more bytes than DER allows", WithRedundantLengthByte(valid));
		yield return () => ("untagged keyIdentifier", Sequence(Tlv(0x04, [0x01])));
		yield return () => ("constructed keyIdentifier", Sequence(Tlv(0xA0, Tlv(0x04, [0x01]))));
		yield return () => ("keyIdentifier twice", Sequence(Tlv(0x80, [0x01]), Tlv(0x80, [0x02])));
		yield return () => ("primitive authorityCertIssuer", Sequence(Tlv(0x81, Name("CN=Issuer"))));
		yield return () => ("authorityCertIssuer without names", Sequence(Tlv(0xA1), Tlv(0x82, [0x01])));
		yield return () => ("authorityCertIssuer with an unknown tag", Sequence(Tlv(0xA1, Tlv(0x89, [0x00])), Tlv(0x82, [0x01])));
		yield return () => ("authorityCertIssuer with an iPAddress of 5 octets", Sequence(Tlv(0xA1, Tlv(0x87, [192, 0, 2, 1, 0])), Tlv(0x82, [0x01])));
		yield return () => ("serial number with a redundant leading byte", Sequence(Tlv(0x82, [0x00, 0x01])));
		yield return () => ("empty serial number", Sequence(Tlv(0x82)));
		yield return () => ("constructed serial number", Sequence(Tlv(0xA2, [0x02, 0x01, 0x01])));
		yield return () => ("fields out of order", Sequence(Tlv(0x82, [0x01]), Tlv(0x80, [0x01])));
		yield return () => ("unknown field", Sequence(Tlv(0x80, [0x01]), Tlv(0x83, [0x01])));
	}

	[Test]
	[MethodDataSource(nameof(MalformedAuthorityKeyIdentifiers))]
	public async Task MalformedAuthorityKeyIdentifiersThrow(string @case, byte[] encoding)
	{
		using (Assert.Multiple())
		{
			await Assert.That(() => AuthorityKeyIdentifier.Decode(encoding)).Throws<ArgumentException>().WithParameterName("source").Because(@case);
			await Assert.That(() => WithExtensions(Extension(AuthorityKeyIdentifierOid, encoding)).GetAuthorityKeyIdentifier()).ThrowsExactly<CryptographicException>().Because(@case);
		}
	}

	[Test]
	public async Task AuthorityKeyIdentifierDecodeCopiesItsInput()
	{
		byte[] encoding = Sequence(Tlv(0x80, [0x01, 0x02]));
		AuthorityKeyIdentifier decoded = AuthorityKeyIdentifier.Decode(encoding);
		Array.Clear(encoding);

		await Assert.That(decoded.KeyIdentifier?.ToArray()).IsEquivalentTo((byte[])[0x01, 0x02], CollectionOrdering.Matching);
	}

	public static IEnumerable<Func<(string Case, byte[] Value, byte[]? Expected)>> SubjectKeyIdentifiers()
	{
		byte[] identifier = [.. Enumerable.Range(1, 20).Select(static value => (byte)value)];

		yield return () => ("twenty bytes", Tlv(0x04, identifier), identifier);
		yield return () => ("empty", Tlv(0x04), []);
		yield return () => ("not an OCTET STRING", Sequence(), null);
		yield return () => ("trailing byte", [.. Tlv(0x04, identifier), 0x00], null);
		yield return () => ("constructed", Tlv(0x24, Tlv(0x04, identifier)), null);
		yield return () => ("length in more bytes than DER allows", WithRedundantLengthByte(Tlv(0x04, identifier)), null);
	}

	[Test]
	[MethodDataSource(nameof(SubjectKeyIdentifiers))]
	public async Task SubjectKeyIdentifiersDecodeOnlyFromDer(string @case, byte[] value, byte[]? expected)
	{
		Certificate certificate = WithExtensions(Extension(SubjectKeyIdentifierOid, value));

		if (expected is null)
		{
			await Assert.That(() => certificate.GetSubjectKeyIdentifier()).ThrowsExactly<CryptographicException>().Because(@case);
		}
		else
		{
			await Assert.That(certificate.GetSubjectKeyIdentifier()?.ToArray()).IsEquivalentTo(expected, CollectionOrdering.Matching).Because(@case);
		}
	}

	// A CA's subject key identifier is the authority key identifier of what it issues; a self-signed certificate names its own key, and a key rollover certificate, which a CA issues to itself with another key, does not (RFC 5280, Sec. 4.2.1.1 and 4.2.1.2).
	[Test]
	public async Task KeyIdentifiersLinkACertificateToItsIssuer()
	{
		using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
		using ECDsa nextKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
		CertificateRequest rootRequest = new("CN=Root", rootKey, HashAlgorithmName.SHA256);
		X509SubjectKeyIdentifierExtension rootIdentifier = new(rootRequest.PublicKey, false);
		rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
		rootRequest.CertificateExtensions.Add(rootIdentifier);
		rootRequest.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(rootIdentifier));
		using X509Certificate2 root = rootRequest.CreateSelfSigned(Now.AddDays(-1), Now.AddDays(1));
		CertificateRequest rolloverRequest = new("CN=Root", nextKey, HashAlgorithmName.SHA256);
		rolloverRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rolloverRequest.PublicKey, false));
		rolloverRequest.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(root, true, false));
		using X509Certificate2 rollover = rolloverRequest.Create(root, Now.AddDays(-1), Now.AddDays(1), [0x02]);

		Certificate selfSigned = Certificate.Decode(root.RawData);
		Certificate rolledOver = Certificate.Decode(rollover.RawData);

		using (Assert.Multiple())
		{
			await Assert.That(selfSigned.GetSubjectKeyIdentifier()?.ToArray()).IsEquivalentTo(rootIdentifier.SubjectKeyIdentifierBytes.ToArray(), CollectionOrdering.Matching);
			await Assert.That(selfSigned.GetAuthorityKeyIdentifier()?.KeyIdentifier?.ToArray()).IsEquivalentTo(rootIdentifier.SubjectKeyIdentifierBytes.ToArray(), CollectionOrdering.Matching);
			await Assert.That(rolledOver.GetAuthorityKeyIdentifier()?.KeyIdentifier?.ToArray()).IsEquivalentTo(rootIdentifier.SubjectKeyIdentifierBytes.ToArray(), CollectionOrdering.Matching);
			await Assert.That(rolledOver.GetSubjectKeyIdentifier() is { } subjectKey && rolledOver.GetAuthorityKeyIdentifier()?.KeyIdentifier is { } authorityKey && !subjectKey.Span.SequenceEqual(authorityKey.Span)).IsTrue();
			await Assert.That(rolledOver.Subject.Span.SequenceEqual(rolledOver.Issuer.Span)).IsTrue();
		}
	}
}
