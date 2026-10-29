using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures;
using CryptoBase.Signatures.Ecdsa;
using CryptoBase.Tests.Signatures.Ecdsa;
using CryptoBase.X509;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using static CryptoBase.Tests.Signatures.SignatureTestUtils;
using static CryptoBase.Tests.TestUtils;
using static CryptoBase.Tests.X509.X509TestUtils;

namespace CryptoBase.Tests.X509;

public class CertificateTest
{
	[Test]
	[MatrixDataSource]
	public async Task DecodesWhatTheBclEncodes([Matrix(256, 384, 521)] int curveBits, [Matrix(SignatureAlgorithm.EcdsaSha256, SignatureAlgorithm.EcdsaSha384, SignatureAlgorithm.EcdsaSha512)] SignatureAlgorithm algorithm)
	{
		using ECDsa key = ECDsa.Create(EcdsaCurve(curveBits).Curve);
		using X509Certificate2 expected = BclSelfSigned(key, EcdsaTestUtils.HashName(algorithm), "CN=Decode, O=CryptoBase", static request =>
		{
			request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
			request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
			request.CertificateExtensions.Add(SubjectAlternativeName("example.com", "192.0.2.1"));
			request.CertificateExtensions.Add(EnhancedKeyUsage(ServerAuthenticationOid));
		});

		Certificate certificate = Certificate.Decode(expected.RawData);
		using ISignatureKey publicKey = SignatureKey.ImportSubjectPublicKeyInfo(certificate.PublicKeyInfo.Encoded.Span);

		using (Assert.Multiple())
		{
			await Assert.That(certificate.Encoded.ToArray()).IsEquivalentTo(expected.RawData, CollectionOrdering.Matching);
			await Assert.That(certificate.Version).IsEqualTo(expected.Version);
			await Assert.That(certificate.SerialNumber.ToArray()).IsEquivalentTo(expected.SerialNumberBytes.ToArray(), CollectionOrdering.Matching);
			await Assert.That(certificate.Issuer.ToArray()).IsEquivalentTo(expected.IssuerName.RawData, CollectionOrdering.Matching);
			await Assert.That(certificate.Subject.ToArray()).IsEquivalentTo(expected.SubjectName.RawData, CollectionOrdering.Matching);
			await Assert.That(certificate.NotBefore.UtcDateTime).IsEqualTo(expected.NotBefore.ToUniversalTime());
			await Assert.That(certificate.NotAfter.UtcDateTime).IsEqualTo(expected.NotAfter.ToUniversalTime());
			await Assert.That(certificate.NotBefore.Offset).IsEqualTo(TimeSpan.Zero);
			await Assert.That(certificate.PublicKeyInfo.Encoded.ToArray()).IsEquivalentTo(expected.PublicKey.ExportSubjectPublicKeyInfo(), CollectionOrdering.Matching);
			await Assert.That(certificate.PublicKeyInfo.Algorithm.Oid).IsEqualTo("1.2.840.10045.2.1");
			await Assert.That(certificate.SignatureAlgorithm.Oid).IsEqualTo(expected.SignatureAlgorithm.Value);
			await Assert.That(certificate.SignatureAlgorithm.Parameters.IsEmpty).IsTrue();
			await Assert.That(certificate.Extensions.Select(static extension => (extension.Oid, extension.Critical, Value: Convert.ToHexString(extension.Value.Span)))).IsEquivalentTo(expected.Extensions.Select(static extension => (extension.Oid?.Value ?? "", extension.Critical, Value: Convert.ToHexString(extension.RawData))), CollectionOrdering.Matching);
			await Assert.That(certificate.VerifySignature(publicKey)).IsTrue();
			await Assert.That(key.VerifyData(certificate.TbsCertificate.Span, certificate.Signature.Span, EcdsaTestUtils.HashName(algorithm), DSASignatureFormat.Rfc3279DerSequence)).IsTrue();
			await Assert.That(certificate.KeyUsage).IsEqualTo(X509KeyUsageFlags.DigitalSignature);
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task KeyUsageMatchesTheBcl([Matrix(X509KeyUsageFlags.DigitalSignature, X509KeyUsageFlags.KeyAgreement, X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, X509KeyUsageFlags.EncipherOnly, X509KeyUsageFlags.DecipherOnly, X509KeyUsageFlags.KeyAgreement | X509KeyUsageFlags.DecipherOnly, (X509KeyUsageFlags)0x80FF)] X509KeyUsageFlags usage)
	{
		CertificateParts parts = new();
		byte[] value = new X509KeyUsageExtension(usage, true).RawData;

		Certificate certificate = Certificate.Decode((parts with { AfterSubjectPublicKeyInfo = [Extensions(Extension("2.5.29.15", value, [0x01, 0x01, 0xFF]))] }).Encode());

		await Assert.That(certificate.KeyUsage).IsEqualTo(usage);
	}

	[Test]
	public async Task KeyUsageIsNullWithoutTheExtension()
	{
		CertificateParts parts = new();

		using (Assert.Multiple())
		{
			await Assert.That(Certificate.Decode(parts.Encode()).KeyUsage).IsNull();
			await Assert.That(Certificate.Decode((parts with { Version = null }).Encode()).KeyUsage).IsNull();
			await Assert.That(Certificate.Decode((parts with { AfterSubjectPublicKeyInfo = [Extensions(Extension("2.5.29.19", [0x30, 0x00]))] }).Encode()).KeyUsage).IsNull();
		}
	}

	[Test]
	public async Task PemDecodesAndSkipsOtherText()
	{
		Certificate first = SelfSignedP256();
		Certificate second = SelfSignedP256();
		string text = $"header\n{PemEncoding.WriteString("PUBLIC KEY", first.PublicKeyInfo.Encoded.Span)}\n{PemEncoding.WriteString("CERTIFICATE", first.Encoded.Span)}\nbetween\n{PemEncoding.WriteString("CERTIFICATE", second.Encoded.Span)}\n";
		Certificate[] all = Certificate.DecodePemAll(text);

		using (Assert.Multiple())
		{
			await Assert.That(Certificate.DecodePem(text).Encoded.ToArray()).IsEquivalentTo(first.Encoded.ToArray(), CollectionOrdering.Matching);
			await Assert.That(all.Select(static certificate => Convert.ToHexString(certificate.Encoded.Span))).IsEquivalentTo([Convert.ToHexString(first.Encoded.Span), Convert.ToHexString(second.Encoded.Span)], CollectionOrdering.Matching);
			await Assert.That(Certificate.DecodePemAll("no blocks")).IsEmpty();
			await Assert.That(() => Certificate.DecodePem(PemEncoding.WriteString("PUBLIC KEY", first.PublicKeyInfo.Encoded.Span))).Throws<ArgumentException>().WithParameterName("source");
			await Assert.That(() => Certificate.DecodePem(PemEncoding.WriteString("CERTIFICATE", [0x30, 0x00]))).Throws<ArgumentException>().WithParameterName("source");
			await Assert.That(() => Certificate.DecodePemAll(PemEncoding.WriteString("CERTIFICATE", [0x30, 0x00]))).Throws<ArgumentException>().WithParameterName("source");
		}
	}

	[Test]
	public async Task SignatureVerifiesOnlyWithTheIssuerKey()
	{
		using EcdsaP256 key = EcdsaP256.GenerateKey();
		using EcdsaP256 other = EcdsaP256.GenerateKey();
		using EcdsaP384 otherCurve = EcdsaP384.GenerateKey();
		Certificate certificate = SelfSigned(key, SignatureAlgorithm.EcdsaSha256);
		byte[] tampered = certificate.Encoded.ToArray();
		tampered[certificate.Encoded.Length - certificate.Signature.Length - 40] ^= 1;

		using (Assert.Multiple())
		{
			await Assert.That(certificate.VerifySignature(key)).IsTrue();
			await Assert.That(certificate.VerifySignature(other)).IsFalse();

			// ecdsa-with-SHA256 does not bind the curve, so a key on another curve only fails to verify.
			await Assert.That(certificate.VerifySignature(otherCurve)).IsFalse();
			await Assert.That(Certificate.Decode(tampered).VerifySignature(key)).IsFalse();
			await Assert.That(() => certificate.VerifySignature(null!)).ThrowsExactly<ArgumentNullException>();
		}
	}

	[Test]
	public async Task OtherAlgorithmsDecodeButDoNotVerify()
	{
		using RSA key = RSA.Create(2048);
		CertificateRequest request = new("CN=RSA", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
		using X509Certificate2 rsa = request.CreateSelfSigned(Now.AddDays(-1), Now.AddDays(1));
		using EcdsaP256 ecdsa = EcdsaP256.GenerateKey();

		Certificate certificate = Certificate.Decode(rsa.RawData);

		using (Assert.Multiple())
		{
			await Assert.That(certificate.SignatureAlgorithm.Oid).IsEqualTo("1.2.840.113549.1.1.11");
			await Assert.That(certificate.SignatureAlgorithm.TryGetSignatureAlgorithm(out _)).IsFalse();
			await Assert.That(certificate.VerifySignature(ecdsa)).IsFalse();
			await Assert.That(() => EcdsaP256.ImportSubjectPublicKeyInfo(certificate.PublicKeyInfo.Encoded.Span)).Throws<ArgumentException>();
			await Assert.That(() => SignatureKey.ImportSubjectPublicKeyInfo(certificate.PublicKeyInfo.Encoded.Span)).ThrowsExactly<NotSupportedException>();
		}
	}

	[Test]
	public async Task AcceptsWhatRfc5280AsksUsersToTolerate()
	{
		CertificateParts parts = new();
		Certificate version1 = Certificate.Decode((parts with { Version = null }).Encode());
		Certificate version2 = Certificate.Decode((parts with { Version = Tlv(0xA0, [0x02, 0x01, 0x01]), AfterSubjectPublicKeyInfo = [Tlv(0x81, [0x07, 0x80]), Tlv(0x82, [0x00, 0x01])] }).Encode());
		Certificate negative = Certificate.Decode((parts with { SerialNumber = [0x02, 0x01, 0xFF] }).Encode());
		Certificate zero = Certificate.Decode((parts with { SerialNumber = [0x02, 0x01, 0x00] }).Encode());
		Certificate emptySubject = Certificate.Decode((parts with { Subject = Sequence() }).Encode());
		Certificate unknownCritical = Certificate.Decode((parts with { AfterSubjectPublicKeyInfo = [Extensions(Extension("1.3.6.1.4.1.99999.1", [0x05, 0x00], [0x01, 0x01, 0xFF]))] }).Encode());

		using (Assert.Multiple())
		{
			await Assert.That(version1.Version).IsEqualTo(1);
			await Assert.That(version1.Extensions).IsEmpty();
			await Assert.That(version2.Version).IsEqualTo(2);
			await Assert.That(negative.SerialNumber.ToArray()).IsEquivalentTo((byte[])[0xFF], CollectionOrdering.Matching);
			await Assert.That(zero.SerialNumber.ToArray()).IsEquivalentTo((byte[])[0x00], CollectionOrdering.Matching);
			await Assert.That(emptySubject.Subject.ToArray()).IsEquivalentTo((byte[])[0x30, 0x00], CollectionOrdering.Matching);
			await Assert.That(unknownCritical.Extensions.Single().Critical).IsTrue();
			await Assert.That(unknownCritical.Extensions.Single().Value.ToArray()).IsEquivalentTo((byte[])[0x05, 0x00], CollectionOrdering.Matching);
		}
	}

	[Test]
	public async Task TimesFollowRfc5280()
	{
		CertificateParts parts = new();
		DateTimeOffset last = new(2049, 12, 31, 23, 59, 59, TimeSpan.Zero);
		DateTimeOffset first = new(1950, 1, 1, 0, 0, 0, TimeSpan.Zero);
		DateTimeOffset later = new(2050, 1, 1, 0, 0, 0, TimeSpan.Zero);
		Certificate utc = Certificate.Decode((parts with { Validity = Sequence(Time(first), Time(last)) }).Encode());
		Certificate generalized = Certificate.Decode((parts with { Validity = Sequence(Time(last, generalized: true), Time(later, generalized: true)) }).Encode());

		using (Assert.Multiple())
		{
			await Assert.That(utc.NotBefore).IsEqualTo(first);
			await Assert.That(utc.NotAfter).IsEqualTo(last);
			await Assert.That(generalized.NotBefore).IsEqualTo(last);
			await Assert.That(generalized.NotAfter).IsEqualTo(later);
		}
	}

	public static IEnumerable<Func<(string Case, byte[] Encoding)>> MalformedCases()
	{
		CertificateParts parts = new();
		byte[] valid = parts.Encode();

		yield return () => ("empty", []);
		yield return () => ("trailing byte", [.. valid, 0]);
		yield return () => ("truncated", valid.AsSpan(0, valid.Length - 1).ToArray());
		yield return () => ("length in more bytes than DER allows", WithRedundantLengthByte(valid));
		yield return () => ("indefinite length", [0x30, 0x80, .. Contents(valid), 0x00, 0x00]);
		yield return () => ("SET instead of SEQUENCE", [0x31, .. valid.AsSpan(1)]);
		yield return () => ("explicit version v1", (parts with { Version = Tlv(0xA0, [0x02, 0x01, 0x00]) }).Encode());
		yield return () => ("version v4", (parts with { Version = Tlv(0xA0, [0x02, 0x01, 0x03]) }).Encode());
		yield return () => ("version after the field", (parts with { Version = Tlv(0xA0, [0x02, 0x01, 0x02, 0x05, 0x00]) }).Encode());
		yield return () => ("serial number with a redundant leading byte", (parts with { SerialNumber = [0x02, 0x02, 0x00, 0x01] }).Encode());
		yield return () => ("inner and outer signature algorithms differ", (parts with { OuterSignature = CertificateParts.EcdsaSha384 }).Encode());
		yield return () => ("algorithm identifier with two parameters", (parts with { InnerSignature = Sequence(Oid("1.2.840.10045.4.3.2"), [0x05, 0x00], [0x05, 0x00]), OuterSignature = Sequence(Oid("1.2.840.10045.4.3.2"), [0x05, 0x00], [0x05, 0x00]) }).Encode());
		yield return () => ("issuer is not a Name", (parts with { Issuer = [0x02, 0x01, 0x01] }).Encode());
		yield return () => ("empty relative distinguished name", (parts with { Issuer = Sequence(Tlv(0x31)) }).Encode());
		yield return () => ("attribute without a value", (parts with { Issuer = Sequence(Tlv(0x31, Sequence(Oid("2.5.4.3")))) }).Encode());
		yield return () => ("relative distinguished name out of DER order", (parts with { Issuer = Sequence(Tlv(0x31, Sequence(Oid("2.5.4.3"), [0x0C, 0x01, 0x62]), Sequence(Oid("2.5.4.3"), [0x0C, 0x01, 0x61]))) }).Encode());
		yield return () => ("UTCTime without seconds", (parts with { Validity = Sequence([0x17, 0x0B, .. "4901010000Z"u8], Time(Now)) }).Encode());
		yield return () => ("UTCTime with an offset", (parts with { Validity = Sequence([0x17, 0x11, .. "491231235959+0000"u8], Time(Now)) }).Encode());
		yield return () => ("GeneralizedTime with fractional seconds", (parts with { Validity = Sequence(Time(Now), [0x18, 0x11, .. "20500101000000.5Z"u8]) }).Encode());
		yield return () => ("time of another type", (parts with { Validity = Sequence([0x02, 0x01, 0x01], Time(Now)) }).Encode());
		yield return () => ("validity with three times", (parts with { Validity = Sequence(Time(Now), Time(Now), Time(Now)) }).Encode());
		yield return () => ("subjectPublicKey with unused bits", (parts with { SubjectPublicKeyInfo = Sequence(EcdsaTestUtils.AlgorithmIdentifier("1.2.840.10045.3.1.7"), [0x03, 0x02, 0x01, 0x80]) }).Encode());
		yield return () => ("signature with unused bits", (parts with { SignatureValue = [0x03, 0x02, 0x01, 0x80] }).Encode());
		yield return () => ("signature that is not a BIT STRING", (parts with { SignatureValue = [0x04, 0x01, 0x00] }).Encode());
		yield return () => ("field after the signature", (parts with { AfterSignature = [[0x05, 0x00]] }).Encode());
		yield return () => ("unique identifier in v1", (parts with { Version = null, AfterSubjectPublicKeyInfo = [Tlv(0x81, [0x00, 0x01])] }).Encode());
		yield return () => ("extensions in v1", (parts with { Version = null, AfterSubjectPublicKeyInfo = [Extensions(Extension("2.5.29.19", [0x30, 0x00]))] }).Encode());
		yield return () => ("extensions in v2", (parts with { Version = Tlv(0xA0, [0x02, 0x01, 0x01]), AfterSubjectPublicKeyInfo = [Extensions(Extension("2.5.29.19", [0x30, 0x00]))] }).Encode());
		yield return () => ("no extensions in the SEQUENCE", (parts with { AfterSubjectPublicKeyInfo = [Extensions()] }).Encode());
		yield return () => ("two SEQUENCEs of extensions", (parts with { AfterSubjectPublicKeyInfo = [Tlv(0xA3, Sequence(Extension("2.5.29.19", [0x30, 0x00])), Sequence(Extension("2.5.29.15", [0x03, 0x01, 0x00])))] }).Encode());
		yield return () => ("an extension twice", (parts with { AfterSubjectPublicKeyInfo = [Extensions(Extension("2.5.29.19", [0x30, 0x00]), Extension("2.5.29.19", [0x30, 0x00]))] }).Encode());
		yield return () => ("critical encoded as FALSE", (parts with { AfterSubjectPublicKeyInfo = [Extensions(Extension("2.5.29.19", [0x30, 0x00], [0x01, 0x01, 0x00]))] }).Encode());
		yield return () => ("extension value that is not an OCTET STRING", (parts with { AfterSubjectPublicKeyInfo = [Extensions(Sequence(Oid("2.5.29.19"), [0x30, 0x00]))] }).Encode());
		yield return () => ("key usage with no bit set", (parts with { AfterSubjectPublicKeyInfo = [Extensions(Extension("2.5.29.15", [0x03, 0x01, 0x00]))] }).Encode());
		yield return () => ("key usage with zero bits", (parts with { AfterSubjectPublicKeyInfo = [Extensions(Extension("2.5.29.15", [0x03, 0x02, 0x07, 0x00]))] }).Encode());
		yield return () => ("key usage with trailing zero bits", (parts with { AfterSubjectPublicKeyInfo = [Extensions(Extension("2.5.29.15", [0x03, 0x02, 0x00, 0x80]))] }).Encode());
		yield return () => ("key usage with a nonzero unused bit", (parts with { AfterSubjectPublicKeyInfo = [Extensions(Extension("2.5.29.15", [0x03, 0x02, 0x07, 0x81]))] }).Encode());
		yield return () => ("key usage with an undefined bit", (parts with { AfterSubjectPublicKeyInfo = [Extensions(Extension("2.5.29.15", [0x03, 0x03, 0x06, 0x00, 0x40]))] }).Encode());
		yield return () => ("key usage of three bytes", (parts with { AfterSubjectPublicKeyInfo = [Extensions(Extension("2.5.29.15", [0x03, 0x04, 0x07, 0x80, 0x00, 0x80]))] }).Encode());
		yield return () => ("key usage that is not a BIT STRING", (parts with { AfterSubjectPublicKeyInfo = [Extensions(Extension("2.5.29.15", [0x04, 0x01, 0x80]))] }).Encode());
		yield return () => ("key usage followed by more data", (parts with { AfterSubjectPublicKeyInfo = [Extensions(Extension("2.5.29.15", [0x03, 0x02, 0x07, 0x80, 0x05, 0x00]))] }).Encode());
		yield return () => ("field after the extensions", (parts with { AfterSubjectPublicKeyInfo = [Extensions(Extension("2.5.29.19", [0x30, 0x00])), [0x05, 0x00]] }).Encode());
		yield return () => ("no subjectPublicKeyInfo", (parts with { SubjectPublicKeyInfo = [] }).Encode());
	}

	[Test]
	[MethodDataSource(nameof(MalformedCases))]
	public async Task MalformedEncodingsThrow(string @case, byte[] encoding)
	{
		await Assert.That(() => Certificate.Decode(encoding)).Throws<ArgumentException>().WithParameterName("source").Because(@case);
	}

	[Test]
	public async Task DecodeCopiesItsInput()
	{
		byte[] encoding = SelfSignedP256().Encoded.ToArray();
		Certificate certificate = Certificate.Decode(encoding);
		byte[] expected = encoding.ToArray();
		Array.Clear(encoding);

		await Assert.That(certificate.Encoded.ToArray()).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}
}
