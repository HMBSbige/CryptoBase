using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures;
using CryptoBase.Signatures.MLDsa;
using CryptoBase.X509;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using static CryptoBase.Tests.Signatures.SignatureTestUtils;

namespace CryptoBase.Tests.X509;

// The examples of RFC 9881, Appendix C, for each parameter set: the private key in the seed form (C.1), its public key (C.2) and the self-signed certificate for it (C.3). OpenSSL 3.6.5 verifies each certificate and derives the public key from the private key.
public class Rfc9881Test
{
	public static IEnumerable<(string File, Type Type, SignatureAlgorithm Algorithm)> Examples()
	{
		yield return ("rfc9881-mldsa44.pem", typeof(MLDsa44), SignatureAlgorithm.MLDsa44);
		yield return ("rfc9881-mldsa65.pem", typeof(MLDsa65), SignatureAlgorithm.MLDsa65);
		yield return ("rfc9881-mldsa87.pem", typeof(MLDsa87), SignatureAlgorithm.MLDsa87);
	}

	[Test]
	[MethodDataSource(nameof(Examples))]
	public async Task CertificatesDecodeAndVerify(string file, Type type, SignatureAlgorithm algorithm)
	{
		string text = ReadExample(file);
		Certificate certificate = Certificate.DecodePem(text);
		byte[] subjectPublicKeyInfo = Block(text, "PUBLIC KEY");
		using ISignatureKey publicKey = SignatureKey.ImportSubjectPublicKeyInfo(certificate.PublicKeyInfo.Encoded.Span);
		using ISignatureKey privateKey = SignatureKey.ImportPkcs8PrivateKey(Block(text, "PRIVATE KEY"));
		CertificateExtension keyUsage = certificate.Extensions.Single(static extension => extension.Oid == "2.5.29.15");

		using (Assert.Multiple())
		{
			await Assert.That(certificate.Version).IsEqualTo(3);
			await Assert.That(certificate.SignatureAlgorithm.TryGetSignatureAlgorithm(out SignatureAlgorithm signatureAlgorithm)).IsTrue();
			await Assert.That(signatureAlgorithm).IsEqualTo(algorithm);
			await Assert.That(certificate.PublicKeyInfo.Algorithm.Encoded.ToArray()).IsEquivalentTo(AlgorithmIdentifier.FromSignatureAlgorithm(algorithm).Encoded.ToArray(), CollectionOrdering.Matching);
			await Assert.That(certificate.PublicKeyInfo.Encoded.ToArray()).IsEquivalentTo(subjectPublicKeyInfo, CollectionOrdering.Matching);
			await Assert.That(certificate.Subject.ToArray()).IsEquivalentTo(certificate.Issuer.ToArray(), CollectionOrdering.Matching);
			await Assert.That(certificate.NotBefore).IsEqualTo(new DateTimeOffset(2020, 2, 3, 4, 32, 10, TimeSpan.Zero));
			await Assert.That(certificate.NotAfter).IsEqualTo(new DateTimeOffset(2040, 1, 29, 4, 32, 10, TimeSpan.Zero));

			// digitalSignature, keyCertSign and cRLSign.
			await Assert.That(keyUsage.Critical).IsTrue();
			await Assert.That(keyUsage.Value.ToArray()).IsEquivalentTo((byte[])[0x03, 0x02, 0x01, 0x86], CollectionOrdering.Matching);
			await Assert.That(certificate.KeyUsage).IsEqualTo(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign);

			await Assert.That(publicKey.GetType()).IsEqualTo(type);
			await Assert.That(privateKey.GetType()).IsEqualTo(type);
			await Assert.That(ExportSubjectPublicKeyInfo(privateKey)).IsEquivalentTo(subjectPublicKeyInfo, CollectionOrdering.Matching);
			await Assert.That(certificate.VerifySignature(publicKey)).IsTrue();
			await Assert.That(certificate.VerifySignature(privateKey)).IsTrue();
		}
	}

	[Test]
	[MethodDataSource(nameof(Examples))]
	public async Task TamperedCertificatesFailVerification(string file, Type type, SignatureAlgorithm algorithm)
	{
		Certificate certificate = Certificate.DecodePem(ReadExample(file));
		using ISignatureKey publicKey = SignatureKey.ImportSubjectPublicKeyInfo(certificate.PublicKeyInfo.Encoded.Span);
		byte[] tamperedSubject = FlipLastSubjectByte(certificate);
		byte[] tamperedSignature = certificate.Encoded.ToArray();
		tamperedSignature[^1] ^= 1;

		using (Assert.Multiple())
		{
			await Assert.That(publicKey.GetType()).IsEqualTo(type);
			await Assert.That(Certificate.Decode(tamperedSubject).VerifySignature(publicKey)).IsFalse();
			await Assert.That(Certificate.Decode(tamperedSignature).VerifySignature(publicKey)).IsFalse();
			await Assert.That(certificate.SignatureAlgorithm.TryGetSignatureAlgorithm(out SignatureAlgorithm signatureAlgorithm) && signatureAlgorithm == algorithm).IsTrue();
		}
	}

	// The example key signs a new certificate for itself that verifies with the example public key.
	[Test]
	[MethodDataSource(nameof(Examples))]
	public async Task ExampleKeysSignCertificates(string file, Type type, SignatureAlgorithm algorithm)
	{
		string text = ReadExample(file);
		Certificate example = Certificate.DecodePem(text);
		using ISignatureKey privateKey = SignatureKey.ImportPkcs8PrivateKey(Block(text, "PRIVATE KEY"));
		using ISignatureKey publicKey = SignatureKey.ImportSubjectPublicKeyInfo(Block(text, "PUBLIC KEY"));

		Certificate certificate = new CertificateBuilder(example.Subject.Span).CreateSelfSigned(privateKey, algorithm, example.NotBefore, example.NotAfter);

		using (Assert.Multiple())
		{
			await Assert.That(publicKey.GetType()).IsEqualTo(type);
			await Assert.That(certificate.PublicKeyInfo.Encoded.ToArray()).IsEquivalentTo(example.PublicKeyInfo.Encoded.ToArray(), CollectionOrdering.Matching);
			await Assert.That(certificate.SignatureAlgorithm.Encoded.ToArray()).IsEquivalentTo(example.SignatureAlgorithm.Encoded.ToArray(), CollectionOrdering.Matching);
			await Assert.That(certificate.VerifySignature(publicKey)).IsTrue();
		}
	}

	// The subject is also the issuer, so the last copy of it in the TBSCertificate is the subject.
	private static byte[] FlipLastSubjectByte(Certificate certificate)
	{
		ReadOnlySpan<byte> tbs = certificate.TbsCertificate.Span;
		int subject = certificate.Encoded.Span.IndexOf(tbs) + tbs.LastIndexOf(certificate.Subject.Span);
		byte[] tampered = certificate.Encoded.ToArray();
		tampered[subject + certificate.Subject.Length - 1] ^= 1;
		return tampered;
	}

	private static string ReadExample(string file)
	{
		using Stream stream = typeof(Rfc9881Test).Assembly.GetManifestResourceStream(file) ?? throw new FileNotFoundException($"The RFC 9881 example '{file}' is not embedded.", file);
		using StreamReader reader = new(stream);
		return reader.ReadToEnd();
	}

	// The DER of the one PEM block with the label.
	private static byte[] Block(string text, string label)
	{
		string block = text.Substring(text.IndexOf($"-----BEGIN {label}-----", StringComparison.Ordinal));
		PemFields fields = PemEncoding.Find(block);
		return Convert.FromBase64String(block[fields.Base64Data]);
	}
}
