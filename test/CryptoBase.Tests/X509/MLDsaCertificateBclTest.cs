#pragma warning disable SYSLIB5006

using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures;
using CryptoBase.Signatures.MLDsa;
using CryptoBase.X509;
using System.Security.Cryptography.X509Certificates;
using static CryptoBase.Tests.Signatures.MLDsa.MLDsaTestUtils;
using static CryptoBase.Tests.Signatures.SignatureTestUtils;
using static CryptoBase.Tests.X509.X509TestUtils;
using BclMLDsa = System.Security.Cryptography.MLDsa;

namespace CryptoBase.Tests.X509;

// ML-DSA certificates in both directions against the platform, where it supports ML-DSA.
[GenerateGenericTest(typeof(MLDsa44))]
[GenerateGenericTest(typeof(MLDsa65))]
[GenerateGenericTest(typeof(MLDsa87))]
internal class MLDsaCertificateBclTest<T> where T : class, IMLDsa<T>
{
	[Test]
	public async Task ThePlatformAcceptsCryptoBaseCertificates()
	{
		SkipUnlessSupported();

		using T key = T.GenerateKey();
		Certificate certificate = SelfSigned(key, AlgorithmsOf<T>()[0], "CN=CryptoBase ML-DSA", new CertificateExtension("2.5.29.19", true, new X509BasicConstraintsExtension(true, false, 0, true).RawData));

		using X509Certificate2 loaded = X509CertificateLoader.LoadCertificate(certificate.Encoded.Span);
		using BclMLDsa? publicKey = loaded.GetMLDsaPublicKey();
		(bool built, string status) = BuildTrustingItself(loaded);

		using (Assert.Multiple())
		{
			await Assert.That(publicKey?.Algorithm).IsEqualTo(BclAlgorithm<T>());
			await Assert.That(publicKey is not null && publicKey.VerifyData(certificate.TbsCertificate.Span, certificate.Signature.Span)).IsTrue();
			await Assert.That(built).IsTrue().Because(status);
		}
	}

	[Test]
	public async Task CryptoBaseAcceptsPlatformCertificates()
	{
		SkipUnlessSupported();

		using BclMLDsa key = BclMLDsa.GenerateKey(BclAlgorithm<T>());
		using X509Certificate2 platform = new CertificateRequest("CN=Platform ML-DSA", key).CreateSelfSigned(Now.AddDays(-1), Now.AddDays(1));

		Certificate certificate = Certificate.Decode(platform.RawData);
		using T publicKey = T.ImportSubjectPublicKeyInfo(certificate.PublicKeyInfo.Encoded.Span);
		using ISignatureKey privateKey = SignatureKey.ImportPkcs8PrivateKey(key.ExportPkcs8PrivateKey());

		using (Assert.Multiple())
		{
			await Assert.That(certificate.SignatureAlgorithm.TryGetSignatureAlgorithm(out SignatureAlgorithm signatureAlgorithm)).IsTrue();
			await Assert.That(signatureAlgorithm).IsEqualTo(AlgorithmsOf<T>()[0]);
			await Assert.That(publicKey.GetType()).IsEqualTo(typeof(T));
			await Assert.That(certificate.VerifySignature(publicKey)).IsTrue();
			await Assert.That(ExportSubjectPublicKeyInfo(privateKey)).IsEquivalentTo(certificate.PublicKeyInfo.Encoded.ToArray(), CollectionOrdering.Matching);
		}
	}
}
