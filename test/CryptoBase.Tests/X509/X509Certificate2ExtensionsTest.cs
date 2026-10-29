using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures;
using CryptoBase.X509;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using static CryptoBase.Tests.Signatures.SignatureTestUtils;
using static CryptoBase.Tests.X509.X509TestUtils;

namespace CryptoBase.Tests.X509;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class X509Certificate2ExtensionsTest
{
	// The private key stays with the platform, which exports this one, and the key outlives the certificate.
	[Test]
	[MatrixDataSource]
	public async Task PrivateKeysSignThroughThePlatform([Matrix(256, 384, 521)] int curveBits)
	{
		using ECDsa platform = ECDsa.Create(EcdsaCurve(curveBits).Curve);
		ISignatureKey key;
		byte[] subjectPublicKeyInfo;

		using (X509Certificate2 certificate = BclSelfSigned(platform, HashAlgorithmName.SHA256))
		{
			key = certificate.GetSignaturePrivateKey();
			subjectPublicKeyInfo = certificate.PublicKey.ExportSubjectPublicKeyInfo();
		}

		using (key)
		{
			await VerifyKey(key, subjectPublicKeyInfo);
		}
	}

	[Test]
	public async Task NonExportableKeysSignThroughThePlatform()
	{
		if (!OperatingSystem.IsWindows())
		{
			Skip.Test("Non-exportable keys are created through CNG.");
			return;
		}

		// CopyWithPrivateKey exports an ephemeral key, so the key is persisted, under a name of its own, until the test deletes it.
		CngKey cngKey = CngKey.Create(CngAlgorithm.ECDsaP256, $"CryptoBase.Tests.{Guid.NewGuid():N}", new CngKeyCreationParameters { ExportPolicy = CngExportPolicies.None });

		try
		{
			using ECDsaCng platform = new(cngKey);
			using X509Certificate2 certificate = BclSelfSigned(platform, HashAlgorithmName.SHA256);
			using ISignatureKey key = certificate.GetSignaturePrivateKey();

			// SignatureKey.TryImportPrivateKey gives false, so the caller keeps the platform key.
			await Assert.That(SignatureKey.TryImportPrivateKey(certificate, out _)).IsFalse();
			await VerifyKey(key, certificate.PublicKey.ExportSubjectPublicKeyInfo());
		}
		finally
		{
			cngKey.Delete();
		}
	}

	[Test]
	public async Task OnlyEcdsaPrivateKeysAreSupported()
	{
		using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
		using X509Certificate2 withKey = BclSelfSigned(ecdsa, HashAlgorithmName.SHA256);
		using X509Certificate2 withoutKey = X509CertificateLoader.LoadCertificate(withKey.RawData);
		using RSA rsa = RSA.Create(2048);
		using X509Certificate2 rsaCertificate = new CertificateRequest("CN=RSA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSelfSigned(Now.AddDays(-1), Now.AddDays(1));

		using (Assert.Multiple())
		{
			await Assert.That(() => withoutKey.GetSignaturePrivateKey()).Throws<ArgumentException>().WithParameterName("certificate");
			await Assert.That(() => rsaCertificate.GetSignaturePrivateKey()).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => X509Certificate2Extensions.GetSignaturePrivateKey(null!)).ThrowsExactly<ArgumentNullException>();
		}
	}

	private static async Task VerifyKey(ISignatureKey key, byte[] subjectPublicKeyInfo)
	{
		byte[] message = "message"u8.ToArray();
		byte[] signature = Sign(key, SignatureAlgorithm.EcdsaSha384, message);
		using ECDsa publicKey = ECDsa.Create();
		publicKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo, out _);

		using (Assert.Multiple())
		{
			await Assert.That(key).IsTypeOf<PlatformEcdsaKey>();
			await Assert.That(key.HasPrivateKey).IsTrue();
			await Assert.That(ExportSubjectPublicKeyInfo(key)).IsEquivalentTo(subjectPublicKeyInfo, CollectionOrdering.Matching);
			await Assert.That(publicKey.VerifyData(message, signature, HashAlgorithmName.SHA384, DSASignatureFormat.Rfc3279DerSequence)).IsTrue();
			await Assert.That(key.Verify(SignatureAlgorithm.EcdsaSha384, message, signature)).IsTrue();
		}
	}
}
