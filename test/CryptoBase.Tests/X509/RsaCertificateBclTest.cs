using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures.Ecdsa;
using CryptoBase.Tests.Signatures.Rsa;
using CryptoBase.X509;
using System.Security.Cryptography.X509Certificates;
using static CryptoBase.Tests.Signatures.SignatureTestUtils;
using static CryptoBase.Tests.X509.TestPki;
using static CryptoBase.Tests.X509.X509TestUtils;
using RsaKey = CryptoBase.Signatures.Rsa.RsaKey;

namespace CryptoBase.Tests.X509;

// Chains that RsaKey issues, against the platform.
public class RsaCertificateBclTest
{
	public static IEnumerable<Func<SignatureAlgorithm>> Algorithms()
	{
		return RsaAlgorithms.Select(static algorithm => (Func<SignatureAlgorithm>)(() => algorithm));
	}

	// A root and an intermediate with RsaKey, which issue with each algorithm, load on the platform, and PlatformCertificateValidator builds the chain to the root as a custom trust anchor; a leaf whose
	// signature is changed fails, which macOS reports as a partial chain. macOS verifies no RSASSA-PSS signature in a chain, not even in one that it issues itself, so those cases are skipped there
	// before they issue certificates with the names and keys of the others, which would keep it from building their chains too.
	[Test]
	[MethodDataSource(nameof(Algorithms))]
	public async Task ThePlatformValidatesChainsOfRsaKeys(SignatureAlgorithm algorithm)
	{
		if (OperatingSystem.IsMacOS() && algorithm is SignatureAlgorithm.RsaPssSha256 or SignatureAlgorithm.RsaPssSha384 or SignatureAlgorithm.RsaPssSha512)
		{
			Skip.Test("macOS does not verify RSASSA-PSS signatures in certificate chains.");
		}

		using RsaKey rootKey = RsaTestUtils.ImportKey();
		using RsaKey intermediateKey = RsaKey.ImportPkcs8PrivateKey(RsaTestUtils.OtherKey2048);
		using EcdsaP256 leafKey = EcdsaP256.GenerateKey();
		byte[] rootName = Name("CN=RSA root, O=CryptoBase");
		byte[] intermediateName = Name("CN=RSA intermediate, O=CryptoBase");
		byte[] rootPublicKey = ExportSubjectPublicKeyInfo(rootKey);
		byte[] intermediatePublicKey = ExportSubjectPublicKeyInfo(intermediateKey);
		Certificate root = Sign(new Template { Subject = rootName, SubjectPublicKeyInfo = rootPublicKey, Extensions = CaExtensions(rootPublicKey) }, rootName, rootKey, algorithm);
		Certificate intermediate = Sign(new Template { Subject = intermediateName, SubjectPublicKeyInfo = intermediatePublicKey, Extensions = [.. CaExtensions(intermediatePublicKey), AuthorityKeyIdentifier(KeyIdentifierOf(rootPublicKey))] }, rootName, rootKey, algorithm);
		Template leafTemplate = new()
		{
			Subject = Name("CN=Leaf"),
			SubjectPublicKeyInfo = ExportSubjectPublicKeyInfo(leafKey),
			Extensions = [SubjectAlternativeNames("example.com"), ExtendedKeyUsage(ServerAuthenticationOid), AuthorityKeyIdentifier(KeyIdentifierOf(intermediatePublicKey))]
		};
		Certificate leaf = Sign(leafTemplate, intermediateName, intermediateKey, algorithm);
		byte[] tamperedEncoding = leaf.Encoded.ToArray();
		tamperedEncoding[^1] ^= 1;
		Certificate tampered = Certificate.Decode(tamperedEncoding);

		using X509Certificate2 bclRoot = X509CertificateLoader.LoadCertificate(root.Encoded.Span);
		using X509Certificate2 bclIntermediate = X509CertificateLoader.LoadCertificate(intermediate.Encoded.Span);
		using X509Certificate2 bclLeaf = X509CertificateLoader.LoadCertificate(leaf.Encoded.Span);
		PlatformCertificateValidator validator = new(TrustOnly(bclRoot));

		CertificateValidationResult result = await validator.ValidateAsync(new CertificateValidationContext([leaf, intermediate], CertificateUsage.ServerAuthentication) { HostName = "example.com" });
		CertificateValidationResult tamperedResult = await validator.ValidateAsync(new CertificateValidationContext([tampered, intermediate], CertificateUsage.ServerAuthentication) { HostName = "example.com" });

		using (Assert.Multiple())
		{
			foreach ((X509Certificate2 loaded, Certificate certificate) in ((X509Certificate2, Certificate)[])[(bclRoot, root), (bclIntermediate, intermediate), (bclLeaf, leaf)])
			{
				await Assert.That(loaded.SignatureAlgorithm.Value).IsEqualTo(certificate.SignatureAlgorithm.Oid);
				await Assert.That(loaded.SubjectName.RawData).IsEquivalentTo(certificate.Subject.ToArray(), CollectionOrdering.Matching);
			}

			await Assert.That(result.IsValid).IsTrue().Because($"{result.Error} {result.Message}");
			await Assert.That(result.PathEnd).IsEqualTo(CertificatePathEnd.TrustAnchor);
			await Assert.That(result.Path.Select(static certificate => Convert.ToHexString(certificate.Encoded.Span))).IsEquivalentTo([Convert.ToHexString(leaf.Encoded.Span), Convert.ToHexString(intermediate.Encoded.Span), Convert.ToHexString(root.Encoded.Span)], CollectionOrdering.Matching);
			await Assert.That(tamperedResult.IsValid).IsFalse();
			await Assert.That(tamperedResult.Errors).Contains(OperatingSystem.IsMacOS() ? CertificateValidationError.UntrustedRoot : CertificateValidationError.InvalidSignature).Because(tamperedResult.Message ?? "");
		}
	}
}
