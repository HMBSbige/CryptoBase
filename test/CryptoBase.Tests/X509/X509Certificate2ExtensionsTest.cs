#pragma warning disable SYSLIB5006

using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures;
using CryptoBase.X509;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using static CryptoBase.Tests.Signatures.SignatureTestUtils;
using static CryptoBase.Tests.X509.X509TestUtils;
using BclMLDsa = System.Security.Cryptography.MLDsa;

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

	// An RSA key, which the platform exports here, signs through the platform with both paddings, and outlives the certificate.
	[Test]
	public async Task RsaPrivateKeysSignThroughThePlatform()
	{
		using RSA platform = CreateRsa();
		ISignatureKey key;
		byte[] subjectPublicKeyInfo;

		using (X509Certificate2 certificate = BclSelfSigned(platform, SignatureAlgorithm.RsaPkcs1Sha256))
		{
			key = certificate.GetSignaturePrivateKey();
			subjectPublicKeyInfo = certificate.PublicKey.ExportSubjectPublicKeyInfo();
		}

		using (key)
		{
			await VerifyRsaKey(key, subjectPublicKeyInfo);
		}
	}

	[Test]
	public async Task NonExportableRsaKeysSignThroughThePlatform()
	{
		if (!OperatingSystem.IsWindows())
		{
			Skip.Test("Non-exportable keys are created through CNG.");
			return;
		}

		CngKey cngKey = CngKey.Create(CngAlgorithm.Rsa, $"CryptoBase.Tests.{Guid.NewGuid():N}", new CngKeyCreationParameters { ExportPolicy = CngExportPolicies.None, Parameters = { new CngProperty("Length", BitConverter.GetBytes(2048), CngPropertyOptions.None) } });

		try
		{
			using RSACng platform = new(cngKey);
			using X509Certificate2 certificate = BclSelfSigned(platform, SignatureAlgorithm.RsaPssSha256);
			using ISignatureKey key = certificate.GetSignaturePrivateKey();
			using RSA? exported = certificate.GetRSAPrivateKey();

			await Assert.That(() => exported?.ExportPkcs8PrivateKey()).Throws<CryptographicException>();
			await VerifyRsaKey(key, certificate.PublicKey.ExportSubjectPublicKeyInfo());
		}
		finally
		{
			cngKey.Delete();
		}
	}

	[Test]
	public async Task OtherPrivateKeysAreNotSupported()
	{
		using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
		using X509Certificate2 withKey = BclSelfSigned(ecdsa, HashAlgorithmName.SHA256);
		using X509Certificate2 withoutKey = X509CertificateLoader.LoadCertificate(withKey.RawData);
		using RSA largeExponent = RsaWithLargeExponent();
		using X509Certificate2 largeExponentCertificate = BclSelfSigned(largeExponent, SignatureAlgorithm.RsaPkcs1Sha256);

		using (Assert.Multiple())
		{
			await Assert.That(() => withoutKey.GetSignaturePrivateKey()).Throws<ArgumentException>().WithParameterName("certificate");
			await Assert.That(() => X509Certificate2Extensions.GetSignaturePrivateKey(null!)).ThrowsExactly<ArgumentNullException>();

			// RSA whose public exponent has more than 33 bits.
			await Assert.That(() => largeExponentCertificate.GetSignaturePrivateKey()).ThrowsExactly<NotSupportedException>();

			if (BclMLDsa.IsSupported)
			{
				using BclMLDsa mlDsa = BclMLDsa.GenerateKey(MLDsaAlgorithm.MLDsa44);
				using X509Certificate2 mlDsaCertificate = new CertificateRequest("CN=ML-DSA", mlDsa).CreateSelfSigned(Now.AddDays(-1), Now.AddDays(1));
				await Assert.That(() => mlDsaCertificate.GetSignaturePrivateKey()).ThrowsExactly<NotSupportedException>();
			}
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

	private static async Task VerifyRsaKey(ISignatureKey key, byte[] subjectPublicKeyInfo)
	{
		byte[] message = "message"u8.ToArray();
		using RSA publicKey = RSA.Create();
		publicKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo, out _);

		using (Assert.Multiple())
		{
			await Assert.That(key).IsTypeOf<PlatformRsaKey>();
			await Assert.That(key.HasPrivateKey).IsTrue();
			await Assert.That(ExportSubjectPublicKeyInfo(key)).IsEquivalentTo(subjectPublicKeyInfo, CollectionOrdering.Matching);

			foreach (SignatureAlgorithm algorithm in RsaAlgorithms)
			{
				(HashAlgorithmName hash, RSASignaturePadding padding) = RsaParametersOf(algorithm);
				byte[] signature = Sign(key, algorithm, message);

				await Assert.That(publicKey.VerifyData(message, signature, hash, padding)).IsTrue().Because(algorithm.ToString());
				await Assert.That(key.Verify(algorithm, message, signature)).IsTrue().Because(algorithm.ToString());
			}
		}
	}

	// The key of RsaPrivateParameters with a public exponent of 40 bits instead, which the platform takes.
	private static RSA RsaWithLargeExponent()
	{
		RSAParameters parameters = RsaPrivateParameters();
		BigInteger p = new(parameters.P, true, true);
		BigInteger q = new(parameters.Q, true, true);
		BigInteger lambda = (p - 1) * (q - 1) / BigInteger.GreatestCommonDivisor(p - 1, q - 1);
		BigInteger e = (BigInteger.One << 39) + 1;

		while (!BigInteger.GreatestCommonDivisor(e, lambda).IsOne)
		{
			e += 2;
		}

		BigInteger d = Inverse(e, lambda);
		int halfLength = parameters.P!.Length;
		RSA key = RSA.Create();
		key.ImportParameters(new RSAParameters
		{
			Modulus = parameters.Modulus,
			Exponent = e.ToByteArray(true, true),
			D = Pad(d, parameters.D!.Length),
			P = parameters.P,
			Q = parameters.Q,
			DP = Pad(d % (p - 1), halfLength),
			DQ = Pad(d % (q - 1), halfLength),
			InverseQ = Pad(Inverse(q, p), halfLength)
		});
		return key;

		static byte[] Pad(BigInteger value, int length)
		{
			byte[] bytes = value.ToByteArray(true, true);
			return [.. new byte[length - bytes.Length], .. bytes];
		}

		static BigInteger Inverse(BigInteger value, BigInteger modulus)
		{
			(BigInteger t, BigInteger nextT, BigInteger r, BigInteger nextR) = (0, 1, modulus, value % modulus);

			while (!nextR.IsZero)
			{
				BigInteger quotient = r / nextR;
				(t, nextT) = (nextT, t - quotient * nextT);
				(r, nextR) = (nextR, r - quotient * nextR);
			}

			return t.Sign < 0 ? t + modulus : t;
		}
	}
}
