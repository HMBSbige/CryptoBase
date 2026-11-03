using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures.Rsa;
using System.Security.Cryptography;
using static CryptoBase.Tests.Signatures.Rsa.RsaTestUtils;
using static CryptoBase.Tests.Signatures.SignatureTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Signatures.Rsa;

// Signatures and key encodings in both directions against the platform's RSA.
internal class RsaBclTest
{
	[Test]
	[MatrixDataSource]
	public async Task SignaturesInteroperate([Matrix(2048, 3072, 4096)] int bits, [Matrix(SignatureAlgorithm.RsaPkcs1Sha256, SignatureAlgorithm.RsaPkcs1Sha384, SignatureAlgorithm.RsaPkcs1Sha512, SignatureAlgorithm.RsaPssSha256, SignatureAlgorithm.RsaPssSha384, SignatureAlgorithm.RsaPssSha512)] SignatureAlgorithm algorithm)
	{
		using RsaKey key = ImportKey(bits);
		using RSA bcl = CreateBclKey(bits);
		using RsaKey publicKey = RsaKey.ImportSubjectPublicKeyInfo(bcl.ExportSubjectPublicKeyInfo());
		(HashAlgorithmName hash, RSASignaturePadding padding, _) = ParametersOf(algorithm);
		byte[] message = CreateDeterministicSource(bits / 8 + 3);
		byte[] other = Flip(message, 0);
		byte[] ours = Sign(key, algorithm, message);
		byte[] theirs = bcl.SignData(message, hash, padding);

		using (Assert.Multiple())
		{
			await Assert.That(ours.Length).IsEqualTo(bits / 8);
			await Assert.That(bcl.VerifyData(message, ours, hash, padding)).IsTrue();
			await Assert.That(bcl.VerifyData(other, ours, hash, padding)).IsFalse();
			await Assert.That(publicKey.Verify(algorithm, message, theirs)).IsTrue();
			await Assert.That(key.Verify(algorithm, message, theirs)).IsTrue();
			await Assert.That(publicKey.Verify(algorithm, other, theirs)).IsFalse();

			// RSASSA-PKCS1-v1_5 is deterministic, and both write the DigestInfo with NULL parameters.
			if (padding == RSASignaturePadding.Pkcs1)
			{
				await Assert.That(ours).IsEquivalentTo(theirs, CollectionOrdering.Matching);
			}
		}
	}

	// Each import of the platform's encodings exports them byte for byte, and the platform's import of ours exports ours.
	[Test]
	[Arguments(2048)]
	[Arguments(3072)]
	[Arguments(4096)]
	public async Task KeyFormatsMatch(int bits)
	{
		using RSA bcl = CreateBclKey(bits);
		byte[] rsaPublicKey = bcl.ExportRSAPublicKey();
		byte[] rsaPrivateKey = bcl.ExportRSAPrivateKey();
		byte[] subjectPublicKeyInfo = bcl.ExportSubjectPublicKeyInfo();
		byte[] pkcs8 = bcl.ExportPkcs8PrivateKey();

		using RsaKey fromRsaPublicKey = RsaKey.ImportRsaPublicKey(rsaPublicKey);
		using RsaKey fromSubjectPublicKeyInfo = RsaKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo);
		using RsaKey fromRsaPrivateKey = RsaKey.ImportRsaPrivateKey(rsaPrivateKey);
		using RsaKey fromPkcs8 = RsaKey.ImportPkcs8PrivateKey(pkcs8);

		using (Assert.Multiple())
		{
			foreach (RsaKey key in (RsaKey[])[fromRsaPublicKey, fromSubjectPublicKeyInfo, fromRsaPrivateKey, fromPkcs8])
			{
				await Assert.That(ExportRsaPublicKey(key)).IsEquivalentTo(rsaPublicKey, CollectionOrdering.Matching);
				await Assert.That(ExportSubjectPublicKeyInfo(key)).IsEquivalentTo(subjectPublicKeyInfo, CollectionOrdering.Matching);
			}

			foreach (RsaKey key in (RsaKey[])[fromRsaPrivateKey, fromPkcs8])
			{
				await Assert.That(ExportRsaPrivateKey(key)).IsEquivalentTo(rsaPrivateKey, CollectionOrdering.Matching);
				await Assert.That(ExportPkcs8PrivateKey(key)).IsEquivalentTo(pkcs8, CollectionOrdering.Matching);
			}

			using RSA fromOurRsaPrivateKey = RSA.Create();
			fromOurRsaPrivateKey.ImportRSAPrivateKey(ExportRsaPrivateKey(fromPkcs8), out int read);
			await Assert.That(read).IsEqualTo(rsaPrivateKey.Length);
			await Assert.That(fromOurRsaPrivateKey.ExportPkcs8PrivateKey()).IsEquivalentTo(ExportPkcs8PrivateKey(fromPkcs8), CollectionOrdering.Matching);

			using RSA fromOurPkcs8 = RSA.Create();
			fromOurPkcs8.ImportPkcs8PrivateKey(ExportPkcs8PrivateKey(fromRsaPrivateKey), out read);
			await Assert.That(read).IsEqualTo(pkcs8.Length);
			await Assert.That(fromOurPkcs8.ExportRSAPrivateKey()).IsEquivalentTo(ExportRsaPrivateKey(fromRsaPrivateKey), CollectionOrdering.Matching);

			using RSA fromOurRsaPublicKey = RSA.Create();
			fromOurRsaPublicKey.ImportRSAPublicKey(ExportRsaPublicKey(fromSubjectPublicKeyInfo), out read);
			await Assert.That(read).IsEqualTo(rsaPublicKey.Length);
			await Assert.That(fromOurRsaPublicKey.ExportSubjectPublicKeyInfo()).IsEquivalentTo(ExportSubjectPublicKeyInfo(fromSubjectPublicKeyInfo), CollectionOrdering.Matching);

			using RSA fromOurSubjectPublicKeyInfo = RSA.Create();
			fromOurSubjectPublicKeyInfo.ImportSubjectPublicKeyInfo(ExportSubjectPublicKeyInfo(fromRsaPublicKey), out read);
			await Assert.That(read).IsEqualTo(subjectPublicKeyInfo.Length);
			await Assert.That(fromOurSubjectPublicKeyInfo.ExportRSAPublicKey()).IsEquivalentTo(ExportRsaPublicKey(fromRsaPublicKey), CollectionOrdering.Matching);
		}
	}

	// A generated key works on the platform, which signs with it what the key verifies. The platform may hold another private exponent that is equivalent to the key's, so only the public key is compared.
	[Test]
	public async Task TheBclUsesGeneratedKeys()
	{
		using RsaKey key = RsaKey.GenerateKey(2048);
		using RSA bcl = RSA.Create();
		bcl.ImportPkcs8PrivateKey(ExportPkcs8PrivateKey(key), out _);
		byte[] message = CreateDeterministicSource(100);

		using (Assert.Multiple())
		{
			await Assert.That(bcl.ExportRSAPublicKey()).IsEquivalentTo(ExportRsaPublicKey(key), CollectionOrdering.Matching);

			foreach (SignatureAlgorithm algorithm in Algorithms)
			{
				(HashAlgorithmName hash, RSASignaturePadding padding, _) = ParametersOf(algorithm);
				await Assert.That(key.Verify(algorithm, message, bcl.SignData(message, hash, padding))).IsTrue().Because(algorithm.ToString());
			}
		}
	}
}
