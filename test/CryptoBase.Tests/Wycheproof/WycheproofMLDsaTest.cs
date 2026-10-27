using CryptoBase.Signatures.MLDsa;
using System.Diagnostics.CodeAnalysis;
using static CryptoBase.Tests.Signatures.MLDsa.MLDsaTestUtils;
using static CryptoBase.Tests.Signatures.SignatureTestUtils;

namespace CryptoBase.Tests.Wycheproof;

public class WycheproofMLDsaTest
{
	[Test]
	[WycheproofVectors<MLDsaVerifyTestGroup, MLDsaVerifyTestVector>("mldsa_44_verify_test.json")]
	public Task Verification44(MLDsaVerifyTestVector vector)
	{
		return VerifyVerification<MLDsa44>(vector);
	}

	[Test]
	[WycheproofVectors<MLDsaVerifyTestGroup, MLDsaVerifyTestVector>("mldsa_65_verify_test.json")]
	public Task Verification65(MLDsaVerifyTestVector vector)
	{
		return VerifyVerification<MLDsa65>(vector);
	}

	[Test]
	[WycheproofVectors<MLDsaVerifyTestGroup, MLDsaVerifyTestVector>("mldsa_87_verify_test.json")]
	public Task Verification87(MLDsaVerifyTestVector vector)
	{
		return VerifyVerification<MLDsa87>(vector);
	}

	[Test]
	[WycheproofVectors<MLDsaSignSeedTestGroup, MLDsaSignTestVector>("mldsa_44_sign_seed_test.json")]
	public Task SigningFromSeed44(MLDsaSignTestVector vector)
	{
		return VerifySigningFromSeed<MLDsa44>(vector);
	}

	[Test]
	[WycheproofVectors<MLDsaSignSeedTestGroup, MLDsaSignTestVector>("mldsa_65_sign_seed_test.json")]
	public Task SigningFromSeed65(MLDsaSignTestVector vector)
	{
		return VerifySigningFromSeed<MLDsa65>(vector);
	}

	[Test]
	[WycheproofVectors<MLDsaSignSeedTestGroup, MLDsaSignTestVector>("mldsa_87_sign_seed_test.json")]
	public Task SigningFromSeed87(MLDsaSignTestVector vector)
	{
		return VerifySigningFromSeed<MLDsa87>(vector);
	}

	[Test]
	[WycheproofVectors<MLDsaSignNoSeedTestGroup, MLDsaSignTestVector>("mldsa_44_sign_noseed_test.json")]
	public Task SigningFromPrivateKey44(MLDsaSignTestVector vector)
	{
		return VerifySigningFromPrivateKey<MLDsa44>(vector);
	}

	[Test]
	[WycheproofVectors<MLDsaSignNoSeedTestGroup, MLDsaSignTestVector>("mldsa_65_sign_noseed_test.json")]
	public Task SigningFromPrivateKey65(MLDsaSignTestVector vector)
	{
		return VerifySigningFromPrivateKey<MLDsa65>(vector);
	}

	[Test]
	[WycheproofVectors<MLDsaSignNoSeedTestGroup, MLDsaSignTestVector>("mldsa_87_sign_noseed_test.json")]
	public Task SigningFromPrivateKey87(MLDsaSignTestVector vector)
	{
		return VerifySigningFromPrivateKey<MLDsa87>(vector);
	}

	// The invalid vectors have a public key of the wrong length, a context over 255 bytes, or a signature that must not verify.
	[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Assertions are awaited before the key is disposed.")]
	private static async Task VerifyVerification<T>(MLDsaVerifyTestVector vector) where T : class, IMLDsa<T>
	{
		if (vector.PublicKey.Length != T.PublicKeyLength)
		{
			using (Assert.Multiple())
			{
				await Assert.That(vector.Result).IsEqualTo(WycheproofResult.Invalid);
				await Assert.That(() => T.ImportPublicKey(vector.PublicKey)).Throws<ArgumentException>().WithParameterName("source");
				await Assert.That(() => T.ImportSubjectPublicKeyInfo(vector.PublicKeyDer)).Throws<ArgumentException>().WithParameterName("source");
			}

			return;
		}

		using T key = T.ImportPublicKey(vector.PublicKey);
		using T fromDer = T.ImportSubjectPublicKeyInfo(vector.PublicKeyDer);

		using (Assert.Multiple())
		{
			await Assert.That(ExportSubjectPublicKeyInfo(key)).IsEquivalentTo(vector.PublicKeyDer, CollectionOrdering.Matching);
			await Assert.That(ExportPublicKey(fromDer)).IsEquivalentTo(vector.PublicKey, CollectionOrdering.Matching);
		}

		if (vector.Ctx is { Length: > 255 } context)
		{
			using (Assert.Multiple())
			{
				await Assert.That(vector.Result).IsEqualTo(WycheproofResult.Invalid);
				await Assert.That(() => key.Verify(vector.Msg, vector.Sig, context)).Throws<ArgumentOutOfRangeException>().WithParameterName("context");
			}

			return;
		}

		bool valid = vector.Result is WycheproofResult.Valid;

		using (Assert.Multiple())
		{
			await Assert.That(key.Verify(vector.Msg, vector.Sig, vector.Ctx)).IsEqualTo(valid);
			await Assert.That(fromDer.Verify(vector.Msg, vector.Sig, vector.Ctx)).IsEqualTo(valid);

			if (vector.Ctx is null or [])
			{
				await Assert.That(key.Verify(AlgorithmsOf<T>()[0], vector.Msg, vector.Sig)).IsEqualTo(valid);
			}
		}
	}

	// The invalid vectors have a seed of the wrong length or a context over 255 bytes.
	[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Assertions are awaited before the key is disposed.")]
	private static async Task VerifySigningFromSeed<T>(MLDsaSignTestVector vector) where T : class, IMLDsa<T>
	{
		byte[] seed = vector.PrivateSeed ?? throw new InvalidOperationException("A seed vector has a seed.");

		if (seed.Length != T.PrivateSeedLength)
		{
			using (Assert.Multiple())
			{
				await Assert.That(vector.Result).IsEqualTo(WycheproofResult.Invalid);
				await Assert.That(() => T.ImportPrivateSeed(seed)).Throws<ArgumentException>().WithParameterName("source");

				if (vector.PrivateKeyPkcs8 is { } invalidPkcs8)
				{
					await Assert.That(() => T.ImportPkcs8PrivateKey(invalidPkcs8)).Throws<ArgumentException>().WithParameterName("source");
				}
			}

			return;
		}

		using T key = T.ImportPrivateSeed(seed);

		using (Assert.Multiple())
		{
			await Assert.That(ExportPrivateSeed(key)).IsEquivalentTo(seed, CollectionOrdering.Matching);

			if (vector.PublicKey is { } publicKey)
			{
				await Assert.That(ExportPublicKey(key)).IsEquivalentTo(publicKey, CollectionOrdering.Matching);
			}

			if (vector.PrivateKeyPkcs8 is { Length: > 0 } pkcs8)
			{
				using T imported = T.ImportPkcs8PrivateKey(pkcs8);
				await Assert.That(ExportPkcs8PrivateKey(key)).IsEquivalentTo(pkcs8, CollectionOrdering.Matching);
				await Assert.That(ExportPrivateSeed(imported)).IsEquivalentTo(seed, CollectionOrdering.Matching);
			}
		}

		await VerifySigning(key, vector);
	}

	// The invalid vectors have a private key of the wrong length or with s1 or s2 out of range, or a context over 255 bytes.
	[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Assertions are awaited before the key is disposed.")]
	private static async Task VerifySigningFromPrivateKey<T>(MLDsaSignTestVector vector) where T : class, IMLDsa<T>
	{
		byte[] privateKey = vector.PrivateKey ?? throw new InvalidOperationException("A private key vector has a private key.");

		if (vector.Flags.Contains("IncorrectPrivateKeyLength") || vector.Flags.Contains("InvalidPrivateKey"))
		{
			using (Assert.Multiple())
			{
				await Assert.That(vector.Result).IsEqualTo(WycheproofResult.Invalid);
				await Assert.That(() => T.ImportPrivateKey(privateKey)).Throws<ArgumentException>().WithParameterName("source");
			}

			return;
		}

		byte[] publicKey = vector.PublicKey ?? throw new InvalidOperationException("A valid private key vector has a public key.");
		using T key = T.ImportPrivateKey(privateKey);
		using T fromPkcs8 = T.ImportPkcs8PrivateKey(ExportPkcs8PrivateKey(key));

		using (Assert.Multiple())
		{
			await Assert.That(key.HasPrivateSeed).IsFalse();
			await Assert.That(ExportPrivateKey(key)).IsEquivalentTo(privateKey, CollectionOrdering.Matching);
			await Assert.That(ExportPrivateKey(fromPkcs8)).IsEquivalentTo(privateKey, CollectionOrdering.Matching);
			await Assert.That(ExportPublicKey(key)).IsEquivalentTo(publicKey, CollectionOrdering.Matching);
		}

		await VerifySigning(key, vector);
	}

	// Signing reproduces the signature from the message and from μ alike, with rnd zero for the deterministic variant.
	[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Assertions are awaited before the key is disposed.")]
	private static async Task VerifySigning<T>(T key, MLDsaSignTestVector vector) where T : class, IMLDsa<T>
	{
		byte[] randomness = vector.Rnd ?? new byte[32];

		if (vector.Ctx is { Length: > 255 } context)
		{
			byte[] message = vector.Msg ?? throw new InvalidOperationException("A context vector has a message.");

			using (Assert.Multiple())
			{
				await Assert.That(vector.Result).IsEqualTo(WycheproofResult.Invalid);
				await Assert.That(() => SignWithRandomness(key, message, context, randomness)).Throws<ArgumentOutOfRangeException>().WithParameterName("context");
			}

			return;
		}

		using (Assert.Multiple())
		{
			await Assert.That(vector.Result).IsEqualTo(WycheproofResult.Valid);
			await Assert.That(vector.Msg is not null || vector.Mu is not null).IsTrue();

			if (vector.Msg is { } message)
			{
				await Assert.That(SignWithRandomness(key, message, vector.Ctx, randomness)).IsEquivalentTo(vector.Sig, CollectionOrdering.Matching);
				await Assert.That(key.Verify(message, vector.Sig, vector.Ctx)).IsTrue();
			}

			if (vector.Mu is { } mu)
			{
				await Assert.That(SignMuWithRandomness(key, mu, randomness)).IsEquivalentTo(vector.Sig, CollectionOrdering.Matching);
				await Assert.That(key.VerifyMu(mu, vector.Sig)).IsTrue();
			}
		}
	}
}
