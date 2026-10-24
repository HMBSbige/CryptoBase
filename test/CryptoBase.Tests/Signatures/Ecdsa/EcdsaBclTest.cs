using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures.Ecdsa;
using CryptoBase.Tests.EllipticCurves;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using System.Security.Cryptography;
using static CryptoBase.Tests.Signatures.Ecdsa.EcdsaTestUtils;
using static CryptoBase.Tests.Signatures.SignatureTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Signatures.Ecdsa;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
internal class EcdsaBclTest
{
	private const int Iterations = 8;

	[Test]
	[GenerateGenericTest(typeof(EcdsaP256))]
	[GenerateGenericTest(typeof(EcdsaP384))]
	[GenerateGenericTest(typeof(EcdsaP521))]
	public async Task PlatformVerifiesOurSignatures<T>() where T : class, IEcdsa<T>
	{
		ECCurve bclCurve = SkipUnlessSupported<T>();
		List<string> failed = [];

		for (int i = 0; i < Iterations; ++i)
		{
			using T key = T.GenerateKey();
			using ECDsa bcl = ECDsa.Create(bclCurve);
			bcl.ImportSubjectPublicKeyInfo(ExportSubjectPublicKeyInfo(key), out _);
			byte[] message = CreateDeterministicSource(1 + i * 37);

			foreach (SignatureAlgorithm algorithm in Algorithms)
			{
				HashAlgorithmName hashName = HashName(algorithm);

				if (!bcl.VerifyData(message, Sign(key, algorithm, message), hashName, DSASignatureFormat.Rfc3279DerSequence)
					|| !bcl.VerifyData(message, Sign(key, algorithm, message, [], EcdsaSignatureFormat.Concatenated), hashName, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
				{
					failed.Add($"{i}: {algorithm}");
				}
			}
		}

		await Assert.That(failed).IsEmpty();
	}

	[Test]
	[GenerateGenericTest(typeof(EcdsaP256))]
	[GenerateGenericTest(typeof(EcdsaP384))]
	[GenerateGenericTest(typeof(EcdsaP521))]
	public async Task WeVerifyPlatformSignatures<T>() where T : class, IEcdsa<T>
	{
		ECCurve bclCurve = SkipUnlessSupported<T>();
		List<string> failed = [];

		for (int i = 0; i < Iterations; ++i)
		{
			using ECDsa bcl = ECDsa.Create(bclCurve);
			using T key = T.ImportSubjectPublicKeyInfo(bcl.ExportSubjectPublicKeyInfo());
			byte[] message = CreateDeterministicSource(1 + i * 37);

			foreach (SignatureAlgorithm algorithm in Algorithms)
			{
				HashAlgorithmName hashName = HashName(algorithm);

				if (!key.Verify(algorithm, message, bcl.SignData(message, hashName, DSASignatureFormat.Rfc3279DerSequence))
					|| !key.Verify(algorithm, message, bcl.SignData(message, hashName, DSASignatureFormat.IeeeP1363FixedFieldConcatenation), EcdsaSignatureFormat.Concatenated)
					|| key.Verify(algorithm, Flip(message, 0), bcl.SignData(message, hashName, DSASignatureFormat.Rfc3279DerSequence)))
				{
					failed.Add($"{i}: {algorithm}");
				}
			}
		}

		await Assert.That(failed).IsEmpty();
	}

	[Test]
	[GenerateGenericTest(typeof(EcdsaP256))]
	[GenerateGenericTest(typeof(EcdsaP384))]
	[GenerateGenericTest(typeof(EcdsaP521))]
	public async Task HashesOfAnyLengthAgree<T>() where T : class, IEcdsa<T>
	{
		ECCurve bclCurve = SkipUnlessSupported<T>();
		using T key = T.GenerateKey();
		using ECDsa bcl = ECDsa.Create(bclCurve);
		bcl.ImportSubjectPublicKeyInfo(ExportSubjectPublicKeyInfo(key), out _);
		using T verifier = T.ImportSubjectPublicKeyInfo(bcl.ExportSubjectPublicKeyInfo());
		using ECDsa bclSigner = ECDsa.Create(bclCurve);
		using T bclKey = T.ImportSubjectPublicKeyInfo(bclSigner.ExportSubjectPublicKeyInfo());
		List<int> failed = [];

		foreach (int length in (int[])[20, 28, T.PrivateKeyLength - 1, T.PrivateKeyLength, T.PrivateKeyLength + 1, 48, 64])
		{
			byte[] hash = CreateDeterministicSource(length);
			byte[] signature = SignHash(key, SignatureAlgorithm.EcdsaSha256, hash, [], EcdsaSignatureFormat.Der);

			if (!bcl.VerifyHash(hash, signature, DSASignatureFormat.Rfc3279DerSequence)
				|| !verifier.VerifyHash(hash, signature, EcdsaSignatureFormat.Der)
				|| !bclKey.VerifyHash(hash, bclSigner.SignHash(hash, DSASignatureFormat.Rfc3279DerSequence), EcdsaSignatureFormat.Der))
			{
				failed.Add(length);
			}
		}

		await Assert.That(failed).IsEmpty();
	}

	[Test]
	[GenerateGenericTest(typeof(EcdsaP256))]
	[GenerateGenericTest(typeof(EcdsaP384))]
	[GenerateGenericTest(typeof(EcdsaP521))]
	public async Task KeysRoundTripThroughThePlatform<T>() where T : class, IEcdsa<T>
	{
		ECCurve bclCurve = SkipUnlessSupported<T>();
		CurveCase curve = CurveOf<T>();

		for (int i = 0; i < Iterations; ++i)
		{
			using T key = T.GenerateKey();
			using ECDsa fromOurs = ECDsa.Create(bclCurve);
			fromOurs.ImportPkcs8PrivateKey(ExportPkcs8PrivateKey(key), out _);
			ECParameters ourParameters = fromOurs.ExportParameters(true);
			using ECDsa bcl = ECDsa.Create(bclCurve);
			ECParameters bclParameters = bcl.ExportParameters(true);
			using T fromBcl = T.ImportPkcs8PrivateKey(bcl.ExportPkcs8PrivateKey());
			using T fromBclPublicKey = T.ImportSubjectPublicKeyInfo(bcl.ExportSubjectPublicKeyInfo());

			using (Assert.Multiple())
			{
				await Assert.That(Normalize(ourParameters.D, curve.ScalarLength)).IsEquivalentTo(ExportPrivateKey(key), CollectionOrdering.Matching);
				await Assert.That(fromOurs.ExportSubjectPublicKeyInfo()).IsEquivalentTo(ExportSubjectPublicKeyInfo(key), CollectionOrdering.Matching);
				await Assert.That(ExportPrivateKey(fromBcl)).IsEquivalentTo(Normalize(bclParameters.D, curve.ScalarLength), CollectionOrdering.Matching);
				await Assert.That(ExportSubjectPublicKeyInfo(fromBcl)).IsEquivalentTo(bcl.ExportSubjectPublicKeyInfo(), CollectionOrdering.Matching);
				await Assert.That(ExportSubjectPublicKeyInfo(fromBclPublicKey)).IsEquivalentTo(bcl.ExportSubjectPublicKeyInfo(), CollectionOrdering.Matching);
				await Assert.That(ExportPublicKey(fromBcl)).IsEquivalentTo((byte[])[0x04, .. Normalize(bclParameters.Q.X, curve.FieldLength), .. Normalize(bclParameters.Q.Y, curve.FieldLength)], CollectionOrdering.Matching);
			}
		}
	}

	private static ECCurve SkipUnlessSupported<T>() where T : class, IEcdsa<T>
	{
		CurveCase curve = CurveOf<T>();
		ECCurve bclCurve = ECCurve.CreateFromValue(curve.Parameters.Oid);

		try
		{
			using ECDsa key = ECDsa.Create(bclCurve);
			byte[] message = [1, 2, 3];
			byte[] signature = key.SignData(message, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
			_ = key.VerifyData(message, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
			_ = key.ExportPkcs8PrivateKey();
		}
		catch (Exception e) when (e is PlatformNotSupportedException or CryptographicException)
		{
			Skip.Test($"The platform has no ECDSA on {curve.Name}: {e.Message}");
		}

		return bclCurve;
	}

	private static byte[] Normalize(byte[]? value, int length)
	{
		ArgumentNullException.ThrowIfNull(value);

		return CurveCase.EncodeInteger(new BigInteger(value, isUnsigned: true, isBigEndian: true), length);
	}
}
