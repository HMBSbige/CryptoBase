using CryptoBase.Abstractions.KeyAgreements;
using CryptoBase.Abstractions.Kems;
using CryptoBase.KeyAgreements.Ecdh;
using CryptoBase.Kems.Hybrid;
using CryptoBase.Kems.MLKem;
using CryptoBase.Tests.EllipticCurves;
using CryptoBase.Tests.KeyAgreements.Ecdh;
using CryptoBase.Tests.Kems.MLKem;
using System.Security.Cryptography;
using static CryptoBase.Tests.KeyAgreements.Ecdh.EcdhTestUtils;
using static CryptoBase.Tests.Kems.Hybrid.EcMLKemTestUtils;
using static CryptoBase.Tests.Kems.KemTestUtils;
using static CryptoBase.Tests.TestUtils;
using BclMLKem = System.Security.Cryptography.MLKem;

namespace CryptoBase.Tests.Kems.Hybrid;

public class EcMLKemBclTest
{
	private const int Iterations = 8;

	[Test]
	[GenerateGenericTest(typeof(SecP256r1MLKem768), typeof(EcdhP256), typeof(MLKem768))]
	[GenerateGenericTest(typeof(SecP384r1MLKem1024), typeof(EcdhP384), typeof(MLKem1024))]
	public async Task DecapsulatesWhatThePlatformEncapsulates<T, TEcdh, TMLKem>() where T : class, IKem<T> where TEcdh : class, IKeyAgreement<TEcdh> where TMLKem : class, IKem<TMLKem>
	{
		CurveCase curve = CurveOf<TEcdh>();
		SkipUnlessSupported(curve);

		for (int i = 0; i < Iterations; ++i)
		{
			using T kem = T.GenerateKey();
			using T fromDecapsulationKey = T.ImportDecapsulationKey(ExportDecapsulationKey(kem));
			(byte[] publicKey, byte[] mlKemEncapsulationKey) = Split(ExportEncapsulationKey(kem), TEcdh.PublicKeyLength);
			using ECDiffieHellman peer = ECDiffieHellman.Create(new ECParameters { Curve = BclCurve(curve), Q = Decode(curve, publicKey) });
			using ECDiffieHellman ephemeral = ECDiffieHellman.Create(BclCurve(curve));
			using BclMLKem mlKem = BclMLKem.ImportEncapsulationKey(MLKemTestUtils.BclAlgorithm<TMLKem>(), mlKemEncapsulationKey);
			mlKem.Encapsulate(out byte[] mlKemCiphertext, out byte[] mlKemSecret);
			byte[] ciphertext = Concat(Encode(curve, ephemeral.ExportParameters(false).Q), mlKemCiphertext);
			byte[] expected = Concat(ephemeral.DeriveRawSecretAgreement(peer.PublicKey), mlKemSecret);

			using (Assert.Multiple())
			{
				await Assert.That(Decapsulate(kem, ciphertext)).IsEquivalentTo(expected, CollectionOrdering.Matching);
				await Assert.That(Decapsulate(fromDecapsulationKey, ciphertext)).IsEquivalentTo(expected, CollectionOrdering.Matching);
			}
		}
	}

	[Test]
	[GenerateGenericTest(typeof(SecP256r1MLKem768), typeof(EcdhP256), typeof(MLKem768))]
	[GenerateGenericTest(typeof(SecP384r1MLKem1024), typeof(EcdhP384), typeof(MLKem1024))]
	public async Task ThePlatformDecapsulatesWhatTheKeyEncapsulates<T, TEcdh, TMLKem>() where T : class, IKem<T> where TEcdh : class, IKeyAgreement<TEcdh> where TMLKem : class, IKem<TMLKem>
	{
		CurveCase curve = CurveOf<TEcdh>();
		SkipUnlessSupported(curve);

		for (int i = 0; i < Iterations; ++i)
		{
			using ECDiffieHellman staticKey = ECDiffieHellman.Create(BclCurve(curve));
			using BclMLKem mlKem = BclMLKem.GenerateKey(MLKemTestUtils.BclAlgorithm<TMLKem>());
			using T kem = T.ImportEncapsulationKey(Concat(Encode(curve, staticKey.ExportParameters(false).Q), mlKem.ExportEncapsulationKey()));
			(byte[] ciphertext, byte[] sharedSecret) = Encapsulate(kem);
			(byte[] ephemeralPublicKey, byte[] mlKemCiphertext) = Split(ciphertext, TEcdh.PublicKeyLength);
			using ECDiffieHellman ephemeral = ECDiffieHellman.Create(new ECParameters { Curve = BclCurve(curve), Q = Decode(curve, ephemeralPublicKey) });

			await Assert.That(sharedSecret).IsEquivalentTo(Concat(staticKey.DeriveRawSecretAgreement(ephemeral.PublicKey), mlKem.Decapsulate(mlKemCiphertext)), CollectionOrdering.Matching);
		}
	}

	[Test]
	[GenerateGenericTest(typeof(SecP256r1MLKem768), typeof(EcdhP256), typeof(MLKem768))]
	[GenerateGenericTest(typeof(SecP384r1MLKem1024), typeof(EcdhP384), typeof(MLKem1024))]
	public async Task ImportsKeysOfPlatformKeys<T, TEcdh, TMLKem>() where T : class, IKem<T> where TEcdh : class, IKeyAgreement<TEcdh> where TMLKem : class, IKem<TMLKem>
	{
		CurveCase curve = CurveOf<TEcdh>();
		SkipUnlessSupported(curve);

		for (int i = 0; i < Iterations; ++i)
		{
			using ECDiffieHellman ecdh = ECDiffieHellman.Create(BclCurve(curve));
			using BclMLKem mlKem = BclMLKem.GenerateKey(MLKemTestUtils.BclAlgorithm<TMLKem>());
			ECParameters parameters = ecdh.ExportParameters(true);
			byte[] privateKey = Normalize(parameters.D, curve.ScalarLength);
			byte[] encapsulationKey = Concat(Encode(curve, parameters.Q), mlKem.ExportEncapsulationKey());
			byte[] decapsulationKey = Concat(privateKey, mlKem.ExportDecapsulationKey());
			using T fromSeed = T.ImportPrivateSeed(Concat(privateKey, mlKem.ExportPrivateSeed()));
			using T fromDecapsulationKey = T.ImportDecapsulationKey(decapsulationKey);

			using (Assert.Multiple())
			{
				await Assert.That(ExportEncapsulationKey(fromSeed)).IsEquivalentTo(encapsulationKey, CollectionOrdering.Matching);
				await Assert.That(ExportDecapsulationKey(fromSeed)).IsEquivalentTo(decapsulationKey, CollectionOrdering.Matching);
				await Assert.That(ExportEncapsulationKey(fromDecapsulationKey)).IsEquivalentTo(encapsulationKey, CollectionOrdering.Matching);
			}
		}
	}

	private static void SkipUnlessSupported(CurveCase curve)
	{
		if (!BclMLKem.IsSupported)
		{
			Skip.Test("The platform does not support ML-KEM.");
		}

		EcdhTestUtils.SkipUnlessSupported(curve);
	}
}
