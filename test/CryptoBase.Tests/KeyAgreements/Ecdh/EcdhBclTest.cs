using CryptoBase.Abstractions.KeyAgreements;
using CryptoBase.KeyAgreements.Ecdh;
using CryptoBase.Tests.EllipticCurves;
using System.Security.Cryptography;
using static CryptoBase.Tests.KeyAgreements.Ecdh.EcdhTestUtils;
using static CryptoBase.Tests.KeyAgreements.KeyAgreementTestUtils;

namespace CryptoBase.Tests.KeyAgreements.Ecdh;

public class EcdhBclTest
{
	private const int Iterations = 8;

	[Test]
	[GenerateGenericTest(typeof(EcdhP256))]
	[GenerateGenericTest(typeof(EcdhP384))]
	[GenerateGenericTest(typeof(EcdhP521))]
	public async Task SharedSecretsMatchThePlatform<T>() where T : class, IKeyAgreement<T>
	{
		CurveCase curve = CurveOf<T>();
		SkipUnlessSupported(curve);

		for (int i = 0; i < Iterations; ++i)
		{
			using T key = T.GenerateKey();
			using ECDiffieHellman bcl = ECDiffieHellman.Create(BclCurve(curve));
			using ECDiffieHellman ours = ECDiffieHellman.Create(new ECParameters { Curve = BclCurve(curve), Q = Decode(curve, ExportPublicKey(key)) });
			byte[] expected = bcl.DeriveRawSecretAgreement(ours.PublicKey);

			await Assert.That(DeriveSharedSecret(key, Encode(curve, bcl.ExportParameters(false).Q))).IsEquivalentTo(expected, CollectionOrdering.Matching);
		}
	}

	[Test]
	[GenerateGenericTest(typeof(EcdhP256))]
	[GenerateGenericTest(typeof(EcdhP384))]
	[GenerateGenericTest(typeof(EcdhP521))]
	public async Task PrivateKeysMoveBetweenImplementations<T>() where T : class, IKeyAgreement<T>
	{
		CurveCase curve = CurveOf<T>();
		SkipUnlessSupported(curve);

		for (int i = 0; i < Iterations; ++i)
		{
			using ECDiffieHellman bcl = ECDiffieHellman.Create(BclCurve(curve));
			using ECDiffieHellman bclPeer = ECDiffieHellman.Create(BclCurve(curve));
			ECParameters parameters = bcl.ExportParameters(true);
			using T fromBcl = T.ImportPrivateKey(Normalize(parameters.D, curve.ScalarLength));

			using T key = T.GenerateKey();
			using ECDiffieHellman toBcl = ECDiffieHellman.Create(new ECParameters { Curve = BclCurve(curve), D = ExportPrivateKey(key), Q = Decode(curve, ExportPublicKey(key)) });
			byte[] peerPublicKey = Encode(curve, bclPeer.ExportParameters(false).Q);

			using (Assert.Multiple())
			{
				await Assert.That(ExportPublicKey(fromBcl)).IsEquivalentTo(Encode(curve, parameters.Q), CollectionOrdering.Matching);
				await Assert.That(DeriveSharedSecret(fromBcl, peerPublicKey)).IsEquivalentTo(bcl.DeriveRawSecretAgreement(bclPeer.PublicKey), CollectionOrdering.Matching);
				await Assert.That(toBcl.DeriveRawSecretAgreement(bclPeer.PublicKey)).IsEquivalentTo(DeriveSharedSecret(key, peerPublicKey), CollectionOrdering.Matching);
			}
		}
	}
}
