using System.Security.Cryptography;
using static CryptoBase.Tests.KeyAgreements.Ecdh.EcdhTestUtils;

namespace CryptoBase.Tests.EllipticCurves;

public class ECKeyBclTest
{
	private const int Iterations = 8;

	private static readonly byte[] Message = "message"u8.ToArray();

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task PlatformPrivateKeysGiveTheSamePublicKeys(CurveCase curve)
	{
		SkipUnlessSupported(curve);

		for (int i = 0; i < Iterations; ++i)
		{
			using ECAlgorithm bcl = i % 2 is 0 ? ECDiffieHellman.Create(BclCurve(curve)) : ECDsa.Create(BclCurve(curve));
			ECParameters parameters = bcl.ExportParameters(true);
			KeyCase key = curve.NewKey();

			using (Assert.Multiple())
			{
				await Assert.That(key.TryImportPrivateKey(Normalize(parameters.D, curve.ScalarLength))).IsTrue();
				await Assert.That(key.ExportPublicKey()).IsEquivalentTo(Encode(curve, parameters.Q), CollectionOrdering.Matching);
			}
		}
	}

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task SharedSecretsMatchThePlatform(CurveCase curve)
	{
		SkipUnlessSupported(curve);

		for (int i = 0; i < Iterations; ++i)
		{
			using ECDiffieHellman bcl = ECDiffieHellman.Create(BclCurve(curve));
			using ECDiffieHellman bclPeer = ECDiffieHellman.Create(BclCurve(curve));
			KeyCase key = curve.NewKey();
			key.GenerateKey();
			KeyCase fromBcl = curve.NewKey();
			_ = fromBcl.TryImportPrivateKey(Normalize(bcl.ExportParameters(true).D, curve.ScalarLength));
			using ECDiffieHellman ours = ECDiffieHellman.Create(new ECParameters { Curve = BclCurve(curve), Q = Decode(curve, key.ExportPublicKey()) });

			using (Assert.Multiple())
			{
				await Assert.That(key.DeriveSharedSecret(Encode(curve, bcl.ExportParameters(false).Q))).IsEquivalentTo(bcl.DeriveRawSecretAgreement(ours.PublicKey), CollectionOrdering.Matching);
				await Assert.That(fromBcl.DeriveSharedSecret(Encode(curve, bclPeer.ExportParameters(false).Q))).IsEquivalentTo(bcl.DeriveRawSecretAgreement(bclPeer.PublicKey), CollectionOrdering.Matching);
			}
		}
	}

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task PlatformTakesGeneratedKeys(CurveCase curve)
	{
		SkipUnlessSupported(curve);

		for (int i = 0; i < Iterations; ++i)
		{
			KeyCase key = curve.NewKey();
			key.GenerateKey();
			ECPoint q = Decode(curve, key.ExportPublicKey());
			ECParameters keyPair = new() { Curve = BclCurve(curve), D = key.ExportPrivateKey(), Q = q };
			using ECDiffieHellman bcl = ECDiffieHellman.Create(keyPair);
			using ECDiffieHellman bclPeer = ECDiffieHellman.Create(BclCurve(curve));
			using ECDsa signer = ECDsa.Create(keyPair);
			using ECDsa verifier = ECDsa.Create(new ECParameters { Curve = BclCurve(curve), Q = q });

			using (Assert.Multiple())
			{
				await Assert.That(key.DeriveSharedSecret(Encode(curve, bclPeer.ExportParameters(false).Q))).IsEquivalentTo(bcl.DeriveRawSecretAgreement(bclPeer.PublicKey), CollectionOrdering.Matching);
				await Assert.That(verifier.VerifyData(Message, signer.SignData(Message, HashAlgorithmName.SHA256), HashAlgorithmName.SHA256)).IsTrue();
			}
		}
	}

	private static void SkipUnlessSupported(CurveCase curve)
	{
		try
		{
			using ECDiffieHellman key = ECDiffieHellman.Create(BclCurve(curve));
			_ = key.DeriveRawSecretAgreement(key.PublicKey);
			using ECDsa signer = ECDsa.Create(BclCurve(curve));
		}
		catch (PlatformNotSupportedException e)
		{
			Skip.Test($"The platform has no raw ECDH or ECDSA on {curve.Name}: {e.Message}");
		}
	}
}
