using CryptoBase.Tests.Wycheproof;
using System.Numerics;

namespace CryptoBase.Tests.EllipticCurves;

public class WycheproofEcdhTest
{
	public static IEnumerable<(CurveCase Curve, EcdhEcpointTestVector Vector)> Vectors()
	{
		foreach (CurveCase curve in CurveCase.All())
		{
			foreach (EcdhEcpointTestVector vector in WycheproofVectors.Load<EcdhEcpointTestVector>($"ecdh_{curve.Name}_ecpoint_test.json"))
			{
				yield return (curve, vector);
			}
		}
	}

	// The private keys, all in [1, n − 1], come in various lengths. The one acceptable vector has a compressed point, which is rejected
	// like the invalid ones.
	[Test]
	[MethodDataSource(nameof(Vectors))]
	public async Task SharedSecretMatches(CurveCase curve, EcdhEcpointTestVector vector)
	{
		KeyCase key = curve.NewKey();
		KeyCase peer = curve.NewKey();
		bool imported = key.TryImportPrivateKey(curve.EncodeScalar(new BigInteger(vector.Private, isUnsigned: true, isBigEndian: true)));

		using (Assert.Multiple())
		{
			await Assert.That(imported).IsTrue();

			if (vector.Result is WycheproofResult.Valid)
			{
				await Assert.That(peer.TryImportPublicKey(vector.Public)).IsTrue();
				await Assert.That(key.DeriveSharedSecret(vector.Public)).IsEquivalentTo(vector.Shared, CollectionOrdering.Matching);
			}
			else
			{
				if (vector.Result is WycheproofResult.Acceptable)
				{
					await Assert.That(vector.Flags).Contains("CompressedPoint");
				}

				await Assert.That(peer.TryImportPublicKey(vector.Public)).IsFalse();
				await Assert.That(key.DeriveSharedSecret(vector.Public)).IsNull();
			}
		}
	}
}
