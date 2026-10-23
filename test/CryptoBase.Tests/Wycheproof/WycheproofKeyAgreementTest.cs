using CryptoBase.Abstractions.KeyAgreements;
using CryptoBase.KeyAgreements.Ecdh;
using CryptoBase.Tests.EllipticCurves;
using static CryptoBase.Tests.KeyAgreements.KeyAgreementTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Wycheproof;

public class WycheproofKeyAgreementTest
{
	public static IEnumerable<EcdhEcpointTestVector> Vectors(string fileName)
	{
		return WycheproofVectors.Load<EcdhEcpointTestVector>(fileName);
	}

	[Test]
	[MethodDataSource(nameof(Vectors), Arguments = ["ecdh_secp256r1_ecpoint_test.json"])]
	public Task EcdhP256(EcdhEcpointTestVector vector)
	{
		return VerifyEcdh<EcdhP256>(vector);
	}

	[Test]
	[MethodDataSource(nameof(Vectors), Arguments = ["ecdh_secp384r1_ecpoint_test.json"])]
	public Task EcdhP384(EcdhEcpointTestVector vector)
	{
		return VerifyEcdh<EcdhP384>(vector);
	}

	[Test]
	[MethodDataSource(nameof(Vectors), Arguments = ["ecdh_secp521r1_ecpoint_test.json"])]
	public Task EcdhP521(EcdhEcpointTestVector vector)
	{
		return VerifyEcdh<EcdhP521>(vector);
	}

	// The private keys, all in [1, n − 1], come in various lengths. The one acceptable vector has a compressed point, which is rejected like
	// the invalid ones.
	private static async Task VerifyEcdh<T>(EcdhEcpointTestVector vector) where T : class, IKeyAgreement<T>
	{
		using T key = T.ImportPrivateKey(CurveCase.EncodeInteger(ModulusCase.Decode(vector.Private), T.PrivateKeyLength));
		(bool result, byte[] output) = TryDeriveSharedSecret(key, vector.Public);

		if (vector.Result is WycheproofResult.Valid)
		{
			using (Assert.Multiple())
			{
				await Assert.That(result).IsTrue();
				await Assert.That(output).IsEquivalentTo(vector.Shared, CollectionOrdering.Matching);
			}

			return;
		}

		using (Assert.Multiple())
		{
			if (vector.Result is WycheproofResult.Acceptable)
			{
				await Assert.That(vector.Flags).Contains("CompressedPoint");
			}

			await Assert.That(result).IsFalse();
			await Assert.That(output).All(static value => value is DestinationSentinel);
		}
	}
}
