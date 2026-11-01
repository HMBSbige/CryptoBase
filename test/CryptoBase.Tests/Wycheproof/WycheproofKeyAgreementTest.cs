using CryptoBase.Abstractions.KeyAgreements;
using CryptoBase.KeyAgreements.Ecdh;
using CryptoBase.KeyAgreements.Xdh;
using CryptoBase.Tests.EllipticCurves;
using static CryptoBase.Tests.KeyAgreements.KeyAgreementTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Wycheproof;

public class WycheproofKeyAgreementTest
{
	[Test]
	[WycheproofVectors<EcdhEcpointTestVector>("ecdh_secp256r1_ecpoint_test.json")]
	public Task EcdhP256(EcdhEcpointTestVector vector)
	{
		return VerifyEcdh<EcdhP256>(vector);
	}

	[Test]
	[WycheproofVectors<EcdhEcpointTestVector>("ecdh_secp384r1_ecpoint_test.json")]
	public Task EcdhP384(EcdhEcpointTestVector vector)
	{
		return VerifyEcdh<EcdhP384>(vector);
	}

	[Test]
	[WycheproofVectors<EcdhEcpointTestVector>("ecdh_secp521r1_ecpoint_test.json")]
	public Task EcdhP521(EcdhEcpointTestVector vector)
	{
		return VerifyEcdh<EcdhP521>(vector);
	}

	[Test]
	[WycheproofVectors<XdhTestVector>("x25519_test.json")]
	public Task X25519(XdhTestVector vector)
	{
		return VerifyXdh<X25519>(vector);
	}

	// Every vector, valid or acceptable, gives its shared secret, twist points and non-canonical u-coordinates included, except the ZeroSharedSecret ones: their all-zero secret must give false.
	private static async Task VerifyXdh<T>(XdhTestVector vector) where T : class, IKeyAgreement<T>
	{
		using T key = T.ImportPrivateKey(vector.Private);
		(bool result, byte[] output) = TryDeriveSharedSecret(key, vector.Public);

		using (Assert.Multiple())
		{
			if (vector.Shared.AsSpan().ContainsAnyExcept((byte)0))
			{
				await Assert.That(result).IsTrue();
				await Assert.That(output).IsEquivalentTo(vector.Shared, CollectionOrdering.Matching);
				return;
			}

			await Assert.That(vector.Flags).Contains("ZeroSharedSecret");
			await Assert.That(result).IsFalse();
			await Assert.That(output).All(static value => value is DestinationSentinel);
		}
	}

	// The private keys, all in [1, n − 1], come in various lengths. The one acceptable vector has a compressed point, which is rejected like the invalid ones.
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
