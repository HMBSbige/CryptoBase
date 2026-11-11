using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures.EdDsa;
using CryptoBase.Tests.Signatures.EdDsa;
using System.Diagnostics.CodeAnalysis;
using static CryptoBase.Tests.Signatures.EdDsa.Ed25519TestUtils;

namespace CryptoBase.Tests.Wycheproof;

public class WycheproofEd25519Test
{
	// Every group key is valid. The acceptable vectors have a public key outside the prime-order subgroup and a signature that meets the equation, which the library takes as it accepts points of small order. The first verification with an instance goes without the table of its public key, and the later ones use it. The reference, which follows the verification policy of the library, decides every other vector as Wycheproof does.
	[Test]
	[WycheproofVectors<EddsaVerifyTestGroup, EddsaVerifyTestVector>("ed25519_test.json")]
	[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Assertions are awaited before the key is disposed.")]
	public async Task Verification(EddsaVerifyTestVector vector)
	{
		using Ed25519 key = Ed25519.ImportSubjectPublicKeyInfo(vector.PublicKeyDer);
		using Ed25519 fromPublicKey = Ed25519.ImportPublicKey(vector.PublicKey);
		bool valid = vector.Result is not WycheproofResult.Invalid;

		using (Assert.Multiple())
		{
			await Assert.That(vector.Result is not WycheproofResult.Acceptable || vector.Flags is ["SmallOrderPublicKey" or "MixedOrderPublicKey"]).IsTrue();
			await Assert.That(ExportPublicKey(key)).IsEquivalentTo(vector.PublicKey, CollectionOrdering.Matching);
			await Assert.That(Ed25519Reference.Verify(vector.PublicKey, vector.Msg, vector.Sig, [])).IsEqualTo(valid);
			await Assert.That(fromPublicKey.Verify(SignatureAlgorithm.Ed25519, vector.Msg, vector.Sig)).IsEqualTo(valid);

			for (int i = 0; i < 3; ++i)
			{
				await Assert.That(key.Verify(vector.Msg, vector.Sig)).IsEqualTo(valid).Because($"verification {i}");
			}
		}
	}
}
