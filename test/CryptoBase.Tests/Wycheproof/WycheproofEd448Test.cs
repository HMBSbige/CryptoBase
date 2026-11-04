using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures.EdDsa;
using CryptoBase.Tests.Signatures.EdDsa;
using System.Diagnostics.CodeAnalysis;
using static CryptoBase.Tests.Signatures.EdDsa.Ed448TestUtils;

namespace CryptoBase.Tests.Wycheproof;

public class WycheproofEd448Test
{
	private static readonly byte[] EmptyContextDomain = Ed448Reference.Domain(Ed448Variant.Pure, []);

	// The reference follows the verification policy of the library, so it decides each vector as Wycheproof does.
	[Test]
	[WycheproofVectors<EddsaVerifyTestGroup, EddsaVerifyTestVector>("ed448_test.json")]
	[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Assertions are awaited before the key is disposed.")]
	public async Task Verification(EddsaVerifyTestVector vector)
	{
		using Ed448 key = Ed448.ImportSubjectPublicKeyInfo(vector.PublicKeyDer);
		using Ed448 fromPublicKey = Ed448.ImportPublicKey(vector.PublicKey);
		bool valid = vector.Result is WycheproofResult.Valid;

		using (Assert.Multiple())
		{
			await Assert.That(vector.Result).IsNotEqualTo(WycheproofResult.Acceptable);
			await Assert.That(ExportPublicKey(key)).IsEquivalentTo(vector.PublicKey, CollectionOrdering.Matching);
			await Assert.That(Ed448Reference.Verify(vector.PublicKey, vector.Msg, vector.Sig, EmptyContextDomain)).IsEqualTo(valid);
			await Assert.That(fromPublicKey.Verify(SignatureAlgorithm.Ed448, vector.Msg, vector.Sig)).IsEqualTo(valid);

			for (int i = 0; i < 3; ++i)
			{
				await Assert.That(key.Verify(vector.Msg, vector.Sig)).IsEqualTo(valid).Because($"verification {i}");
			}
		}
	}
}
