using CryptoBase.KeyAgreements.Xdh;
using static CryptoBase.Tests.KeyAgreements.KeyAgreementTestUtils;

namespace CryptoBase.Tests.KeyAgreements.Xdh;

// The test vectors of RFC 7748 §5.2 and §6.1.
public class X25519Rfc7748Test
{
	[Test]
	[Arguments("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")]
	[Arguments("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d", "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493", "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")]
	public async Task FunctionMatchesTheVectors(string scalar, string u, string expected)
	{
		using X25519 key = X25519.ImportPrivateKey(Convert.FromHexString(scalar));

		await Assert.That(DeriveSharedSecret(key, Convert.FromHexString(u))).IsEquivalentTo(Convert.FromHexString(expected), CollectionOrdering.Matching);
	}

	[Test]
	[Arguments(1, "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")]
	[Arguments(1000, "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")]
	public async Task IterationsMatchTheVectors(int iterations, string expected)
	{
		await Assert.That(Iterate(iterations)).IsEquivalentTo(Convert.FromHexString(expected), CollectionOrdering.Matching);
	}

	[Test]
	[Explicit]
	public async Task OneMillionIterationsMatchTheVector()
	{
		await Assert.That(Iterate(1_000_000)).IsEquivalentTo(Convert.FromHexString("7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424"), CollectionOrdering.Matching);
	}

	[Test]
	public async Task DiffieHellmanMatchesTheVector()
	{
		using X25519 alice = X25519.ImportPrivateKey(Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
		using X25519 bob = X25519.ImportPrivateKey(Convert.FromHexString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"));
		byte[] alicePublicKey = Convert.FromHexString("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
		byte[] bobPublicKey = Convert.FromHexString("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
		byte[] sharedSecret = Convert.FromHexString("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

		using (Assert.Multiple())
		{
			await Assert.That(ExportPublicKey(alice)).IsEquivalentTo(alicePublicKey, CollectionOrdering.Matching);
			await Assert.That(ExportPublicKey(bob)).IsEquivalentTo(bobPublicKey, CollectionOrdering.Matching);
			await Assert.That(DeriveSharedSecret(alice, bobPublicKey)).IsEquivalentTo(sharedSecret, CollectionOrdering.Matching);
			await Assert.That(DeriveSharedSecret(bob, alicePublicKey)).IsEquivalentTo(sharedSecret, CollectionOrdering.Matching);
		}
	}

	// k and u start at 9; each iteration sets k to X25519(k, u) and u to the old k.
	private static byte[] Iterate(int iterations)
	{
		byte[] k = new byte[X25519.PrivateKeyLength];
		byte[] u = new byte[X25519.PublicKeyLength];
		byte[] result = new byte[X25519.SharedSecretLength];
		k[0] = 9;
		u[0] = 9;

		for (int i = 0; i < iterations; ++i)
		{
			if (!X25519Key.TryDeriveSharedSecret(k, u, result))
			{
				throw new InvalidOperationException($"Iteration {i} gave the all-zero value.");
			}

			(k, u, result) = (result, k, u);
		}

		return k;
	}
}
