using CryptoBase.KeyAgreements.Xdh;
using static CryptoBase.Tests.KeyAgreements.KeyAgreementTestUtils;

namespace CryptoBase.Tests.KeyAgreements.Xdh;

// The test vectors of RFC 7748 §5.2 and §6.2.
public class X448Rfc7748Test
{
	[Test]
	[Arguments("3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3", "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086", "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f")]
	[Arguments("203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f", "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db", "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d")]
	public async Task FunctionMatchesTheVectors(string scalar, string u, string expected)
	{
		using X448 key = X448.ImportPrivateKey(Convert.FromHexString(scalar));

		await Assert.That(DeriveSharedSecret(key, Convert.FromHexString(u))).IsEquivalentTo(Convert.FromHexString(expected), CollectionOrdering.Matching);
	}

	[Test]
	[Arguments(1, "3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113")]
	[Arguments(1000, "aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38")]
	public async Task IterationsMatchTheVectors(int iterations, string expected)
	{
		await Assert.That(Iterate(iterations)).IsEquivalentTo(Convert.FromHexString(expected), CollectionOrdering.Matching);
	}

	[Test]
	[Explicit]
	public async Task OneMillionIterationsMatchTheVector()
	{
		await Assert.That(Iterate(1_000_000)).IsEquivalentTo(Convert.FromHexString("077f453681caca3693198420bbe515cae0002472519b3e67661a7e89cab94695c8f4bcd66e61b9b9c946da8d524de3d69bd9d9d66b997e37"), CollectionOrdering.Matching);
	}

	[Test]
	public async Task DiffieHellmanMatchesTheVector()
	{
		using X448 alice = X448.ImportPrivateKey(Convert.FromHexString("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b"));
		using X448 bob = X448.ImportPrivateKey(Convert.FromHexString("1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d"));
		byte[] alicePublicKey = Convert.FromHexString("9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0");
		byte[] bobPublicKey = Convert.FromHexString("3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609");
		byte[] sharedSecret = Convert.FromHexString("07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d");

		using (Assert.Multiple())
		{
			await Assert.That(ExportPublicKey(alice)).IsEquivalentTo(alicePublicKey, CollectionOrdering.Matching);
			await Assert.That(ExportPublicKey(bob)).IsEquivalentTo(bobPublicKey, CollectionOrdering.Matching);
			await Assert.That(DeriveSharedSecret(alice, bobPublicKey)).IsEquivalentTo(sharedSecret, CollectionOrdering.Matching);
			await Assert.That(DeriveSharedSecret(bob, alicePublicKey)).IsEquivalentTo(sharedSecret, CollectionOrdering.Matching);
		}
	}

	private static byte[] Iterate(int iterations)
	{
		byte[] k = new byte[X448.PrivateKeyLength];
		byte[] u = new byte[X448.PublicKeyLength];
		byte[] result = new byte[X448.SharedSecretLength];
		k[0] = 5;
		u[0] = 5;

		for (int i = 0; i < iterations; ++i)
		{
			if (!X448Key.TryDeriveSharedSecret(k, u, result))
			{
				throw new InvalidOperationException($"Iteration {i} gave the all-zero value.");
			}

			(k, u, result) = (result, k, u);
		}

		return k;
	}
}
