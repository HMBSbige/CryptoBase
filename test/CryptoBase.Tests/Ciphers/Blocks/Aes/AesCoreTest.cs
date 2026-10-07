using CryptoBase.Ciphers.Blocks.Aes;
using System.Security.Cryptography;
using BclAes = System.Security.Cryptography.Aes;

namespace CryptoBase.Tests.Ciphers.Blocks.Aes;

public class AesCoreTest
{
	[Test]
	[Arguments(16)]
	[Arguments(24)]
	[Arguments(32)]
	public async Task BatchWidthsMatchSingleBlockReference(int keyLength)
	{
		byte[] key = TestUtils.CreateDeterministicSource(keyLength);

		await TestUtils.TestNBlock16<AesCipher>(key);
	}

	[Test]
	[Arguments(16)]
	[Arguments(24)]
	[Arguments(32)]
	public async Task BatchesMatchBcl(int keyLength)
	{
		Random random = new(197 + keyLength);
		using BclAes reference = BclAes.Create();

		for (int iteration = 0; iteration < 8; ++iteration)
		{
			byte[] key = new byte[keyLength];
			random.NextBytes(key);
			reference.SetKey(key);
			using AesCipher crypto = AesCipher.Create(key);

			foreach (int blocks in new[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 32, 33, 65 })
			{
				int length = blocks * 16;
				byte[] source = new byte[length + 1];
				random.NextBytes(source);
				byte[] expected = reference.EncryptEcb(source.AsSpan(1), PaddingMode.None);
				byte[] actual = new byte[length + 3];
				TestUtils.PrepareDestination(actual);
				crypto.EncryptBlocks(source.AsSpan(1), actual.AsSpan(1));
				await Assert.That(actual.AsMemory(1, length)).IsEquivalentTo(expected, CollectionOrdering.Matching);
				await Assert.That(actual[0]).IsEqualTo(TestUtils.DestinationSentinel);
				await Assert.That(actual.AsMemory(length + 1)).All(static value => value is TestUtils.DestinationSentinel);

				crypto.DecryptBlocks(actual.AsSpan(1, length), actual.AsSpan(1));
				await Assert.That(actual.AsMemory(1, length)).IsEquivalentTo(source.AsSpan(1).ToArray(), CollectionOrdering.Matching);
				crypto.EncryptBlocks(actual.AsSpan(1, length), actual.AsSpan(1));
				await Assert.That(actual.AsMemory(1, length)).IsEquivalentTo(expected, CollectionOrdering.Matching);

				expected = reference.DecryptEcb(source.AsSpan(1), PaddingMode.None);
				crypto.DecryptBlocks(source.AsSpan(1), actual.AsSpan(1));
				await Assert.That(actual.AsMemory(1, length)).IsEquivalentTo(expected, CollectionOrdering.Matching);
				await Assert.That(actual[0]).IsEqualTo(TestUtils.DestinationSentinel);
				await Assert.That(actual.AsMemory(length + 1)).All(static value => value is TestUtils.DestinationSentinel);
			}
		}
	}

	[Test]
	[Arguments(16)]
	[Arguments(24)]
	[Arguments(32)]
	public async Task AllByteValuesMatchBcl(int keyLength)
	{
		byte[] key = TestUtils.CreateDeterministicSource(keyLength);
		byte[] source = new byte[256 * 64];

		for (int value = 0; value < 256; ++value)
		{
			source.AsSpan(value * 64, 64).Fill((byte)value);
		}

		using BclAes reference = BclAes.Create();
		reference.SetKey(key);
		using AesCipher crypto = AesCipher.Create(key);

		byte[] actual = new byte[source.Length];
		crypto.EncryptBlocks(source, actual);
		await Assert.That(actual).IsEquivalentTo(reference.EncryptEcb(source, PaddingMode.None), CollectionOrdering.Matching);
		crypto.DecryptBlocks(source, actual);
		await Assert.That(actual).IsEquivalentTo(reference.DecryptEcb(source, PaddingMode.None), CollectionOrdering.Matching);
	}

	[Test]
	[Arguments(0)]
	[Arguments(15)]
	[Arguments(17)]
	[Arguments(23)]
	[Arguments(25)]
	[Arguments(31)]
	[Arguments(33)]
	public async Task InvalidKeyLengthsAreRejected(int length)
	{
		byte[] key = new byte[length];
		await Assert.That(() => AesCipher.Create(key)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("key");
	}
}
