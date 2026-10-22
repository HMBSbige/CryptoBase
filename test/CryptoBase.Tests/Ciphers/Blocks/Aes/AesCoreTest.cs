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
				byte[] actual = TestUtils.CreateGuardedBuffer(1, length, 2);
				crypto.EncryptBlocks(source.AsSpan(1), actual.AsSpan(1));
				await TestUtils.AssertOutput(actual, 1, expected);

				crypto.DecryptBlocks(actual.AsSpan(1, length), actual.AsSpan(1));
				await Assert.That(actual.AsMemory(1, length)).IsEquivalentTo(source.AsSpan(1).ToArray(), CollectionOrdering.Matching);
				crypto.EncryptBlocks(actual.AsSpan(1, length), actual.AsSpan(1));
				await Assert.That(actual.AsMemory(1, length)).IsEquivalentTo(expected, CollectionOrdering.Matching);

				expected = reference.DecryptEcb(source.AsSpan(1), PaddingMode.None);
				crypto.DecryptBlocks(source.AsSpan(1), actual.AsSpan(1));
				await TestUtils.AssertOutput(actual, 1, expected);
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
		using AesCipher crypto = AesCipher.Create(key);
		await AesTestUtils.AssertAllByteValuesMatchBcl(key, 64, crypto.EncryptBlocks, crypto.DecryptBlocks);
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
