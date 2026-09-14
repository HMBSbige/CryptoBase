using CryptoBase.Ciphers.Blocks.Aes;
using System.Security.Cryptography;
using BclAes = System.Security.Cryptography.Aes;

namespace CryptoBase.Tests.Ciphers.Blocks.Aes;

public class AesCoreTest
{
	/// <summary>
	/// https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
	/// </summary>
	[Test]
	[Arguments(@"000102030405060708090a0b0c0d0e0f", @"00112233445566778899aabbccddeeff", @"69c4e0d86a7b0430d8cdb78070b4c55a")]
	[Arguments(@"000102030405060708090a0b0c0d0e0f1011121314151617", @"00112233445566778899aabbccddeeff", @"dda97ca4864cdfe06eaf70a0ec0d7191")]
	[Arguments(@"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", @"00112233445566778899aabbccddeeff", @"8ea2b7ca516745bfeafc49904b496089")]
	[Arguments(@"80000000000000000000000000000000", @"00000000000000000000000000000000", @"0EDD33D3C621E546455BD8BA1418BEC8")]
	[Arguments(@"000000000000000000000000000000000000000000000000", @"80000000000000000000000000000000", @"6CD02513E8D4DC986B4AFE087A60BD0C")]
	[Arguments(@"0000000000000000000000000000000000000000000000000000000000000000", @"80000000000000000000000000000000", @"DDC6BF790C15760D8D9AEB6F9A75FD4E")]
	public async Task StandardVectorEncryptsAndDecrypts(string keyHex, string hex1, string hex2)
	{
		byte[] key = Convert.FromHexString(keyHex);
		byte[] plain = Convert.FromHexString(hex1);
		byte[] cipher = Convert.FromHexString(hex2);

		await TestUtils.TestBlock16<AesCipher>(key, plain, cipher);
	}

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
