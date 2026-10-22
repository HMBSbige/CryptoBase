using CryptoBase.Ciphers.Blocks.Aes;
using BclAes = System.Security.Cryptography.Aes;

namespace CryptoBase.Tests.Ciphers.Blocks.Aes;

public class AesBitsliceTest
{
	[Before(Class)]
	public static void SkipWhenUnavailable()
	{
		if (!AesCipherBitslice.IsSupported)
		{
			Skip.Test("SSE2 is not supported.");
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task UnalignedBatchesAndInPlaceTransformsMatchBcl([Matrix(16, 24, 32)] int keyLength, [Matrix(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 65)] int blocks)
	{
		Random random = new(197 + keyLength);
		using BclAes reference = BclAes.Create();

		for (int iteration = 0; iteration < 3; ++iteration)
		{
			byte[] key = new byte[keyLength];
			random.NextBytes(key);
			reference.SetKey(key);
			using AesCipherBitslice crypto = AesCipherBitslice.Create(key);
			int sourceOffset = iteration * 7 + 1;
			int destinationOffset = 15 - iteration * 6;

			await AesTestUtils.AssertUnalignedAndInPlaceTransformsMatchBcl(reference, random, blocks, sourceOffset, destinationOffset, crypto.EncryptBlocks, crypto.DecryptBlocks);
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task AllByteValuesMatchBcl([Matrix(16, 24, 32)] int keyLength)
	{
		byte[] key = TestUtils.CreateDeterministicSource(keyLength);
		using AesCipherBitslice crypto = AesCipherBitslice.Create(key);
		await AesTestUtils.AssertAllByteValuesMatchBcl(key, 16, crypto.EncryptBlocks, crypto.DecryptBlocks);
	}
}
