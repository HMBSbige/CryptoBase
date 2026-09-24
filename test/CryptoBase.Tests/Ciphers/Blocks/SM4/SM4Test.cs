using CryptoBase.Ciphers.Blocks.SM4;

namespace CryptoBase.Tests.Ciphers.Blocks.SM4;

public class SM4Test
{
	[Test]
	[Arguments("0123456789ABCDEFFEDCBA9876543210", "0123456789ABCDEFFEDCBA9876543210", "681EDF34D206965E86B3E94F536E4246")]
	[Arguments("FEDCBA98765432100123456789ABCDEF", "000102030405060708090A0B0C0D0E0F", "F766678F13F01ADEAC1B3EA955ADB594")]
	[Arguments("0123456789ABCDEFFEDCBA9876543210", "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD", "5EC8143DE509CFF7B5179F8F474B8619")]
	[Arguments("0123456789ABCDEFFEDCBA9876543210", "EEEEEEEEFFFFFFFFAAAAAAAABBBBBBBB", "2F1D305A7FB17DF985F81C8482192304")]
	[Arguments("FEDCBA98765432100123456789ABCDEF", "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD", "C5876897E4A59BBBA72A10C83872245B")]
	[Arguments("FEDCBA98765432100123456789ABCDEF", "EEEEEEEEFFFFFFFFAAAAAAAABBBBBBBB", "12DD90BC2D200692B529A4155AC9E600")]
	[Arguments("0123456789ABCDEFFEDCBA9876543210", "994AC3E7C357896A81FCA80E383EEF80", "B198F2DE3F4BAED1F0F1304C01275A8F")]
	[Arguments("0123456789ABCDEFFEDCBA9876543210", "B198F2DE3F4BAED1F0F1304C01275A8F", "45E139B7AEFF1F27AD5715AB315D0CEF")]
	[Arguments("0123456789ABCDEFFEDCBA9876543210", "45E139B7AEFF1F27AD5715AB315D0CEF", "8CC880BD1198F37BA2DD1420F9E8BB82")]
	[Arguments("0123456789ABCDEFFEDCBA9876543210", "8CC880BD1198F37BA2DD1420F9E8BB82", "F732CA4BA8F7B34D27D1CDE6B6655A23")]
	[Arguments("0123456789ABCDEFFEDCBA9876543210", "F732CA4BA8F7B34D27D1CDE6B6655A23", "C2F3548453E3B920A53700BEE77B48FB")]
	[Arguments("0123456789ABCDEFFEDCBA9876543210", "C2F3548453E3B920A53700BEE77B48FB", "213D9E481D9EF5BF77D5B44A5371947A")]
	[Arguments("0123456789ABCDEFFEDCBA9876543210", "213D9E481D9EF5BF77D5B44A5371947A", "88A66E0693CA43A5C4F6CD534B7B8EFE")]
	[Arguments("0123456789ABCDEFFEDCBA9876543210", "88A66E0693CA43A5C4F6CD534B7B8EFE", "B4287C4229325D88EDCE00190E16026E")]
	[Arguments("0123456789ABCDEFFEDCBA9876543210", "B4287C4229325D88EDCE00190E16026E", "87FF2CACE8E7E9BF3151EC47C35183C1")]
	[Arguments("0123456789ABCDEFFEDCBA9876543210", "87FF2CACE8E7E9BF3151EC47C35183C1", "595298C7C6FD271F0402F804C33D3F66")]
	public async Task StandardVectorEncryptsAndDecrypts(string keyHex, string plaintextHex, string ciphertextHex)
	{
		byte[] key = Convert.FromHexString(keyHex);
		byte[] plaintext = Convert.FromHexString(plaintextHex);
		byte[] ciphertext = Convert.FromHexString(ciphertextHex);

		await Assert.That(SM4Reference.Transform(key, plaintext)).IsEquivalentTo(ciphertext, CollectionOrdering.Matching);
		await Assert.That(SM4Reference.Transform(key, ciphertext, true)).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
		await TestUtils.TestBlock16<SM4Cipher>(key, plaintext, ciphertext);
	}

	[Test]
	[Arguments("0123456789ABCDEFFEDCBA9876543210")]
	[Arguments("00000000000000000000000000000000")]
	[Arguments("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")]
	public async Task BatchWidthsMatchSingleBlockReference(string keyHex)
	{
		byte[] key = Convert.FromHexString(keyHex);

		await TestUtils.TestNBlock16<SM4Cipher>(key);
	}

	[Test]
	[Arguments(0u)]
	[Arguments(uint.MaxValue)]
	[Arguments(0xA55A3CC3u)]
	public async Task ScalarSboxCoversEveryByteValueInEveryPosition(uint background)
	{
		uint[] expected = new uint[1024];
		uint[] actual = new uint[1024];

		for (int lane = 0; lane < 4; ++lane)
		{
			for (uint value = 0; value < 256; ++value)
			{
				uint input = background & ~(255u << lane * 8) | value << lane * 8;
				int index = lane * 256 + (int)value;
				expected[index] = SM4Reference.Substitute(input);
				actual[index] = SM4Utils.SubByte(input);
			}
		}

		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	[Arguments(1)]
	[Arguments(2)]
	[Arguments(3)]
	[Arguments(4)]
	[Arguments(5)]
	[Arguments(6)]
	[Arguments(7)]
	[Arguments(8)]
	[Arguments(9)]
	[Arguments(10)]
	[Arguments(11)]
	[Arguments(12)]
	[Arguments(13)]
	[Arguments(14)]
	[Arguments(15)]
	[Arguments(16)]
	[Arguments(17)]
	[Arguments(20)]
	[Arguments(21)]
	[Arguments(24)]
	[Arguments(25)]
	[Arguments(31)]
	[Arguments(32)]
	[Arguments(33)]
	public async Task RandomizedBlocksMatchIndependentReference(int blocks)
	{
		Random random = new(0x534D3400 + blocks);

		for (int sample = 0; sample < 4; ++sample)
		{
			byte[] key = new byte[16];
			byte[] plaintext = new byte[blocks * 16];
			random.NextBytes(key);
			random.NextBytes(plaintext);
			byte[] ciphertext = SM4Reference.Transform(key, plaintext);
			using SM4Cipher crypto = SM4Cipher.Create(key);

			byte[] source = TestUtils.CreateGuardedBuffer(1, plaintext.Length);
			plaintext.CopyTo(source, 1);
			byte[] destination = TestUtils.CreateGuardedBuffer(3, plaintext.Length);
			crypto.EncryptBlocks(source.AsSpan().Slice(1, plaintext.Length), destination.AsSpan().Slice(3));
			await TestUtils.AssertOutput(destination, 3, ciphertext);
			await TestUtils.AssertOutput(source, 1, plaintext);

			byte[] decrypted = TestUtils.CreateGuardedBuffer(7, plaintext.Length);
			crypto.DecryptBlocks(destination.AsSpan().Slice(3, ciphertext.Length), decrypted.AsSpan().Slice(7));
			await TestUtils.AssertOutput(decrypted, 7, plaintext);
			await TestUtils.AssertOutput(destination, 3, ciphertext);

			crypto.EncryptBlocks(source.AsSpan().Slice(1, plaintext.Length), source.AsSpan().Slice(1, plaintext.Length));
			await TestUtils.AssertOutput(source, 1, ciphertext);
			crypto.DecryptBlocks(source.AsSpan().Slice(1, plaintext.Length), source.AsSpan().Slice(1, plaintext.Length));
			await TestUtils.AssertOutput(source, 1, plaintext);
		}
	}

	[Test]
	[Arguments(1)]
	[Arguments(4)]
	[Arguments(8)]
	[Arguments(13)]
	public async Task EveryFirstRoundSboxInputMatchesIndependentReference(int batchWidth)
	{
		byte[] key = Convert.FromHexString("0123456789ABCDEFFEDCBA9876543210");
		using SM4Cipher crypto = SM4Cipher.Create(key);

		for (int firstValue = 0; firstValue < 256; firstValue += batchWidth)
		{
			int blocks = Math.Min(batchWidth, 256 - firstValue);
			byte[] source = new byte[blocks * 16];

			for (int block = 0; block < blocks; ++block)
			{
				source.AsSpan().Slice(block * 16, 16).Fill((byte)(firstValue + block));
			}

			byte[] actual = new byte[source.Length];
			crypto.EncryptBlocks(source, actual);
			await Assert.That(actual).IsEquivalentTo(SM4Reference.Transform(key, source), CollectionOrdering.Matching);
			crypto.DecryptBlocks(source, actual);
			await Assert.That(actual).IsEquivalentTo(SM4Reference.Transform(key, source, true), CollectionOrdering.Matching);
		}
	}
}
