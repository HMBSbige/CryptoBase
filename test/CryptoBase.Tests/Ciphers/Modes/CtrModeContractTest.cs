using CryptoBase.Abstractions.Ciphers;
using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Blocks.SM4;
using CryptoBase.Ciphers.Modes;
using System.Buffers.Binary;
using System.Runtime.Intrinsics;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Ciphers.Modes;

public class CtrModeContractTest
{
	[Test]
	[GenerateGenericTest(typeof(AesCipher))]
	[GenerateGenericTest(typeof(SM4Cipher))]
	[MatrixDataSource]
	public async Task InitialCounterMustBeExactlyOneBlock<TCipher>([Matrix(0, 15, 17)] int length) where TCipher : IBlockCipher<TCipher>
	{
		byte[] key = CreateDeterministicSource(16);
		byte[] initialCounter = new byte[length];
		await Assert.That(() => CtrMode128<TCipher>.Create(key, initialCounter).Dispose()).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("initialCounter");
	}

	[Test]
	[GenerateGenericTest(typeof(AesCipher))]
	[GenerateGenericTest(typeof(SM4Cipher))]
	[MatrixDataSource]
	public async Task CriticalBatchBoundariesMatchByteWiseProcessing<TCipher>([Matrix(1, 15, 16, 17, 31, 32, 33, 127, 128, 129, 255, 256, 257, 511, 512, 513, 2047, 2048, 2049, 4097)] int length) where TCipher : IBlockCipher<TCipher>
	{
		byte[] key = CreateDeterministicSource(16);
		byte[] counter = CreateDeterministicSource(16);

		using CtrMode128<TCipher> crypto = CtrMode128<TCipher>.Create(key, counter);
		using CtrMode128<TCipher> bulk = CtrMode128<TCipher>.Create(key, counter);
		await TestBlocks(crypto, bulk, length);
	}

	[Test]
	[GenerateGenericTest(typeof(AesCipher))]
	[GenerateGenericTest(typeof(SM4Cipher))]
	[MatrixDataSource]
	public async Task Ctr32BlocksWrapWithoutCarryingIntoNonce<TCipher>([Matrix(48, 64, 2048, 4096)] int length) where TCipher : IBlockCipher<TCipher>
	{
		byte[] initial = Convert.FromHexString("000102030405060708090A0BFFFFFFFE");
		Vector128<byte> counter = Vector128.LoadUnsafe(ref initial[0]);
		byte[] expected = new byte[length];
		byte[] actual = new byte[length];
		using TCipher cipher = TCipher.Create(CreateDeterministicSource(16));
		uint value = BinaryPrimitives.ReadUInt32BigEndian(initial.AsSpan(12));

		for (int offset = 0; offset < length; offset += 16)
		{
			BinaryPrimitives.WriteUInt32BigEndian(initial.AsSpan(12), value);
			cipher.EncryptBlock(initial, expected.AsSpan(offset, 16));
			value = unchecked(value + 1);
		}

		int processed = CtrBlocks<TCipher, CtrIncrementer32>.XorBlocks(cipher, ref counter, new byte[length], actual);
		await Assert.That(processed).IsEqualTo(length);
		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	[GenerateGenericTest(typeof(AesCipher))]
	[GenerateGenericTest(typeof(SM4Cipher))]
	[Arguments("000102030405060708090A0BFFFFFFFE", 48)]
	[Arguments("000102030405060708090A0BFFFFFFFE", 4096)]
	[Arguments("0000000000000000fffffffffffffffd", 4096)]
	[Arguments("fffffffffffffffffffffffffffffffd", 4096)]
	public async Task FullWidthCounterCarries<TCipher>(string initialHex, int length) where TCipher : IBlockCipher<TCipher>
	{
		byte[] key = CreateDeterministicSource(16);
		byte[] initial = Convert.FromHexString(initialHex);
		byte[] expected = new byte[length];
		byte[] actual = new byte[expected.Length];
		using TCipher cipher = TCipher.Create(key);
		using CtrMode128<TCipher> ctr = CtrMode128<TCipher>.Create(key, initial);
		UInt128 counter = BinaryPrimitives.ReadUInt128BigEndian(initial);
		byte[] block = new byte[16];

		for (int offset = 0; offset < expected.Length; offset += 16)
		{
			BinaryPrimitives.WriteUInt128BigEndian(block, counter);
			cipher.EncryptBlock(block, expected.AsSpan(offset, 16));
			counter = unchecked(counter + 1);
		}

		ctr.Xor(new byte[actual.Length], actual);
		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}
}
