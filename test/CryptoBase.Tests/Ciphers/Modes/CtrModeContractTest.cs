using CryptoBase.Abstractions.Ciphers;
using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Blocks.SM4;
using CryptoBase.Ciphers.Modes;
using CryptoBase.Ciphers.Modes.Ctr;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.Intrinsics;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Ciphers.Modes;

public class CtrModeContractTest
{
	[Test]
	[Arguments(15)]
	[Arguments(17)]
	[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Assertions finish before disposal.")]
	public async Task CounterMustBeExactlyOneBlock(int length)
	{
		byte[] key = CreateDeterministicSource(16);
		byte[] counter = new byte[length];
		using CtrMode128<AesCipher> cipher = CtrMode128<AesCipher>.Create(key, new byte[16]);

		await Assert.That(() => CtrMode128<AesCipher>.Create(key, counter).Dispose()).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("initialCounter");
		await Assert.That(() => cipher.Reset(counter)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("initialCounter");
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
			++value;
		}

		int processed = CtrBlocks<TCipher, CtrIncrementer32>.XorBlocks(cipher, ref counter, new byte[length], actual);
		await Assert.That(processed).IsEqualTo(length);
		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}
}
