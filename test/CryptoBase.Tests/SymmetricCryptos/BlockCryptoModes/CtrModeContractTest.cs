using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.Abstractions.Vectors;
using CryptoBase.SymmetricCryptos.BlockCryptoModes;
using CryptoBase.SymmetricCryptos.BlockCryptos.Aes;
using CryptoBase.SymmetricCryptos.BlockCryptos.SM4;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.SymmetricCryptos.BlockCryptoModes;

public class CtrModeContractTest
{
	private static readonly int[] AesLengths = [127, 128, 129, 511, 512, 513];
	private static readonly int[] SM4Lengths = [127, 128, 129, 255, 256, 257, 511, 512, 513];

	public static IEnumerable<(CtrAlgorithm, int)> CriticalBoundaryCases()
	{
		foreach (CtrAlgorithm algorithm in (CtrAlgorithm[])[CtrAlgorithm.Aes128, CtrAlgorithm.Aes32])
		{
			foreach (int length in AesLengths)
			{
				yield return (algorithm, length);
			}
		}

		foreach (CtrAlgorithm algorithm in (CtrAlgorithm[])[CtrAlgorithm.SM4128, CtrAlgorithm.SM432])
		{
			foreach (int length in SM4Lengths)
			{
				yield return (algorithm, length);
			}
		}
	}

	[Test]
	[MethodDataSource(nameof(CriticalBoundaryCases))]
	public async Task CriticalBatchBoundariesMatchByteWiseProcessing(CtrAlgorithm algorithm, int length)
	{
		using IStreamCrypto crypto = Create(algorithm);
		await TestBlocks(crypto, length);
	}

	[Test]
	[Arguments(BlockCipher.Aes)]
	[Arguments(BlockCipher.SM4)]
	public async Task CounterWidthControlsCarryAt32BitWrap(BlockCipher cipher)
	{
		switch (cipher)
		{
			case BlockCipher.Aes:
				await VerifyCounterWrap<AesCipher>(CreateDeterministicSource(16));
				break;
			case BlockCipher.SM4:
				await VerifyCounterWrap<SM4Cipher>(CreateDeterministicSource(16));
				break;
			default:
				throw new ArgumentOutOfRangeException(nameof(cipher));
		}
	}

	public enum CtrAlgorithm
	{
		Aes128,
		Aes32,
		SM4128,
		SM432
	}

	public enum BlockCipher
	{
		Aes,
		SM4
	}

	private static IStreamCrypto Create(CtrAlgorithm algorithm)
	{
		byte[] key = CreateDeterministicSource(16);
		byte[] counter = CreateDeterministicSource(16);

		return algorithm switch
		{
			CtrAlgorithm.Aes128 => new CtrMode128<AesCipher>(AesCipher.Create(key), counter),
			CtrAlgorithm.Aes32 => new CtrMode128Ctr32<AesCipher>(AesCipher.Create(key), counter),
			CtrAlgorithm.SM4128 => new CtrMode128<SM4Cipher>(SM4Cipher.Create(key), counter),
			CtrAlgorithm.SM432 => new CtrMode128Ctr32<SM4Cipher>(SM4Cipher.Create(key), counter),
			_ => throw new ArgumentOutOfRangeException(nameof(algorithm))
		};
	}

	private static async Task VerifyCounterWrap<TCipher>(byte[] key) where TCipher : IBlock16Cipher<TCipher>
	{
		byte[] initialCounter = Convert.FromHexString("000102030405060708090A0BFFFFFFFE");
		byte[] zeros = new byte[48];
		byte[] actual128 = new byte[zeros.Length];
		byte[] actual32 = new byte[zeros.Length];
		using CtrMode128<TCipher> ctr128 = new(TCipher.Create(key), initialCounter);
		using CtrMode128Ctr32<TCipher> ctr32 = new(TCipher.Create(key), initialCounter);

		ctr128.Update(zeros, actual128);
		ctr32.Update(zeros, actual32);

		using TCipher reference = TCipher.Create(key);
		byte[] expected128 = EncryptCounters(reference, "000102030405060708090A0BFFFFFFFE", "000102030405060708090A0BFFFFFFFF", "000102030405060708090A0C00000000");
		byte[] expected32 = EncryptCounters(reference, "000102030405060708090A0BFFFFFFFE", "000102030405060708090A0BFFFFFFFF", "000102030405060708090A0B00000000");

		await Assert.That(actual128).IsEquivalentTo(expected128, CollectionOrdering.Matching);
		await Assert.That(actual32).IsEquivalentTo(expected32, CollectionOrdering.Matching);
		await Assert.That(actual128.AsSpan(32).AsVectorBuffer16()).IsNotEqualTo(actual32.AsSpan(32).AsVectorBuffer16());
	}

	private static byte[] EncryptCounters<TCipher>(TCipher cipher, params string[] counterHexes) where TCipher : IBlock16Cipher<TCipher>
	{
		byte[] result = new byte[counterHexes.Length * 16];

		for (int i = 0; i < counterHexes.Length; ++i)
		{
			VectorBuffer16 block = cipher.Encrypt(Convert.FromHexString(counterHexes[i]).AsVectorBuffer16());
			block.AsSpan().CopyTo(result.AsSpan(i * 16));
		}

		return result;
	}
}
