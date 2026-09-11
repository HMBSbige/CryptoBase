using CryptoBase.Abstractions.SymmetricCryptos;
using static CryptoBase.Tests.SymmetricCryptos.StreamCryptos.SnuffleCryptoTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.SymmetricCryptos.StreamCryptos;

public class SnuffleCryptoBlocksTest
{
	[Test]
	[MatrixDataSource]
	public async Task CriticalBlockBoundariesMatchByteWiseProcessing([Matrix] SnuffleAlgorithm algorithm, [Matrix(0, 1, 63, 64, 65, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 2047, 2048, 2049)] int length)
	{
		using IStreamCrypto byteWise = Create(algorithm);
		using IStreamCrypto bulk = Create(algorithm);
		byte[] source = CreateDeterministicSource(length);
		byte[] expected = new byte[length];
		byte[] actual = new byte[length];

		for (int i = 0; i < source.Length; ++i)
		{
			byteWise.Update(source.AsSpan().Slice(i, 1), expected.AsSpan().Slice(i, 1));
		}

		bulk.Update(source, actual);

		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}
}
