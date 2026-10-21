using CryptoBase.Hashes.Sha3;
using static CryptoBase.Tests.Hashes.HashAlgorithmTestUtils;

namespace CryptoBase.Tests.Hashes.Sha3;

public class Sha3_256Test
{
	private const int HashLength = 32;
	private const int Rate = 136;

	[Test]
	[MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(RateBlockAndPaddingLengths), Arguments = [Rate])]
	public Task BlockBoundaries(int length)
	{
		return VerifyBoundary<Sha3_256HashAlgorithm>(length, static source => Sha3TestUtils.Hash(HashLength, source));
	}

	[Test]
	[MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(HashIncrementalBatchCases), Arguments = [Rate])]
	public Task IncrementalBlockBatches(int length, int sourceOffset, int blockSize)
	{
		return VerifyIncrementalBlockBatch<Sha3_256HashAlgorithm>(length, sourceOffset, blockSize, static source => Sha3TestUtils.Hash(HashLength, source));
	}

	[Test]
	[CombinedDataSources]
	public Task InputIsUnchanged([MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(InputIntegrityLengths))] int length, [Arguments(1, 7)] int offset)
	{
		return VerifyInputIsUnchanged<Sha3_256HashAlgorithm>(length, offset);
	}
}
