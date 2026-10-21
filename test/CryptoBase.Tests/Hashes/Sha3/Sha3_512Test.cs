using CryptoBase.Hashes.Sha3;
using static CryptoBase.Tests.Hashes.HashAlgorithmTestUtils;

namespace CryptoBase.Tests.Hashes.Sha3;

public class Sha3_512Test
{
	private const int HashLength = 64;
	private const int Rate = 72;

	[Test]
	[MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(RateBlockAndPaddingLengths), Arguments = [Rate])]
	public Task BlockBoundaries(int length)
	{
		return VerifyBoundary<Sha3_512HashAlgorithm>(length, static source => Sha3TestUtils.Hash(HashLength, source));
	}

	[Test]
	[MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(HashIncrementalBatchCases), Arguments = [Rate])]
	public Task IncrementalBlockBatches(int length, int sourceOffset, int blockSize)
	{
		return VerifyIncrementalBlockBatch<Sha3_512HashAlgorithm>(length, sourceOffset, blockSize, static source => Sha3TestUtils.Hash(HashLength, source));
	}

	[Test]
	[CombinedDataSources]
	public Task InputIsUnchanged([MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(InputIntegrityLengths))] int length, [Arguments(1, 7)] int offset)
	{
		return VerifyInputIsUnchanged<Sha3_512HashAlgorithm>(length, offset);
	}
}
