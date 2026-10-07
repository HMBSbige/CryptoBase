using CryptoBase.Hashes.MD5;
using static CryptoBase.Tests.Hashes.HashAlgorithmTestUtils;
using BclMD5 = System.Security.Cryptography.MD5;

namespace CryptoBase.Tests.Hashes.MD5;

public class MD5Test
{
	[Test]
	[MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(Hash64BlockAndPaddingLengths))]
	public Task BlockBoundaries(int length)
	{
		return VerifyBoundary<MD5HashAlgorithm>(length, BclMD5.HashData);
	}

	[Test]
	[MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(Hash64IncrementalBatchCases))]
	public Task IncrementalBlockBatches(int length, int sourceOffset, int blockSize)
	{
		return VerifyIncrementalBlockBatch<MD5HashAlgorithm>(length, sourceOffset, blockSize, BclMD5.HashData);
	}

	[Test]
	[CombinedDataSources]
	public Task InputIsUnchanged([MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(InputIntegrityLengths))] int length, [Arguments(1, 7)] int offset)
	{
		return VerifyInputIsUnchanged<MD5HashAlgorithm>(length, offset);
	}
}
