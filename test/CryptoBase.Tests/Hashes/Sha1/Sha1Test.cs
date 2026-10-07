using CryptoBase.Hashes.Sha1;
using System.Security.Cryptography;
using static CryptoBase.Tests.Hashes.HashAlgorithmTestUtils;

namespace CryptoBase.Tests.Hashes.Sha1;

public class Sha1Test
{
	[Test]
	[MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(Hash64BlockAndPaddingLengths))]
	public Task BlockBoundaries(int length)
	{
		return VerifyBoundary<Sha1HashAlgorithm>(length, SHA1.HashData);
	}

	[Test]
	[MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(Hash64IncrementalBatchCases))]
	public Task IncrementalBlockBatches(int length, int sourceOffset, int blockSize)
	{
		return VerifyIncrementalBlockBatch<Sha1HashAlgorithm>(length, sourceOffset, blockSize, SHA1.HashData);
	}

	[Test]
	[CombinedDataSources]
	public Task InputIsUnchanged([MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(InputIntegrityLengths))] int length, [Arguments(1, 7)] int offset)
	{
		return VerifyInputIsUnchanged<Sha1HashAlgorithm>(length, offset);
	}
}
