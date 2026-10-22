using CryptoBase.Hashes.Sha2;
using System.Security.Cryptography;
using static CryptoBase.Tests.Hashes.HashAlgorithmTestUtils;

namespace CryptoBase.Tests.Hashes.Sha2;

public class Sha384Test
{
	[Test]
	[MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(Hash128BlockAndPaddingLengths))]
	public Task BlockBoundaries(int length)
	{
		return VerifyBoundary<Sha384Core>(length, SHA384.HashData);
	}

	[Test]
	[MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(Hash128IncrementalBatchCases))]
	public Task IncrementalBlockBatches(int length, int sourceOffset, int blockSize)
	{
		return VerifyIncrementalBlockBatch<Sha384Core>(length, sourceOffset, blockSize, SHA384.HashData);
	}

	[Test]
	[CombinedDataSources]
	public Task InputIsUnchanged([MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(InputIntegrityLengths))] int length, [Arguments(1, 7)] int offset)
	{
		return VerifyInputIsUnchanged<Sha384Core>(length, offset);
	}
}
