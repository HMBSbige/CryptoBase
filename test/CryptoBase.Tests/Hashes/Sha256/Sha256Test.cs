using CryptoBase.Hashes.Sha256;
using System.Security.Cryptography;
using static CryptoBase.Tests.Hashes.HashAlgorithmTestUtils;

namespace CryptoBase.Tests.Hashes.Sha256;

public class Sha256Test
{
	[Test]
	[MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(Hash64BlockAndPaddingLengths))]
	public Task BlockBoundaries(int length)
	{
		return VerifyBoundary<Sha256HashAlgorithm>(length, SHA256.HashData);
	}

	[Test]
	[MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(Hash64IncrementalBatchCases))]
	public Task IncrementalBlockBatches(int length, int sourceOffset, int blockSize)
	{
		return VerifyIncrementalBlockBatch<Sha256HashAlgorithm>(length, sourceOffset, blockSize, SHA256.HashData);
	}

	[Test]
	[CombinedDataSources]
	public Task InputIsUnchanged([MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(InputIntegrityLengths))] int length, [Arguments(1, 7)] int offset)
	{
		return VerifyInputIsUnchanged<Sha256HashAlgorithm>(length, offset);
	}
}
