using CryptoBase.Hashes.Sha1;
using System.Security.Cryptography;
using static CryptoBase.Tests.Hashes.HashAlgorithmTestUtils;

namespace CryptoBase.Tests.Hashes.Sha1;

public class Sha1Test
{
	[Test]
	[Arguments("", "da39a3ee5e6b4b0d3255bfef95601890afd80709")]
	[Arguments("abc", "a9993e364706816aba3e25717850c26c9cd0d89d")]
	[Arguments("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "a49b2446a02c645bf419f995b67091253a04a259")]
	public Task KnownVectors(string value, string expected)
	{
		return VerifyHashVector<Sha1HashAlgorithm>(value, expected, 20, 64);
	}

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
