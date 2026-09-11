using CryptoBase.Hashes.Crc32;
using static CryptoBase.Tests.Hashes.HashAlgorithmTestUtils;

namespace CryptoBase.Tests.Hashes.Crc32;

public class Crc32Test
{
	[Test]
	[Arguments("", "00000000")]
	[Arguments("123456789", "cbf43926")]
	public Task KnownVectors(string value, string expected)
	{
		return VerifyHashVector<Crc32HashAlgorithm>(value, expected, sizeof(uint));
	}

	[Test]
	[CombinedDataSources]
	public Task BlockBoundaries([MethodDataSource(typeof(CrcTestUtils), nameof(CrcTestUtils.BlockBoundaryLengths))] int length, [Arguments(0, 1, 3, 15)] int offset)
	{
		return CrcTestUtils.VerifyBlockBoundary<Crc32HashAlgorithm>(length, offset, 0xedb88320);
	}

	[Test]
	[CombinedDataSources]
	public Task IncrementalBlockBatches([MethodDataSource(typeof(CrcTestUtils), nameof(CrcTestUtils.SplitBoundaryLengths))] int length, [MethodDataSource(typeof(CrcTestUtils), nameof(CrcTestUtils.SplitSizes))] int splitSize)
	{
		return CrcTestUtils.VerifySplitBoundary<Crc32HashAlgorithm>(length, splitSize, 0xedb88320);
	}

	[Test]
	[CombinedDataSources]
	public Task InputIsUnchanged([MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(InputIntegrityLengths))] int length, [Arguments(1, 7)] int offset)
	{
		return VerifyInputIsUnchanged<Crc32HashAlgorithm>(length, offset);
	}
}
