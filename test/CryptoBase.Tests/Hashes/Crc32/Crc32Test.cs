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
		return VerifyHashVector<Crc32Core>(value, expected, sizeof(uint));
	}

	[Test]
	[CombinedDataSources]
	public Task BlockBoundaries([MethodDataSource(typeof(CrcTestUtils), nameof(CrcTestUtils.BlockBoundaryLengths))] int length, [Arguments(0, 1, 3, 15)] int offset)
	{
		return CrcTestUtils.VerifyBlockBoundary<Crc32Core>(length, offset, 0xedb88320);
	}

	[Test]
	[MethodDataSource(typeof(CrcTestUtils), nameof(CrcTestUtils.SplitBoundaryCases))]
	public Task IncrementalBlockBatches(int length, int splitSize)
	{
		return CrcTestUtils.VerifySplitBoundary<Crc32Core>(length, splitSize, 0xedb88320);
	}

	[Test]
	[CombinedDataSources]
	public Task InputIsUnchanged([MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(InputIntegrityLengths))] int length, [Arguments(1, 7)] int offset)
	{
		return VerifyInputIsUnchanged<Crc32Core>(length, offset);
	}
}
