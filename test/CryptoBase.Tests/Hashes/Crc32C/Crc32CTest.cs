using CryptoBase.Hashes.Crc32C;
using static CryptoBase.Tests.Hashes.HashAlgorithmTestUtils;

namespace CryptoBase.Tests.Hashes.Crc32C;

public class Crc32CTest
{
	[Test]
	[Arguments("", "00000000")]
	[Arguments("123456789", "e3069283")]
	public Task KnownVectors(string value, string expected)
	{
		return VerifyHashVector<Crc32CHashAlgorithm>(value, expected, sizeof(uint));
	}

	[Test]
	[CombinedDataSources]
	public Task BlockBoundaries([MethodDataSource(typeof(CrcTestUtils), nameof(CrcTestUtils.BlockBoundaryLengths))] int length, [Arguments(0, 1, 3, 15)] int offset)
	{
		return CrcTestUtils.VerifyBlockBoundary<Crc32CHashAlgorithm>(length, offset, 0x82f63b78);
	}

	[Test]
	[MethodDataSource(typeof(CrcTestUtils), nameof(CrcTestUtils.SplitBoundaryCases))]
	public Task IncrementalBlockBatches(int length, int splitSize)
	{
		return CrcTestUtils.VerifySplitBoundary<Crc32CHashAlgorithm>(length, splitSize, 0x82f63b78);
	}

	[Test]
	[CombinedDataSources]
	public Task InputIsUnchanged([MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(InputIntegrityLengths))] int length, [Arguments(1, 7)] int offset)
	{
		return VerifyInputIsUnchanged<Crc32CHashAlgorithm>(length, offset);
	}
}
