using CryptoBase.Hashes.MD5;
using static CryptoBase.Tests.Hashes.HashAlgorithmTestUtils;
using BclMD5 = System.Security.Cryptography.MD5;

namespace CryptoBase.Tests.Hashes.MD5;

public class MD5Test
{
	/// <summary>
	/// RFC 1321, Appendix A.5.
	/// </summary>
	[Test]
	[Arguments("", "d41d8cd98f00b204e9800998ecf8427e")]
	[Arguments("abc", "900150983cd24fb0d6963f7d28e17f72")]
	[Arguments("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "57edf4a22be3c955ac49da2e2107b67a")]
	public Task KnownVectors(string value, string expected)
	{
		return VerifyHashVector<MD5HashAlgorithm>(value, expected, 16, 64);
	}

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
