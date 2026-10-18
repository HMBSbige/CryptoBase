using CryptoBase.Hashes.Sha3;
using static CryptoBase.Tests.Hashes.HashAlgorithmTestUtils;

namespace CryptoBase.Tests.Hashes.Sha3;

public class Sha3_224Test
{
	private const int HashLength = 28;
	private const int Rate = 144;

	// The empty message: FIPS 202 example values, https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-224_Msg0.pdf
	// "abc" and the 448-bit message: https://www.di-mgt.com.au/sha_testvectors.html
	[Test]
	[Arguments("", "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7")]
	[Arguments("abc", "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf")]
	[Arguments("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33")]
	public Task KnownVectors(string value, string expected)
	{
		return VerifyHashVector<Sha3_224HashAlgorithm>(value, expected, HashLength, Rate);
	}

	// FIPS 202 example values for 200 bytes of 0xA3, https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-224_1600.pdf
	[Test]
	public Task Nist1600BitMessage()
	{
		byte[] source = new byte[200];
		source.AsSpan().Fill(0xA3);
		return VerifyBoundary<Sha3_224HashAlgorithm>(source, Convert.FromHexString("9376816aba503f72f96ce7eb65ac095deee3be4bf9bbc2a1cb7e11e0"));
	}

	[Test]
	[MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(RateBlockAndPaddingLengths), Arguments = [Rate])]
	public Task BlockBoundaries(int length)
	{
		return VerifyBoundary<Sha3_224HashAlgorithm>(length, static source => Sha3TestUtils.Hash(HashLength, source));
	}

	[Test]
	[MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(HashIncrementalBatchCases), Arguments = [Rate])]
	public Task IncrementalBlockBatches(int length, int sourceOffset, int blockSize)
	{
		return VerifyIncrementalBlockBatch<Sha3_224HashAlgorithm>(length, sourceOffset, blockSize, static source => Sha3TestUtils.Hash(HashLength, source));
	}

	[Test]
	[CombinedDataSources]
	public Task InputIsUnchanged([MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(InputIntegrityLengths))] int length, [Arguments(1, 7)] int offset)
	{
		return VerifyInputIsUnchanged<Sha3_224HashAlgorithm>(length, offset);
	}
}
