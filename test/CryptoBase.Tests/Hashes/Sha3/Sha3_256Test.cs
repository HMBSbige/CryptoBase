using CryptoBase.Hashes.Sha3;
using static CryptoBase.Tests.Hashes.HashAlgorithmTestUtils;

namespace CryptoBase.Tests.Hashes.Sha3;

public class Sha3_256Test
{
	private const int HashLength = 32;
	private const int Rate = 136;

	// The empty message: FIPS 202 example values, https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-256_Msg0.pdf
	// "abc" and the 448-bit message: https://www.di-mgt.com.au/sha_testvectors.html
	[Test]
	[Arguments("", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")]
	[Arguments("abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")]
	[Arguments("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376")]
	public Task KnownVectors(string value, string expected)
	{
		return VerifyHashVector<Sha3_256HashAlgorithm>(value, expected, HashLength, Rate);
	}

	// FIPS 202 example values for 200 bytes of 0xA3, https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-256_1600.pdf
	[Test]
	public Task Nist1600BitMessage()
	{
		byte[] source = new byte[200];
		source.AsSpan().Fill(0xA3);
		return VerifyBoundary<Sha3_256HashAlgorithm>(source, Convert.FromHexString("79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787"));
	}

	[Test]
	[MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(RateBlockAndPaddingLengths), Arguments = [Rate])]
	public Task BlockBoundaries(int length)
	{
		return VerifyBoundary<Sha3_256HashAlgorithm>(length, static source => Sha3TestUtils.Hash(HashLength, source));
	}

	[Test]
	[MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(HashIncrementalBatchCases), Arguments = [Rate])]
	public Task IncrementalBlockBatches(int length, int sourceOffset, int blockSize)
	{
		return VerifyIncrementalBlockBatch<Sha3_256HashAlgorithm>(length, sourceOffset, blockSize, static source => Sha3TestUtils.Hash(HashLength, source));
	}

	[Test]
	[CombinedDataSources]
	public Task InputIsUnchanged([MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(InputIntegrityLengths))] int length, [Arguments(1, 7)] int offset)
	{
		return VerifyInputIsUnchanged<Sha3_256HashAlgorithm>(length, offset);
	}
}
