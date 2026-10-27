using CryptoBase.Hashes.Blake2;
using static CryptoBase.Tests.Hashes.HashAlgorithmTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hashes.Blake2;

public class Blake2bHashDataTest
{
	[Test]
	[Arguments(127)]
	[Arguments(128)]
	[Arguments(129)]
	[Arguments(256)]
	public async Task SupportsOverlappingSourceAndDestination(int length)
	{
		byte[] source = CreateDeterministicSource(length);
		await VerifyOverlappingHashData<Blake2b256Core>(source, GetKnownDigest(source, Blake2b256Test.BoundaryVectors));
		await VerifyOverlappingHashData<Blake2b512Core>(source, GetKnownDigest(source, Blake2b512Test.BoundaryVectors));
	}
}
