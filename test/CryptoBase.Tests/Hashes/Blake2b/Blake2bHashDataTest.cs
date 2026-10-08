using CryptoBase.Abstractions.Hashes;
using CryptoBase.Hashes;
using CryptoBase.Hashes.Blake2b;
using static CryptoBase.Tests.Hashes.HashAlgorithmTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hashes.Blake2b;

public class Blake2bHashDataTest
{
	[Test]
	[Arguments(127)]
	[Arguments(128)]
	[Arguments(129)]
	[Arguments(256)]
	public async Task SupportsOverlappingSourceAndDestination(int length)
	{
		await VerifyOverlap<Blake2b256HashAlgorithm>(length, Blake2b256Test.BoundaryVectors);
		await VerifyOverlap<Blake2b512HashAlgorithm>(length, Blake2b512Test.BoundaryVectors);
	}

	private static async Task VerifyOverlap<THash>(int length, IEnumerable<(int Length, string ExpectedHex)> vectors) where THash : unmanaged, IHashCore<THash>
	{
		byte[] source = CreateDeterministicSource(length);
		byte[] expected = GetKnownDigest(source, vectors, typeof(THash).Name);

		foreach ((int sourceOffset, int destinationOffset) in new[] { (0, 0), (0, 17), (17, 0), (0, length - 1) })
		{
			byte[] buffer = new byte[Math.Max(sourceOffset + length, destinationOffset + THash.HashLength) + 1];
			PrepareDestination(buffer);
			source.CopyTo(buffer.AsSpan().Slice(sourceOffset));
			byte[] expectedBuffer = (byte[])buffer.Clone();
			expected.CopyTo(expectedBuffer.AsSpan().Slice(destinationOffset));

			int written = HashAlgorithm<THash>.HashData(buffer.AsSpan().Slice(sourceOffset, length), buffer.AsSpan().Slice(destinationOffset));

			await Assert.That(written).IsEqualTo(THash.HashLength);
			await Assert.That(buffer).IsEquivalentTo(expectedBuffer, CollectionOrdering.Matching);
		}
	}
}
