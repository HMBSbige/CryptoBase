using CryptoBase.Abstractions.Hashes;
using CryptoBase.Hashes;
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

	// Every length of the final block takes its own path through the padding, alone and after a full block.
	[Test]
	public async Task EveryFinalBlockLengthMatchesReference()
	{
		byte[] source = CreateDeterministicSource(256);

		for (int length = 0; length <= source.Length; ++length)
		{
			ReadOnlySpan<byte> input = source.AsSpan(0, length);
			byte[] digest256 = new byte[32];
			byte[] digest512 = new byte[64];
			HashData<HashAlgorithm<Blake2b256Core>>(input, digest256);
			HashData<HashAlgorithm<Blake2b512Core>>(input, digest512);
			byte[] expected256 = Blake2bReference.Hash(input, 32);
			byte[] expected512 = Blake2bReference.Hash(input, 64);

			using (Assert.Multiple())
			{
				await Assert.That(digest256).IsEquivalentTo(expected256, CollectionOrdering.Matching).Because($"BLAKE2b-256 of {length} bytes");
				await Assert.That(digest512).IsEquivalentTo(expected512, CollectionOrdering.Matching).Because($"BLAKE2b-512 of {length} bytes");
			}
		}
	}

	private static int HashData<TAlgorithm>(ReadOnlySpan<byte> source, Span<byte> destination) where TAlgorithm : IOneShotHashAlgorithm
	{
		return TAlgorithm.HashData(source, destination);
	}
}
