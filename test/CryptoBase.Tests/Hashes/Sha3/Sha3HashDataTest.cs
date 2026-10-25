using CryptoBase.Hashes.Sha3;
using static CryptoBase.Tests.Hashes.HashAlgorithmTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hashes.Sha3;

public class Sha3HashDataTest
{
	// Inputs below the rate take one block, which one-shot hashing computes without a sponge; from the rate on, the sponge takes over.
	public static IEnumerable<(int, int)> OverlapCases()
	{
		foreach (int hashLength in (int[])[28, 32, 48, 64])
		{
			int rate = KeccakReference.Sha3Rate(hashLength);

			foreach (int length in (int[])[1, 20, 32, 64, rate - 1, rate, rate + 1])
			{
				yield return (hashLength, length);
			}
		}
	}

	[Test]
	[MethodDataSource(nameof(OverlapCases))]
	public Task SupportsOverlappingSourceAndDestination(int hashLength, int length)
	{
		byte[] source = CreateDeterministicSource(length);
		byte[] expected = KeccakReference.Sha3(source, hashLength);

		return hashLength switch
		{
			28 => VerifyOverlappingHashData<Sha3_224Core>(source, expected),
			32 => VerifyOverlappingHashData<Sha3_256Core>(source, expected),
			48 => VerifyOverlappingHashData<Sha3_384Core>(source, expected),
			64 => VerifyOverlappingHashData<Sha3_512Core>(source, expected),
			_ => throw new ArgumentOutOfRangeException(nameof(hashLength))
		};
	}
}
