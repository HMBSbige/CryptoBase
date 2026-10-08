using CryptoBase.Hashes.Blake2b;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hashes.Blake2b;

public class Blake2bKernelTest
{
	private const int BlockSize = 128;

	private static readonly int[] BlockCounts = [1, 2, 3, 5];

	private static readonly UInt128[] Counters =
	[
		BlockSize,
		1000 * BlockSize + 77,
		ulong.MaxValue - BlockSize + 1,
		ulong.MaxValue - 2 * BlockSize + 3,
		ulong.MaxValue,
		new(1, 0),
		new(0x8000_0000_0000_0000, 0x0123_4567_89AB_CDEF),
		UInt128.MaxValue - 2 * BlockSize + 1
	];

	private static readonly ulong[] FinalFlags = [0, ulong.MaxValue];

	[Test]
	public Task ScalarMatchesReference()
	{
		return VerifyKernel<Blake2bScalar>();
	}

	[Test]
	public Task Vector128MatchesReference()
	{
		if (!Blake2bVector128.IsSupported)
		{
			Skip.Test("SSE2 is required.");
		}

		return VerifyKernel<Blake2bVector128>();
	}

	[Test]
	public Task Vector256MatchesReference()
	{
		if (!Blake2bVector256.IsSupported)
		{
			Skip.Test("AVX2 is required.");
		}

		return VerifyKernel<Blake2bVector256>();
	}

	private static async Task VerifyKernel<TKernel>() where TKernel : IBlake2bKernel
	{
		foreach (int blockCount in BlockCounts)
		{
			byte[] buffer = CreateDeterministicSource(blockCount * BlockSize + 1);
			ReadOnlyMemory<byte> unalignedBlocks = buffer.AsMemory(1);

			foreach (UInt128 counter in Counters)
			{
				foreach (ulong finalFlag in FinalFlags)
				{
					ulong[] expected = CreateState(blockCount, counter, finalFlag);
					ulong[] actual = (ulong[])expected.Clone();

					for (int i = 0; i < blockCount; ++i)
					{
						Blake2bReference.Compress(expected, unalignedBlocks.Span.Slice(i * BlockSize, BlockSize), counter + (uint)(i * BlockSize), finalFlag);
					}

					TKernel.Compress(ref actual[0], unalignedBlocks.Span, counter, finalFlag);

					await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
				}
			}
		}
	}

	private static ulong[] CreateState(int blockCount, UInt128 counter, ulong finalFlag)
	{
		ulong[] state = new ulong[8];
		ulong seed = (ulong)counter ^ (ulong)(counter >> 64) * 0x9E3779B97F4A7C15UL ^ finalFlag ^ (ulong)blockCount;

		for (int i = 0; i < state.Length; ++i)
		{
			seed = seed * 6364136223846793005UL + 1442695040888963407UL;
			state[i] = seed;
		}

		return state;
	}
}
