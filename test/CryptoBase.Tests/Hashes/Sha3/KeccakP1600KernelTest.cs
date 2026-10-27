using CryptoBase.Hashes.Sha3;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hashes.Sha3;

public class KeccakP1600KernelTest
{
	private const int LaneCount = 25;

	// Words past the interleaved state that a kernel must leave alone.
	private const int GuardWords = 3;

	private const ulong GuardWord = 0xA5A5_A5A5_A5A5_A5A5UL;

	[Test]
	public async Task EveryKernelIsListed()
	{
		await Assert.That(KeccakP1600KernelCase.All().Select(static kernel => kernel.KernelType)).IsEquivalentTo(ImplementationsOf(typeof(IKeccakP1600Kernel)));
	}

	[Test]
	[MethodDataSource(typeof(KeccakP1600KernelCase), nameof(KeccakP1600KernelCase.All))]
	public async Task PermuteMatchesKeccakTeamValues(KeccakP1600KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		ulong[] state = CreateGuardedState(kernel.Lanes);

		kernel.Permute(state);
		await AssertStates(state, Enumerable.Repeat(Sha3PermutationTest.ZeroStatePermutedOnce, kernel.Lanes).ToArray());

		kernel.Permute(state);
		await AssertStates(state, Enumerable.Repeat(Sha3PermutationTest.ZeroStatePermutedTwice, kernel.Lanes).ToArray());
	}

	// Distinct random states catch lanes of one state leaking into another, which identical states would hide.
	[Test]
	[MethodDataSource(typeof(KeccakP1600KernelCase), nameof(KeccakP1600KernelCase.All))]
	public async Task PermuteMatchesReference(KeccakP1600KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		Random random = new(kernel.Lanes);
		ulong[][] expected = new ulong[kernel.Lanes][];
		ulong[] state = CreateGuardedState(kernel.Lanes);

		for (int j = 0; j < kernel.Lanes; ++j)
		{
			expected[j] = new ulong[LaneCount];

			for (int i = 0; i < LaneCount; ++i)
			{
				expected[j][i] = (ulong)random.NextInt64(long.MinValue, long.MaxValue);
				state[i * kernel.Lanes + j] = expected[j][i];
			}
		}

		for (int iteration = 0; iteration < 4; ++iteration)
		{
			foreach (ulong[] lanes in expected)
			{
				KeccakReference.Permute(lanes);
			}

			kernel.Permute(state);
			await AssertStates(state, expected);
		}
	}

	private static ulong[] CreateGuardedState(int lanes)
	{
		ulong[] state = new ulong[LaneCount * lanes + GuardWords];
		state.AsSpan(LaneCount * lanes).Fill(GuardWord);
		return state;
	}

	private static async Task AssertStates(ulong[] state, ulong[][] expected)
	{
		int lanes = expected.Length;

		using (Assert.Multiple())
		{
			for (int j = 0; j < lanes; ++j)
			{
				ulong[] actual = Enumerable.Range(0, LaneCount).Select(i => state[i * lanes + j]).ToArray();
				await Assert.That(actual).IsEquivalentTo(expected[j], CollectionOrdering.Matching).Because($"state {j} of {lanes}");
			}

			await Assert.That(state.AsMemory(LaneCount * lanes)).All(static word => word is GuardWord);
		}
	}
}
