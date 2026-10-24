using CryptoBase.Hashes.Sha3;
using CryptoBase.Internal;

namespace CryptoBase.Tests.Hashes.Sha3;

// Permute prefers the 512-bit row kernel where it runs at full width, so these tests call the lane-per-vector kernel directly wherever AVX-512VL is supported and check it against the reference.
public class KeccakP1600Lane128Test
{
	public static IEnumerable<int> Rates => [72, 104, 136, 144, 168];

	[Test]
	public async Task PermuteMatchesKeccakTeamValues()
	{
		SkipUnlessSupported();
		InlineArray25<ulong> state = default;

		KeccakP1600.PermuteLane128(ref state);
		await Assert.That(ToArray(state)).IsEquivalentTo(Sha3PermutationTest.ZeroStatePermutedOnce, CollectionOrdering.Matching);

		KeccakP1600.PermuteLane128(ref state);
		await Assert.That(ToArray(state)).IsEquivalentTo(Sha3PermutationTest.ZeroStatePermutedTwice, CollectionOrdering.Matching);
	}

	[Test]
	[Arguments(1)]
	[Arguments(2)]
	[Arguments(3)]
	public async Task PermuteMatchesReference(int seed)
	{
		SkipUnlessSupported();
		Random random = new(seed);
		ulong[] expected = new ulong[25];

		for (int i = 0; i < expected.Length; ++i)
		{
			expected[i] = (ulong)random.NextInt64(long.MinValue, long.MaxValue);
		}

		InlineArray25<ulong> state = default;
		expected.CopyTo(state);

		for (int i = 0; i < 4; ++i)
		{
			KeccakReference.Permute(expected);
			KeccakP1600.PermuteLane128(ref state);
			await Assert.That(ToArray(state)).IsEquivalentTo(expected, CollectionOrdering.Matching);
		}
	}

	[Test]
	[MethodDataSource(nameof(Rates))]
	public Task AbsorbMatchesScalar(int rate)
	{
		SkipUnlessSupported();
		return rate switch
		{
			72 => VerifyAbsorb<KeccakRate72>(),
			104 => VerifyAbsorb<KeccakRate104>(),
			136 => VerifyAbsorb<KeccakRate136>(),
			144 => VerifyAbsorb<KeccakRate144>(),
			168 => VerifyAbsorb<KeccakRate168>(),
			_ => throw new ArgumentOutOfRangeException(nameof(rate))
		};
	}

	[Test]
	[MethodDataSource(nameof(Rates))]
	public Task SqueezeMatchesScalar(int rate)
	{
		SkipUnlessSupported();
		return rate switch
		{
			72 => VerifySqueeze<KeccakRate72>(),
			104 => VerifySqueeze<KeccakRate104>(),
			136 => VerifySqueeze<KeccakRate136>(),
			144 => VerifySqueeze<KeccakRate144>(),
			168 => VerifySqueeze<KeccakRate168>(),
			_ => throw new ArgumentOutOfRangeException(nameof(rate))
		};
	}

	// Three whole blocks and a partial one, which the kernel must leave alone.
	private static async Task VerifyAbsorb<TRate>() where TRate : IKeccakRate
	{
		int rate = TRate.RateInBytes;
		byte[] source = new byte[3 * rate + 5];
		new Random(rate).NextBytes(source);
		InlineArray25<ulong> state = RandomState(rate);
		InlineArray25<ulong> expected = state;

		int absorbed = KeccakP1600.AbsorbLane128<TRate>(ref state, source);

		for (int block = 0; block < 3; ++block)
		{
			for (int lane = 0; lane < rate / sizeof(ulong); ++lane)
			{
				expected[lane] ^= BitConverter.ToUInt64(source, block * rate + lane * sizeof(ulong));
			}

			KeccakP1600.PermuteScalar(ref expected);
		}

		using (Assert.Multiple())
		{
			await Assert.That(absorbed).IsEqualTo(3 * rate);
			await Assert.That(ToArray(state)).IsEquivalentTo(ToArray(expected), CollectionOrdering.Matching);
		}
	}

	// Three whole blocks fit, and the bytes after them must stay as they were.
	private static async Task VerifySqueeze<TRate>() where TRate : IKeccakRate
	{
		int rate = TRate.RateInBytes;
		byte[] destination = new byte[3 * rate + 5];
		destination.AsSpan().Fill(0xA5);
		byte[] expectedOutput = (byte[])destination.Clone();
		InlineArray25<ulong> state = RandomState(rate);
		InlineArray25<ulong> expected = state;

		int written = KeccakP1600.SqueezeLane128<TRate>(ref state, destination);

		for (int block = 0; block < 3; ++block)
		{
			KeccakP1600.PermuteScalar(ref expected);

			for (int lane = 0; lane < rate / sizeof(ulong); ++lane)
			{
				BitConverter.TryWriteBytes(expectedOutput.AsSpan(block * rate + lane * sizeof(ulong)), expected[lane]);
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(written).IsEqualTo(3 * rate);
			await Assert.That(destination).IsEquivalentTo(expectedOutput, CollectionOrdering.Matching);
			await Assert.That(ToArray(state)).IsEquivalentTo(ToArray(expected), CollectionOrdering.Matching);
		}
	}

	private static void SkipUnlessSupported()
	{
		if (!KeccakP1600Lane128.IsSupported)
		{
			Skip.Test("AVX-512VL is not supported here.");
		}
	}

	private static InlineArray25<ulong> RandomState(int seed)
	{
		Random random = new(seed);
		InlineArray25<ulong> state = default;

		for (int i = 0; i < 25; ++i)
		{
			state[i] = (ulong)random.NextInt64(long.MinValue, long.MaxValue);
		}

		return state;
	}

	private static ulong[] ToArray(in InlineArray25<ulong> state)
	{
		return ((ReadOnlySpan<ulong>)state).ToArray();
	}
}
