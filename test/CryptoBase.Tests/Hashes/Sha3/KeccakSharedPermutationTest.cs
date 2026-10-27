using CryptoBase.Hashes.Sha3;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hashes.Sha3;

// Sponges sharing permutations, with a sponge of another rate or in the free lanes of a batch, against KeccakSponge alone.
public class KeccakSharedPermutationTest
{
	public static IEnumerable<int> Rates => [72, 104, 136, 144, 168];

	public static IEnumerable<byte> DomainSeparators => [KeccakReference.Sha3DomainSeparator, KeccakReference.ShakeDomainSeparator];

	// Zero lets ResetWithGuests choose; the others force one kernel, whose lanes past the streams are free.
	public static IEnumerable<int> Lanes => [0, 1, 2, 4, 8];

	private interface IRatePairCase
	{
		Task Run<TFirst, TSecond>() where TFirst : IKeccakRate where TSecond : IKeccakRate;
	}

	// A prefix first, as J takes z, so that the first block starts mid-block; the input ends before, at and after a block boundary.
	[Test]
	[CombinedDataSources]
	public Task BlockwiseAbsorptionMatchesAbsorb([MethodDataSource(nameof(Rates))] int rate, [MethodDataSource(nameof(DomainSeparators))] byte domainSeparator)
	{
		return Run(rate, rate, new BlockwiseAbsorptionCase(domainSeparator));
	}

	[Test]
	[CombinedDataSources]
	public Task PairedPermutationsMatchSeparateSponges([MethodDataSource(nameof(Rates))] int firstRate, [MethodDataSource(nameof(Rates))] int secondRate)
	{
		return Run(firstRate, secondRate, new PairCase());
	}

	[Test]
	[CombinedDataSources]
	public Task GuestsMatchSeparateSponges([MethodDataSource(nameof(Rates))] int rate, [MethodDataSource(nameof(Rates))] int guestRate, [MethodDataSource(nameof(Lanes))] int lanes)
	{
		if (lanes is not 0)
		{
			SkipUnlessSupported(KeccakP1600KernelCase.For(lanes));
		}

		return Run(rate, guestRate, new GuestCase(lanes));
	}

	// Guests only take lanes the streams leave free, so a batch takes as many streams as it would without them.
	[Test]
	public async Task ResetWithGuestsTakesAsManyStreamsAsReset()
	{
		using (Assert.Multiple())
		{
			for (int streams = 1; streams <= 20; ++streams)
			{
				KeccakBatchSponge<KeccakRate168> alone = default;
				alone.Reset(streams, KeccakP1600Batch.ChooseLanes(streams));

				for (int guests = 0; guests <= 8; ++guests)
				{
					KeccakBatchSponge<KeccakRate168> batch = default;
					batch.ResetWithGuests(streams, guests);

					await Assert.That(batch.Count).IsEqualTo(alone.Count).Because($"{streams} streams with {guests} guests");
					await Assert.That(batch.FreeLanes).IsGreaterThanOrEqualTo(Math.Min(guests, KeccakP1600Batch.MaxLanes - batch.Count)).Because($"{streams} streams with {guests} guests");
				}
			}
		}
	}

	private static Task Run<TCase>(int first, int second, TCase testCase) where TCase : IRatePairCase
	{
		return first switch
		{
			72 => Run<KeccakRate72, TCase>(second, testCase),
			104 => Run<KeccakRate104, TCase>(second, testCase),
			136 => Run<KeccakRate136, TCase>(second, testCase),
			144 => Run<KeccakRate144, TCase>(second, testCase),
			168 => Run<KeccakRate168, TCase>(second, testCase),
			_ => throw new ArgumentOutOfRangeException(nameof(first))
		};
	}

	private static Task Run<TFirst, TCase>(int second, TCase testCase) where TFirst : IKeccakRate where TCase : IRatePairCase
	{
		return second switch
		{
			72 => testCase.Run<TFirst, KeccakRate72>(),
			104 => testCase.Run<TFirst, KeccakRate104>(),
			136 => testCase.Run<TFirst, KeccakRate136>(),
			144 => testCase.Run<TFirst, KeccakRate144>(),
			168 => testCase.Run<TFirst, KeccakRate168>(),
			_ => throw new ArgumentOutOfRangeException(nameof(second))
		};
	}

	// Takes every permutation offered: the next block of the message while absorbing, else a whole block of output.
	private static void Step<TRate>(ref KeccakSponge<TRate> sponge, ReadOnlySpan<byte> message, ref int absorbed, Span<byte> output, ref int squeezed, byte domainSeparator) where TRate : IKeccakRate
	{
		if (sponge.IsSqueezing)
		{
			sponge.Squeeze(output.Slice(squeezed, TRate.RateInBytes));
			squeezed += TRate.RateInBytes;
		}
		else
		{
			absorbed += sponge.AbsorbBlock(message.Slice(absorbed), domainSeparator);
		}
	}

	private static void Finish<TRate>(ref KeccakSponge<TRate> sponge, ReadOnlySpan<byte> message, int absorbed, Span<byte> output, int squeezed, byte domainSeparator) where TRate : IKeccakRate
	{
		if (!sponge.IsSqueezing)
		{
			sponge.Absorb(message.Slice(absorbed));
			sponge.Pad(domainSeparator);
		}

		sponge.Squeeze(output.Slice(squeezed));
	}

	private readonly struct BlockwiseAbsorptionCase(byte domainSeparator) : IRatePairCase
	{
		public async Task Run<TRate, TUnused>() where TRate : IKeccakRate where TUnused : IKeccakRate
		{
			int rate = TRate.RateInBytes;
			int outputLength = 2 * rate + 3;

			foreach (int prefixLength in (int[])[0, 1, 32, rate - 1])
			{
				foreach (int messageLength in (int[])[0, 1, rate - prefixLength - 1, rate - prefixLength, rate - prefixLength + 1, 2 * rate, 3 * rate + 5])
				{
					byte[] input = CreateDeterministicSource(prefixLength + messageLength);
					byte[] expected = Sha3TestUtils.AbsorbPadAndSqueeze<TRate>(input, domainSeparator, outputLength);
					int permutations = input.Length / rate + 1;

					for (int steps = 0; steps <= permutations; ++steps)
					{
						byte[] actual = new byte[outputLength];
						(int taken, bool awaited) = AbsorbInSteps<TRate>(input, prefixLength, steps, domainSeparator, actual);

						using (Assert.Multiple())
						{
							await Assert.That(awaited).IsTrue();
							await Assert.That(taken).IsEqualTo(Math.Min(steps, permutations)).Because($"permutations of a {prefixLength} + {messageLength}-byte input");
							await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching).Because($"{prefixLength} + {messageLength}-byte input, {steps} steps");
						}
					}
				}
			}
		}

		private static (int Taken, bool Awaited) AbsorbInSteps<TRate>(byte[] input, int prefixLength, int steps, byte domainSeparator, byte[] output) where TRate : IKeccakRate
		{
			KeccakSponge<TRate> sponge = default;
			sponge.Absorb(input.AsSpan(0, prefixLength));
			ReadOnlySpan<byte> message = input.AsSpan(prefixLength);
			int absorbed = 0;
			int taken = 0;
			bool awaited = true;

			for (; taken < steps && !sponge.IsSqueezing; ++taken)
			{
				absorbed += sponge.AbsorbBlock(message.Slice(absorbed), domainSeparator);
				awaited &= sponge.AwaitsPermutation;
				sponge.Permute();
			}

			Finish(ref sponge, message, absorbed, output, 0, domainSeparator);
			return (taken, awaited);
		}
	}

	// Two messages of different lengths, so that one sponge goes on squeezing blocks beside the other's absorption.
	private readonly struct PairCase : IRatePairCase
	{
		public async Task Run<TFirst, TSecond>() where TFirst : IKeccakRate where TSecond : IKeccakRate
		{
			int outputLength = 3 * Math.Max(TFirst.RateInBytes, TSecond.RateInBytes) + 5;
			(int, int, int)[] cases = [(64, 1120, 1), (0, 33, 2), (500, 34, 4), (2 * TFirst.RateInBytes, 2 * TSecond.RateInBytes - 1, 3)];

			foreach ((int firstLength, int secondLength, int pairs) in cases)
			{
				byte[] firstMessage = CreateDeterministicSource(firstLength);
				byte[] secondMessage = CreateDeterministicSource(secondLength + 1).AsSpan(1).ToArray();
				(byte[] firstOutput, byte[] secondOutput) = Pair<TFirst, TSecond>(firstMessage, secondMessage, pairs, outputLength);

				using (Assert.Multiple())
				{
					await Assert.That(firstOutput).IsEquivalentTo(Sha3TestUtils.AbsorbPadAndSqueeze<TFirst>(firstMessage, KeccakReference.Sha3DomainSeparator, outputLength), CollectionOrdering.Matching).Because($"{firstLength}-byte message beside {secondLength} bytes, {pairs} pairs");
					await Assert.That(secondOutput).IsEquivalentTo(Sha3TestUtils.AbsorbPadAndSqueeze<TSecond>(secondMessage, KeccakReference.ShakeDomainSeparator, outputLength), CollectionOrdering.Matching).Because($"{secondLength}-byte message beside {firstLength} bytes, {pairs} pairs");
				}
			}
		}

		private static (byte[] First, byte[] Second) Pair<TFirst, TSecond>(byte[] firstMessage, byte[] secondMessage, int pairs, int outputLength) where TFirst : IKeccakRate where TSecond : IKeccakRate
		{
			byte[] firstOutput = new byte[outputLength];
			byte[] secondOutput = new byte[outputLength];
			KeccakSponge<TFirst> first = default;
			KeccakSponge<TSecond> second = default;
			int firstAbsorbed = 0, secondAbsorbed = 0, firstSqueezed = 0, secondSqueezed = 0;

			for (int i = 0; i < pairs; ++i)
			{
				Step(ref first, firstMessage, ref firstAbsorbed, firstOutput, ref firstSqueezed, KeccakReference.Sha3DomainSeparator);
				Step(ref second, secondMessage, ref secondAbsorbed, secondOutput, ref secondSqueezed, KeccakReference.ShakeDomainSeparator);
				KeccakP1600Batch.Permute(ref first, ref second);
			}

			Finish(ref first, firstMessage, firstAbsorbed, firstOutput, firstSqueezed, KeccakReference.Sha3DomainSeparator);
			Finish(ref second, secondMessage, secondAbsorbed, secondOutput, secondSqueezed, KeccakReference.ShakeDomainSeparator);
			return (firstOutput, secondOutput);
		}
	}

	// Guests of their own rate and lengths, at times more than the free lanes. Some batch inputs reach past a block, so that Absorb permutes on its own first.
	private readonly struct GuestCase(int lanes) : IRatePairCase
	{
		private const int Blocks = 3;

		public async Task Run<TRate, TGuest>() where TRate : IKeccakRate where TGuest : IKeccakRate
		{
			int rate = TRate.RateInBytes;
			int outputLength = Blocks * rate + 9;
			int guestOutputLength = (Blocks + 1) * TGuest.RateInBytes + 1;
			(int, int, int)[] cases = [(1, 1, 34), (2, 3, 33), (3, 1, rate + 2), (5, 4, 0), (7, 2, 34), (6, 9, 66)];

			foreach ((int streams, int guestCount, int inputLength) in cases)
			{
				int groupLanes = lanes is 0 ? KeccakP1600Batch.ChooseLanes(streams + guestCount) : lanes;
				int count = Math.Min(streams, groupLanes);
				byte[] inputs = CreateDeterministicSource(count * inputLength);
				byte[][] guestMessages = [.. Enumerable.Range(0, guestCount).Select(static i => CreateDeterministicSource(i * 151 % 400))];
				(byte[] outputs, byte[][] guestOutputs, int actualCount) = Host<TRate, TGuest>(streams, inputs, guestMessages, outputLength, guestOutputLength);

				using (Assert.Multiple())
				{
					await Assert.That(actualCount).IsEqualTo(count);

					for (int j = 0; j < count; ++j)
					{
						byte[] expected = Sha3TestUtils.AbsorbPadAndSqueeze<TRate>(inputs.AsSpan(j * inputLength, inputLength), KeccakReference.ShakeDomainSeparator, outputLength);
						await Assert.That(outputs.AsSpan(j * outputLength, outputLength).ToArray()).IsEquivalentTo(expected, CollectionOrdering.Matching).Because($"stream {j} of {count} with {guestCount} guests in {groupLanes} lanes");
					}

					for (int i = 0; i < guestCount; ++i)
					{
						byte[] expected = Sha3TestUtils.AbsorbPadAndSqueeze<TGuest>(guestMessages[i], KeccakReference.Sha3DomainSeparator, guestOutputLength);
						await Assert.That(guestOutputs[i]).IsEquivalentTo(expected, CollectionOrdering.Matching).Because($"guest {i} of {guestCount} beside {count} streams in {groupLanes} lanes");
					}
				}
			}
		}

		private (byte[] Outputs, byte[][] GuestOutputs, int Count) Host<TRate, TGuest>(int streams, byte[] inputs, byte[][] guestMessages, int outputLength, int guestOutputLength) where TRate : IKeccakRate where TGuest : IKeccakRate
		{
			int rate = TRate.RateInBytes;
			int guestCount = guestMessages.Length;
			byte[][] guestOutputs = [.. guestMessages.Select(_ => new byte[guestOutputLength])];
			int[] absorbed = new int[guestCount];
			int[] squeezed = new int[guestCount];
			KeccakSponge<TGuest>[] guests = new KeccakSponge<TGuest>[guestCount];
			KeccakBatchSponge<TRate> batch = default;

			if (lanes is 0)
			{
				batch.ResetWithGuests(streams, guestCount);
			}
			else
			{
				batch.Reset(streams, lanes);
			}

			byte[] outputs = new byte[batch.Count * outputLength];
			batch.Absorb(inputs);
			batch.Pad(KeccakReference.ShakeDomainSeparator);

			for (int block = 0; block < Blocks; ++block)
			{
				for (int i = 0; i < guestCount; ++i)
				{
					Step(ref guests[i], guestMessages[i], ref absorbed[i], guestOutputs[i], ref squeezed[i], KeccakReference.Sha3DomainSeparator);
				}

				batch.Permute(guests.AsSpan());
				batch.Squeeze(outputs, block * rate, rate);
			}

			// The rest of the output crosses into a block that Squeeze permutes for alone.
			batch.Squeeze(outputs, Blocks * rate, outputLength - Blocks * rate);

			for (int i = 0; i < guestCount; ++i)
			{
				Finish(ref guests[i], guestMessages[i], absorbed[i], guestOutputs[i], squeezed[i], KeccakReference.Sha3DomainSeparator);
			}

			return (outputs, guestOutputs, batch.Count);
		}
	}
}
