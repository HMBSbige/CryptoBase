using CryptoBase.Hashes.Sha3;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hashes.Sha3;

public class KeccakBatchSpongeTest
{
	// Stream counts below, at and past each kernel width, so that groups end both full and partial.
	private static readonly int[] StreamCounts = [1, 2, 3, 4, 5, 7, 8, 9, 30];

	// Stream counts for which KeccakP1600Batch chooses each kernel width, alone and after full groups.
	private static readonly int[] ChosenStreamCounts = [1, 3, 5, 9, 11, 30];

	public static IEnumerable<int> Rates => [72, 104, 136, 144, 168];

	// Each forces one kernel for every group.
	public static IEnumerable<int> Lanes => [1, 2, 4, 8];

	[Test]
	public async Task ScheduleCoversEveryStream()
	{
		TestContext.Current?.Output.WriteLine($"Widest kernel: {KernelName(KeccakP1600Batch.MaxLanes)}");

		for (int streams = 1; streams <= 64; ++streams)
		{
			List<string> groups = [];

			for (int remaining = streams; remaining > 0;)
			{
				int lanes = KeccakP1600Batch.ChooseLanes(remaining);
				await Assert.That(IsSupported(lanes)).IsTrue().Because($"{lanes} lanes for {remaining} of {streams} streams");

				int count = Math.Min(remaining, lanes);
				groups.Add($"{KernelName(lanes)}[{count}]");
				remaining -= count;
			}

			if (ChosenStreamCounts.Contains(streams))
			{
				TestContext.Current?.Output.WriteLine($"{streams} streams: {string.Join(" + ", groups)}");
			}
		}
	}

	// Each rate pads with the domain separator of a function that uses it.
	[Test]
	[CombinedDataSources]
	public Task MatchesIndependentSponges([MethodDataSource(nameof(Rates))] int rate, [MethodDataSource(nameof(Lanes))] int lanes)
	{
		if (!IsSupported(lanes))
		{
			Skip.Test($"{KernelName(lanes)} is not supported here.");
		}

		return rate switch
		{
			72 => Verify<KeccakRate72>(KeccakReference.Sha3DomainSeparator, lanes, StreamCounts),
			104 => Verify<KeccakRate104>(KeccakReference.Sha3DomainSeparator, lanes, StreamCounts),
			136 => Verify<KeccakRate136>(KeccakReference.ShakeDomainSeparator, lanes, StreamCounts),
			144 => Verify<KeccakRate144>(KeccakReference.Sha3DomainSeparator, lanes, StreamCounts),
			168 => Verify<KeccakRate168>(KeccakReference.ShakeDomainSeparator, lanes, StreamCounts),
			_ => throw new ArgumentOutOfRangeException(nameof(rate))
		};
	}

	[Test]
	public Task ChosenKernelsMatchIndependentSponges()
	{
		return Verify<KeccakRate168>(KeccakReference.ShakeDomainSeparator, 0, ChosenStreamCounts);
	}

	// The vector paths load and store whole words of every stream four or eight at a time, so inputs and outputs that end at an
	// inaccessible page must absorb and squeeze without faulting; the last stream of the last group reaches the page.
	[Test]
	[CombinedDataSources]
	public Task StaysWithinInputsAndOutputs([MethodDataSource(nameof(Rates))] int rate, [MethodDataSource(nameof(Lanes))] int lanes)
	{
		if (!GuardPageBuffer.IsSupported)
		{
			Skip.Test("Guard pages are not supported here.");
		}

		if (!IsSupported(lanes))
		{
			Skip.Test($"{KernelName(lanes)} is not supported here.");
		}

		return rate switch
		{
			72 => VerifyBeforeGuardPages<KeccakRate72>(lanes),
			104 => VerifyBeforeGuardPages<KeccakRate104>(lanes),
			136 => VerifyBeforeGuardPages<KeccakRate136>(lanes),
			144 => VerifyBeforeGuardPages<KeccakRate144>(lanes),
			168 => VerifyBeforeGuardPages<KeccakRate168>(lanes),
			_ => throw new ArgumentOutOfRangeException(nameof(rate))
		};
	}

	[Test]
	public async Task PaddingSwitchesToSqueezing()
	{
		KeccakBatchSponge<KeccakRate136> sponge = default;
		sponge.Reset(3);
		await Assert.That(sponge.IsSqueezing).IsFalse();

		sponge.Absorb(new byte[sponge.Count * 137]);
		await Assert.That(sponge.IsSqueezing).IsFalse();

		sponge.Pad(KeccakReference.ShakeDomainSeparator);
		await Assert.That(sponge.IsSqueezing).IsTrue();
		await Assert.That(sponge.ExtractLane(0).IsSqueezing).IsTrue();
	}

	private static bool IsSupported(int lanes)
	{
		return lanes switch
		{
			1 => KeccakP1600Times1.IsSupported,
			2 => KeccakP1600Times2.IsSupported,
			4 => KeccakP1600Times4.IsSupported,
			8 => KeccakP1600Times8.IsSupported,
			_ => false
		};
	}

	// Each group absorbs in two calls where the input allows, the second starting mid-word, on a word boundary or past a block
	// boundary, squeezes in lockstep across block boundaries and from mid-block, then hands every stream to a sponge of its own to
	// squeeze more blocks. The input lengths fall on both sides of a word, of one and two four-word tiles, and of the block. Zero
	// lanes lets KeccakP1600Batch choose.
	private static async Task Verify<TRate>(byte domainSeparator, int lanes, int[] streamCounts) where TRate : IKeccakRate
	{
		int rate = TRate.RateInBytes;
		int[] inputLengths = [0, 7, 8, 9, 31, 32, 33, 63, 64, 65, rate - 1, rate, rate + 1, 2 * rate + 5];
		int[] splits = [5, 8, rate + 3];
		int[] squeezeLengths = [3 * rate, 7, rate + 1];
		int extractedLength = 2 * rate + 5;
		int outputLength = squeezeLengths.Sum() + extractedLength;

		foreach (int inputLength in inputLengths)
		{
			foreach (int streams in streamCounts)
			{
				byte[] inputs = CreateDeterministicSource(streams * inputLength);
				byte[][] expected = new byte[streams][];

				for (int j = 0; j < streams; ++j)
				{
					KeccakSponge<TRate> sponge = Sha3TestUtils.AbsorbAndPad<TRate>(inputs.AsSpan(j * inputLength, inputLength), domainSeparator);
					expected[j] = new byte[outputLength];
					sponge.Squeeze(expected[j]);
				}

				foreach (int split in splits.Select(split => Math.Min(split, inputLength)).Distinct())
				{
					byte[][] actual = new byte[streams][];

					for (int first = 0; first < streams;)
					{
						KeccakBatchSponge<TRate> batch = default;
						Reset(ref batch, streams - first, lanes);

						int count = batch.Count;
						batch.Absorb(Gather(inputs, inputLength, first, count, 0, split));
						batch.Absorb(Gather(inputs, inputLength, first, count, split, inputLength - split));
						batch.Pad(domainSeparator);

						for (int j = 0; j < count; ++j)
						{
							actual[first + j] = new byte[outputLength];
						}

						int offset = 0;

						foreach (int length in squeezeLengths)
						{
							byte[] outputs = new byte[count * length];
							batch.Squeeze(outputs);

							for (int j = 0; j < count; ++j)
							{
								outputs.AsSpan(j * length, length).CopyTo(actual[first + j].AsSpan(offset));
							}

							offset += length;
						}

						for (int j = 0; j < count; ++j)
						{
							KeccakSponge<TRate> extracted = batch.ExtractLane(j);
							extracted.Squeeze(actual[first + j].AsSpan(offset, extractedLength));
						}

						first += count;
					}

					using (Assert.Multiple())
					{
						for (int j = 0; j < streams; ++j)
						{
							await Assert.That(actual[j]).IsEquivalentTo(expected[j], CollectionOrdering.Matching).Because($"stream {j} of {streams} with {inputLength}-byte inputs split at {split}");
						}
					}
				}
			}
		}
	}

	// ML-KEM and ML-DSA seeds, the F and H inputs of SLH-DSA with n = 32, and a block and a byte, squeezed for whole and partial
	// tiles of words. Groups of the forced kernel width leave a partial group where it does not divide the streams.
	private static async Task VerifyBeforeGuardPages<TRate>(int lanes) where TRate : IKeccakRate
	{
		int rate = TRate.RateInBytes;
		(int Streams, int InputLength, int OutputLength)[] cases = [(8, 34, 3 * rate), (8, 66, 2 * rate + 32), (8, 96, 32), (8, 128, 32), (4, 66, rate + 33), (8, rate + 1, 33)];

		foreach ((int streams, int inputLength, int outputLength) in cases)
		{
			byte[] inputs = CreateDeterministicSource(streams * inputLength);
			byte[] expected = new byte[streams * outputLength];

			for (int j = 0; j < streams; ++j)
			{
				KeccakSponge<TRate> sponge = Sha3TestUtils.AbsorbAndPad<TRate>(inputs.AsSpan(j * inputLength, inputLength), KeccakReference.ShakeDomainSeparator);
				sponge.Squeeze(expected.AsSpan(j * outputLength, outputLength));
			}

			await Assert.That(BatchBeforeGuardPages<TRate>(inputs, streams, outputLength, lanes)).IsEquivalentTo(expected, CollectionOrdering.Matching).Because($"{streams} {inputLength}-byte inputs squeezed for {outputLength} bytes");
		}
	}

	private static byte[] BatchBeforeGuardPages<TRate>(byte[] inputs, int streams, int outputLength, int lanes) where TRate : IKeccakRate
	{
		int inputLength = inputs.Length / streams;
		using GuardPageBuffer input = new(inputs.Length);
		using GuardPageBuffer output = new(streams * outputLength);
		inputs.CopyTo(input.Span);

		for (int first = 0; first < streams;)
		{
			KeccakBatchSponge<TRate> batch = default;
			Reset(ref batch, streams - first, lanes);

			int count = batch.Count;
			batch.Absorb(input.Span.Slice(first * inputLength, count * inputLength));
			batch.Pad(KeccakReference.ShakeDomainSeparator);
			batch.Squeeze(output.Span.Slice(first * outputLength, count * outputLength));
			first += count;
		}

		return output.Span.ToArray();
	}

	private static void Reset<TRate>(ref KeccakBatchSponge<TRate> batch, int streams, int lanes) where TRate : IKeccakRate
	{
		if (lanes is 0)
		{
			batch.Reset(streams);
		}
		else
		{
			batch.Reset(streams, lanes);
		}
	}

	private static byte[] Gather(byte[] inputs, int inputLength, int first, int count, int offset, int length)
	{
		byte[] gathered = new byte[count * length];

		for (int j = 0; j < count; ++j)
		{
			inputs.AsSpan((first + j) * inputLength + offset, length).CopyTo(gathered.AsSpan(j * length));
		}

		return gathered;
	}

	private static string KernelName(int lanes)
	{
		return lanes switch
		{
			8 => nameof(KeccakP1600Times8),
			4 => nameof(KeccakP1600Times4),
			2 => nameof(KeccakP1600Times2),
			_ => nameof(KeccakP1600Times1)
		};
	}
}
