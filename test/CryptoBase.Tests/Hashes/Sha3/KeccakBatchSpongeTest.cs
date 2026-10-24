using CryptoBase.Hashes.Sha3;
using System.Runtime.InteropServices;
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

	// As Lanes, and zero to let ResetWithGuests choose.
	public static IEnumerable<int> SeededLanes => [0, 1, 2, 4, 8];

	[Test]
	public async Task ScheduleCoversEveryStream()
	{
		TestContext.Current?.Output.WriteLine($"Widest kernel: {Sha3TestUtils.KernelName(KeccakP1600Batch.MaxLanes)}");

		for (int streams = 1; streams <= 64; ++streams)
		{
			List<string> groups = [];

			for (int remaining = streams; remaining > 0;)
			{
				int lanes = KeccakP1600Batch.ChooseLanes(remaining);
				await Assert.That(Sha3TestUtils.IsKernelSupported(lanes)).IsTrue().Because($"{lanes} lanes for {remaining} of {streams} streams");

				int count = Math.Min(remaining, lanes);
				groups.Add($"{Sha3TestUtils.KernelName(lanes)}[{count}]");
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
		Sha3TestUtils.SkipUnlessKernelSupported(lanes);

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

	// The vector paths load and store whole words of every stream four or eight at a time, so inputs and outputs that end at an inaccessible page must absorb and squeeze without faulting; the last stream of the last group reaches the page.
	[Test]
	[CombinedDataSources]
	public Task StaysWithinInputsAndOutputs([MethodDataSource(nameof(Rates))] int rate, [MethodDataSource(nameof(Lanes))] int lanes)
	{
		GuardPageBuffer.SkipUnlessSupported();
		Sha3TestUtils.SkipUnlessKernelSupported(lanes);

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

	// Zero lanes lets ResetWithGuests choose, which must take as many streams on as wide a kernel as without a seed.
	[Test]
	[CombinedDataSources]
	public Task SeededResetMatchesIndependentSponges([MethodDataSource(nameof(Rates))] int rate, [MethodDataSource(nameof(SeededLanes))] int lanes)
	{
		if (lanes is not 0)
		{
			Sha3TestUtils.SkipUnlessKernelSupported(lanes);
		}

		return rate switch
		{
			72 => VerifySeeded<KeccakRate72>(KeccakReference.Sha3DomainSeparator, lanes),
			104 => VerifySeeded<KeccakRate104>(KeccakReference.Sha3DomainSeparator, lanes),
			136 => VerifySeeded<KeccakRate136>(KeccakReference.ShakeDomainSeparator, lanes),
			144 => VerifySeeded<KeccakRate144>(KeccakReference.Sha3DomainSeparator, lanes),
			168 => VerifySeeded<KeccakRate168>(KeccakReference.ShakeDomainSeparator, lanes),
			_ => throw new ArgumentOutOfRangeException(nameof(rate))
		};
	}

	// The prefix and the suffixes may end at an inaccessible page.
	[Test]
	[MethodDataSource(nameof(Lanes))]
	public async Task SeededResetStaysWithinPrefixAndSuffixes(int lanes)
	{
		GuardPageBuffer.SkipUnlessSupported();
		Sha3TestUtils.SkipUnlessKernelSupported(lanes);

		using GuardPageBuffer prefix = new(KeccakBatchSponge<KeccakRate168>.SeedLength);
		CreateDeterministicSource(prefix.Span.Length).CopyTo(prefix.Span);

		for (int streams = 1; streams <= lanes; ++streams)
		{
			foreach (int suffixLength in (int[])[1, 2])
			{
				using GuardPageBuffer suffixBuffer = new(streams * sizeof(ushort));
				Span<ushort> suffixes = MemoryMarshal.Cast<byte, ushort>(suffixBuffer.Span);
				ushort[] values = Suffixes(streams, suffixLength);
				values.CopyTo(suffixes);

				KeccakBatchSponge<KeccakRate168> batch = default;
				batch.Reset(streams, lanes, prefix.Span, suffixes, suffixLength, KeccakReference.ShakeDomainSeparator);
				byte[] actual = new byte[streams * KeccakRate168.RateInBytes];
				batch.Squeeze(actual);

				byte[] expected = new byte[actual.Length];

				for (int j = 0; j < streams; ++j)
				{
					KeccakSponge<KeccakRate168> sponge = Sha3TestUtils.AbsorbAndPad<KeccakRate168>(SeededInput(prefix.Span, values[j], suffixLength), KeccakReference.ShakeDomainSeparator);
					sponge.Squeeze(expected.AsSpan(j * KeccakRate168.RateInBytes, KeccakRate168.RateInBytes));
				}

				await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching).Because($"{streams} streams with {suffixLength}-byte suffixes");
			}
		}
	}

	[Test]
	public async Task PaddingSwitchesToSqueezing()
	{
		KeccakBatchSponge<KeccakRate136> sponge = default;
		sponge.ResetWithGuests(3, 0);
		await Assert.That(sponge.IsSqueezing).IsFalse();

		sponge.Absorb(new byte[sponge.Count * 137]);
		await Assert.That(sponge.IsSqueezing).IsFalse();

		sponge.Pad(KeccakReference.ShakeDomainSeparator);
		await Assert.That(sponge.IsSqueezing).IsTrue();
		await Assert.That(sponge.ExtractLane(0).IsSqueezing).IsTrue();
	}

	// Each group absorbs in two calls where the input allows, the second starting mid-word, on a word boundary or past a block boundary, squeezes in lockstep across block boundaries and from mid-block, then hands every stream to a sponge of its own to squeeze more blocks. The input lengths fall on both sides of a word, of one and two four-word tiles, and of the block. Zero lanes lets KeccakP1600Batch choose.
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
					expected[j] = Sha3TestUtils.AbsorbPadAndSqueeze<TRate>(inputs.AsSpan(j * inputLength, inputLength), domainSeparator, outputLength);
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
						SqueezeGroup(ref batch, actual.AsSpan(first, count), squeezeLengths, outputLength);
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

	// Seeds of ML-KEM and ML-DSA, SLH-DSA F and H inputs at n = 32, a block and a byte, squeezed for whole and partial word tiles. Groups of the forced kernel width leave a partial group where it does not divide the streams.
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

	private static async Task VerifySeeded<TRate>(byte domainSeparator, int lanes) where TRate : IKeccakRate
	{
		int rate = TRate.RateInBytes;
		byte[] prefix = CreateDeterministicSource(KeccakBatchSponge<TRate>.SeedLength);
		int[] squeezeLengths = [3 * rate, 7, rate + 1];
		int extractedLength = rate + 5;
		int outputLength = squeezeLengths.Sum() + extractedLength;
		int[] guestCounts = lanes is 0 ? [0, 1, 2] : [0];

		foreach (int suffixLength in (int[])[1, 2])
		{
			foreach (int streams in StreamCounts)
			{
				ushort[] suffixes = Suffixes(streams, suffixLength);
				byte[][] expected = new byte[streams][];

				for (int j = 0; j < streams; ++j)
				{
					expected[j] = Sha3TestUtils.AbsorbPadAndSqueeze<TRate>(SeededInput(prefix, suffixes[j], suffixLength), domainSeparator, outputLength);
				}

				foreach (int guests in guestCounts)
				{
					byte[][] actual = new byte[streams][];

					for (int first = 0; first < streams;)
					{
						KeccakBatchSponge<TRate> batch = default;

						if (lanes is 0)
						{
							KeccakBatchSponge<TRate> unseeded = default;
							unseeded.ResetWithGuests(streams - first, guests);
							batch.ResetWithGuests(streams - first, guests, prefix, suffixes.AsSpan(first), suffixLength, domainSeparator);

							using (Assert.Multiple())
							{
								await Assert.That(batch.Count).IsEqualTo(unseeded.Count);
								await Assert.That(batch.FreeLanes).IsEqualTo(unseeded.FreeLanes);
							}
						}
						else
						{
							batch.Reset(streams - first, lanes, prefix, suffixes.AsSpan(first), suffixLength, domainSeparator);
						}

						await Assert.That(batch.IsSqueezing).IsTrue();

						int count = batch.Count;
						SqueezeGroup(ref batch, actual.AsSpan(first, count), squeezeLengths, outputLength);
						first += count;
					}

					using (Assert.Multiple())
					{
						for (int j = 0; j < streams; ++j)
						{
							await Assert.That(actual[j]).IsEquivalentTo(expected[j], CollectionOrdering.Matching).Because($"stream {j} of {streams} with {suffixLength}-byte suffixes and {guests} guests");
						}
					}
				}
			}
		}
	}

	// Squeezes in lockstep across block boundaries and from mid-block, then hands every stream to a sponge of its own for the rest.
	private static void SqueezeGroup<TRate>(ref KeccakBatchSponge<TRate> batch, Span<byte[]> actual, int[] squeezeLengths, int outputLength) where TRate : IKeccakRate
	{
		int offset = 0;

		for (int j = 0; j < actual.Length; ++j)
		{
			actual[j] = new byte[outputLength];
		}

		foreach (int length in squeezeLengths)
		{
			byte[] outputs = new byte[actual.Length * length];
			batch.Squeeze(outputs);

			for (int j = 0; j < actual.Length; ++j)
			{
				outputs.AsSpan(j * length, length).CopyTo(actual[j].AsSpan(offset));
			}

			offset += length;
		}

		for (int j = 0; j < actual.Length; ++j)
		{
			KeccakSponge<TRate> extracted = batch.ExtractLane(j);
			extracted.Squeeze(actual[j].AsSpan(offset));
		}
	}

	// Distinct suffixes that use every byte they have.
	private static ushort[] Suffixes(int streams, int suffixLength)
	{
		int mask = suffixLength is 1 ? 0xFF : 0xFFFF;
		return [.. Enumerable.Range(0, streams).Select(j => (ushort)(0xA5C3 + j * 0x0101 & mask))];
	}

	private static byte[] SeededInput(ReadOnlySpan<byte> prefix, ushort suffix, int suffixLength)
	{
		byte[] input = new byte[prefix.Length + suffixLength];
		prefix.CopyTo(input);
		input[prefix.Length] = (byte)suffix;

		if (suffixLength is 2)
		{
			input[prefix.Length + 1] = (byte)(suffix >> 8);
		}

		return input;
	}

	private static void Reset<TRate>(ref KeccakBatchSponge<TRate> batch, int streams, int lanes) where TRate : IKeccakRate
	{
		batch.Reset(streams, lanes is 0 ? KeccakP1600Batch.ChooseLanes(streams) : lanes);
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
}
