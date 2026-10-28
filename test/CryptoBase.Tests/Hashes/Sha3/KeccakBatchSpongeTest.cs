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

	private static readonly int[] PrefixLengths = [KeccakBatchSponge<KeccakRate168>.ShortPrefixLength, KeccakBatchSponge<KeccakRate168>.LongPrefixLength];

	public static IEnumerable<int> Rates => [72, 104, 136, 144, 168];

	// Each forces one kernel for every group.
	public static IEnumerable<int> Lanes => [1, 2, 4, 8];

	// As Lanes, and zero to let ResetWithGuests choose.
	public static IEnumerable<int> SeededLanes => [0, 1, 2, 4, 8];

	[Test]
	public async Task ScheduleCoversEveryStream()
	{
		TestContext.Current?.Output.WriteLine($"Widest kernel: {KeccakP1600KernelCase.For(KeccakP1600Batch.MaxLanes)}");

		for (int streams = 1; streams <= 64; ++streams)
		{
			List<string> groups = [];

			for (int remaining = streams; remaining > 0;)
			{
				int lanes = KeccakP1600Batch.ChooseLanes(remaining);
				await Assert.That(KeccakP1600KernelCase.For(lanes).IsSupported).IsTrue().Because($"{lanes} lanes for {remaining} of {streams} streams");

				int count = Math.Min(remaining, lanes);
				groups.Add($"{KeccakP1600KernelCase.For(lanes)}[{count}]");
				remaining -= count;
			}

			if (ChosenStreamCounts.Contains(streams))
			{
				TestContext.Current?.Output.WriteLine($"{streams} streams: {string.Join(" + ", groups)}");
			}
		}
	}

	// The vector paths store whole words of every stream four or eight at a time, so outputs that end at an inaccessible page must squeeze without faulting; the last stream of the last group reaches the page.
	[Test]
	[CombinedDataSources]
	public Task SqueezeStaysWithinOutputs([MethodDataSource(nameof(Rates))] int rate, [MethodDataSource(nameof(Lanes))] int lanes)
	{
		GuardPageBuffer.SkipUnlessSupported();
		SkipUnlessSupported(KeccakP1600KernelCase.For(lanes));

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

	// Zero lanes lets ResetWithGuests choose.
	[Test]
	[CombinedDataSources]
	public Task SeededResetMatchesIndependentSponges([MethodDataSource(nameof(Rates))] int rate, [MethodDataSource(nameof(SeededLanes))] int lanes)
	{
		if (lanes is not 0)
		{
			SkipUnlessSupported(KeccakP1600KernelCase.For(lanes));
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
		SkipUnlessSupported(KeccakP1600KernelCase.For(lanes));

		foreach (int prefixLength in PrefixLengths)
		{
			using GuardPageBuffer prefix = new(prefixLength);
			CreateDeterministicSource(prefixLength).CopyTo(prefix.Span);

			for (int streams = 1; streams <= lanes; ++streams)
			{
				foreach (int suffixLength in (int[])[1, 2])
				{
					using GuardPageBuffer suffixBuffer = new(streams * sizeof(ushort));
					Span<ushort> suffixes = MemoryMarshal.Cast<byte, ushort>(suffixBuffer.Span);
					ushort[] values = Sha3TestUtils.Suffixes(streams, suffixLength);
					values.CopyTo(suffixes);

					KeccakBatchSponge<KeccakRate168> batch = default;
					batch.Reset(streams, lanes, prefix.Span, suffixes, suffixLength, KeccakReference.ShakeDomainSeparator);
					byte[] actual = new byte[streams * KeccakRate168.RateInBytes];
					batch.Squeeze(actual);

					byte[] expected = new byte[actual.Length];

					for (int j = 0; j < streams; ++j)
					{
						KeccakSponge<KeccakRate168> sponge = Sha3TestUtils.AbsorbAndPad<KeccakRate168>(Sha3TestUtils.SeededInput(prefix.Span, values[j], suffixLength), KeccakReference.ShakeDomainSeparator);
						sponge.Squeeze(expected.AsSpan(j * KeccakRate168.RateInBytes, KeccakRate168.RateInBytes));
					}

					await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching).Because($"{prefixLength}-byte prefix, {streams} streams with {suffixLength}-byte suffixes");
				}
			}
		}
	}

	// The seeds of ML-KEM and ML-DSA, squeezed for whole and partial word tiles. Groups of the forced kernel width leave a partial group where it does not divide the streams.
	private static async Task VerifyBeforeGuardPages<TRate>(int lanes) where TRate : IKeccakRate
	{
		int rate = TRate.RateInBytes;
		(int Streams, int PrefixLength, int SuffixLength, int OutputLength)[] cases = [(8, 32, 2, 3 * rate), (8, 64, 2, 2 * rate + 32), (8, 32, 1, 32), (8, 64, 2, 33), (4, 64, 2, rate + 33)];

		// The suffix needs a row of its own before the last row of the rate.
		foreach ((int streams, int prefixLength, int suffixLength, int outputLength) in cases.Where(c => c.PrefixLength < rate - sizeof(ulong)))
		{
			byte[] prefix = CreateDeterministicSource(prefixLength);
			ushort[] suffixes = Sha3TestUtils.Suffixes(streams, suffixLength);
			byte[] expected = new byte[streams * outputLength];

			for (int j = 0; j < streams; ++j)
			{
				KeccakSponge<TRate> sponge = Sha3TestUtils.AbsorbAndPad<TRate>(Sha3TestUtils.SeededInput(prefix, suffixes[j], suffixLength), KeccakReference.ShakeDomainSeparator);
				sponge.Squeeze(expected.AsSpan(j * outputLength, outputLength));
			}

			await Assert.That(BatchBeforeGuardPages<TRate>(prefix, suffixes, suffixLength, outputLength, lanes)).IsEquivalentTo(expected, CollectionOrdering.Matching).Because($"{streams} {prefixLength}+{suffixLength}-byte inputs squeezed for {outputLength} bytes");
		}
	}

	private static byte[] BatchBeforeGuardPages<TRate>(byte[] prefix, ushort[] suffixes, int suffixLength, int outputLength, int lanes) where TRate : IKeccakRate
	{
		int streams = suffixes.Length;
		using GuardPageBuffer output = new(streams * outputLength);

		for (int first = 0; first < streams;)
		{
			KeccakBatchSponge<TRate> batch = default;
			batch.Reset(streams - first, lanes, prefix, suffixes.AsSpan(first), suffixLength, KeccakReference.ShakeDomainSeparator);

			int count = batch.Count;
			batch.Squeeze(output.Span.Slice(first * outputLength, count * outputLength));
			first += count;
		}

		return output.Span.ToArray();
	}

	// Each group squeezes in lockstep across block boundaries and from mid-block, then hands every stream to a sponge of its own to squeeze more.
	private static async Task VerifySeeded<TRate>(byte domainSeparator, int lanes) where TRate : IKeccakRate
	{
		int rate = TRate.RateInBytes;
		int[] squeezeLengths = [3 * rate, 7, rate + 1];
		int extractedLength = rate + 5;
		int outputLength = squeezeLengths.Sum() + extractedLength;
		int[] guestCounts = lanes is 0 ? [0, 1, 2] : [0];

		// The suffix needs a row of its own before the last row of the rate.
		foreach (int prefixLength in PrefixLengths.Where(length => length < rate - sizeof(ulong)))
		{
			byte[] prefix = CreateDeterministicSource(prefixLength);

			foreach (int suffixLength in (int[])[1, 2])
			{
				foreach (int streams in StreamCounts)
				{
					ushort[] suffixes = Sha3TestUtils.Suffixes(streams, suffixLength);
					byte[][] expected = new byte[streams][];

					for (int j = 0; j < streams; ++j)
					{
						expected[j] = Sha3TestUtils.AbsorbPadAndSqueeze<TRate>(Sha3TestUtils.SeededInput(prefix, suffixes[j], suffixLength), domainSeparator, outputLength);
					}

					foreach (int guests in guestCounts)
					{
						byte[][] actual = new byte[streams][];

						for (int first = 0; first < streams;)
						{
							KeccakBatchSponge<TRate> batch = default;

							if (lanes is 0)
							{
								batch.ResetWithGuests(streams - first, guests, prefix, suffixes.AsSpan(first), suffixLength, domainSeparator);
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
								await Assert.That(actual[j]).IsEquivalentTo(expected[j], CollectionOrdering.Matching).Because($"stream {j} of {streams} with a {prefix.Length}-byte prefix, {suffixLength}-byte suffixes and {guests} guests");
							}
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
}
