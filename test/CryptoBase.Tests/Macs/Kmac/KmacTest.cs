using CryptoBase.Tests.Hashes;
using CryptoBase.Tests.Hashes.Sha3;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Macs.Kmac;

// The NIST samples and the contract of the public classes; KmacDifferentialTest compares the output with the platform and with KeccakReference over lengths around the block boundaries.
[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Assertions are awaited before disposal.")]
public class KmacTest
{
	private static readonly byte[] Key = CreateDeterministicSource(32);
	private static readonly byte[] Customization = "My Tagged Application"u8.ToArray();

	[Test]
	[MethodDataSource(typeof(Sp800_185Samples), nameof(Sp800_185Samples.Kmac))]
	[MethodDataSource(typeof(Sp800_185Samples), nameof(Sp800_185Samples.KmacXof))]
	public async Task MatchesNistSamples(KmacSample sample)
	{
		KmacVariant variant = new(sample.SecurityStrength, sample.Xof);
		byte[] expected = Convert.FromHexString(sample.Output);
		byte[] customization = Encoding.ASCII.GetBytes(sample.Customization);
		using KmacSubject kmac = variant.Create(sample.Key, customization);
		kmac.Append(sample.Data);

		using (Assert.Multiple())
		{
			await AssertWrites(expected, destination => variant.Compute(sample.Key, sample.Data, destination, customization));
			await AssertWrites(expected, kmac.GetCurrent);
			await AssertWrites(expected, kmac.GetAndReset);
		}

		if (sample.Xof)
		{
			kmac.Append(sample.Data);
			await AssertWrites(expected, kmac.Read);
		}
	}

	[Test]
	[MethodDataSource(typeof(KmacVariant), nameof(KmacVariant.All))]
	public async Task AppendInPiecesMatchesOneAppend(KmacVariant variant)
	{
		int rate = variant.Rate;
		byte[] source = CreateDeterministicSource(7 * rate + 13);
		byte[] expected = variant.Compute(Key, source, rate + 1, Customization);
		using KmacSubject kmac = variant.Create(Key, Customization);

		foreach (int[] pieceLengths in XofContractTest.PieceLengthPatterns(rate))
		{
			for (int i = 0, offset = 0; offset < source.Length; ++i)
			{
				int length = Math.Min(pieceLengths[i % pieceLengths.Length], source.Length - offset);
				kmac.Append(source.AsSpan(offset, length));
				offset += length;
			}

			await AssertWrites(expected, kmac.GetAndReset);
		}
	}

	[Test]
	[MethodDataSource(typeof(KmacVariant), nameof(KmacVariant.All))]
	public async Task GetCurrentLeavesStateUnchanged(KmacVariant variant)
	{
		int rate = variant.Rate;
		byte[] first = CreateDeterministicSource(rate - 1);
		byte[] second = CreateDeterministicSource(2 * rate + 9);
		using KmacSubject kmac = variant.Create(Key, Customization);

		kmac.Append(first);
		await AssertWrites(variant.Compute(Key, first, 2 * rate + 3, Customization), kmac.GetCurrent);
		await AssertWrites(variant.Compute(Key, first, 1, Customization), kmac.GetCurrent);

		kmac.Append(second);
		await AssertWrites(variant.Compute(Key, Concat(first, second), 32, Customization), kmac.GetAndReset);
	}

	// A reset returns to the state after the key, not to an empty cSHAKE or a default key.
	[Test]
	[MethodDataSource(typeof(KmacVariant), nameof(KmacVariant.All))]
	public async Task ResetsKeepKeyAndCustomization(KmacVariant variant)
	{
		int rate = variant.Rate;
		byte[] first = CreateDeterministicSource(rate + 1);
		byte[] second = CreateDeterministicSource(3);
		using KmacSubject kmac = variant.Create(Key, Customization);

		kmac.Append(first);
		await AssertWrites(variant.Compute(Key, first, rate + 7, Customization), kmac.GetAndReset);
		await AssertWrites(variant.Compute(Key, [], 32, Customization), kmac.GetCurrent);

		kmac.Append(second);
		await AssertWrites(variant.Compute(Key, second, 32, Customization), kmac.GetAndReset);

		kmac.Append(first);
		kmac.Reset();
		kmac.Append(second);
		await AssertWrites(variant.Compute(Key, second, rate + 7, Customization), kmac.GetAndReset);
	}

	// L is encoded into the input, so no tag is a prefix of a longer one, and none matches KMACXOF, which encodes 0.
	[Test]
	[MethodDataSource(typeof(KmacVariant), nameof(KmacVariant.FixedLength))]
	public async Task TagsOfDifferentLengthsAreUnrelated(KmacVariant variant)
	{
		byte[] source = CreateDeterministicSource(19);
		int[] lengths = [1, 16, 32, 64, variant.Rate + 1];
		byte[][] tags = lengths.Select(length => variant.Compute(Key, source, length, Customization)).ToArray();
		byte[] stream = new KmacVariant(variant.SecurityStrength, true).Compute(Key, source, lengths[^1], Customization);
		using KmacSubject kmac = variant.Create(Key, Customization);
		kmac.Append(source);

		using (Assert.Multiple())
		{
			for (int i = 0; i < tags.Length; ++i)
			{
				await Assert.That(tags[i]).IsEquivalentTo(variant.Reference(Key, source, lengths[i], Customization), CollectionOrdering.Matching);
				await AssertWrites(tags[i], kmac.GetCurrent);

				// A 1-byte tag still has a 1 in 256 chance of matching, so only the longer ones are compared with the stream.
				if (lengths[i] > 1)
				{
					await Assert.That(tags[i].AsSpan().SequenceEqual(stream.AsSpan(0, lengths[i]))).IsFalse();
				}

				for (int j = i + 1; j < tags.Length; ++j)
				{
					await Assert.That(tags[j].AsSpan(0, lengths[i]).SequenceEqual(tags[i])).IsFalse().Because($"{lengths[i]} and {lengths[j]} bytes");
				}
			}
		}
	}

	[Test]
	[MethodDataSource(typeof(KmacVariant), nameof(KmacVariant.FixedLength))]
	public async Task EmptyDestinationThrowsAndLeavesStateUnchanged(KmacVariant variant)
	{
		byte[] source = CreateDeterministicSource(41);
		byte[] keyCopy = (byte[])Key.Clone();
		byte[] sourceCopy = (byte[])source.Clone();
		using KmacSubject kmac = variant.Create(Key, Customization);
		kmac.Append(source);

		using (Assert.Multiple())
		{
			await Assert.That(() => variant.Compute(Key, source, Span<byte>.Empty, Customization)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("destination");
			await Assert.That(() => kmac.GetCurrent(Span<byte>.Empty)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("destination");
			await Assert.That(() => kmac.GetAndReset(Span<byte>.Empty)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("destination");
			await Assert.That(Key).IsEquivalentTo(keyCopy, CollectionOrdering.Matching);
			await Assert.That(source).IsEquivalentTo(sourceCopy, CollectionOrdering.Matching);
		}

		// The failed GetMacAndReset neither finished nor reset the input.
		await AssertWrites(variant.Compute(Key, source, 32, Customization), kmac.GetAndReset);
	}

	[Test]
	[MethodDataSource(typeof(KmacVariant), nameof(KmacVariant.Extendable))]
	public async Task OutputIsAStream(KmacVariant variant)
	{
		int rate = variant.Rate;
		byte[] source = CreateDeterministicSource(rate + 1);
		int outputLength = 4 * rate + 5;
		byte[] expected = variant.Reference(Key, source, outputLength, Customization);
		using KmacSubject xof = variant.Create(Key, Customization);
		xof.Append(source);

		using (Assert.Multiple())
		{
			foreach (int length in (int[])[0, 1, 32, rate, rate + 1, outputLength])
			{
				byte[] prefix = expected.AsSpan(0, length).ToArray();
				await AssertWrites(prefix, destination => variant.Compute(Key, source, destination, Customization));
				await AssertWrites(prefix, xof.GetCurrent);
			}
		}

		foreach (int[] pieceLengths in XofContractTest.PieceLengthPatterns(rate))
		{
			xof.Reset();
			xof.Append(source);
			byte[] destination = new byte[outputLength + 2];
			PrepareDestination(destination);

			for (int i = 0, offset = 0; offset < outputLength; ++i)
			{
				int length = Math.Min(pieceLengths[i % pieceLengths.Length], outputLength - offset);
				xof.Read(destination.AsSpan(1 + offset, length));
				offset += length;
			}

			await AssertOutput(destination, 1, expected);
		}
	}

	[Test]
	[MethodDataSource(typeof(KmacVariant), nameof(KmacVariant.Extendable))]
	public async Task ReadingRejectsInputUntilReset(KmacVariant variant)
	{
		int rate = variant.Rate;
		byte[] first = CreateDeterministicSource(rate + 3);
		byte[] second = CreateDeterministicSource(7);
		byte[] expected = variant.Compute(Key, Concat(first, second), 2 * rate + 5, Customization);
		using KmacSubject xof = variant.Create(Key, Customization);

		// An empty read leaves the input open.
		xof.Append(first);
		xof.Read(Span<byte>.Empty);
		xof.Append(second);

		byte[] actual = new byte[expected.Length];
		xof.Read(actual.AsSpan(0, 5));

		using (Assert.Multiple())
		{
			await Assert.That(() => xof.Append(first)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => xof.Append(ReadOnlySpan<byte>.Empty)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => xof.GetCurrent(new byte[1])).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => xof.GetAndReset(new byte[1])).ThrowsExactly<InvalidOperationException>();
		}

		xof.Read(Span<byte>.Empty);
		xof.Read(actual.AsSpan(5));
		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);

		xof.Reset();
		xof.Append(second);
		await AssertWrites(variant.Compute(Key, second, rate + 1, Customization), xof.Read);
	}

	[Test]
	[MethodDataSource(typeof(KmacVariant), nameof(KmacVariant.Extendable))]
	public async Task CloneIsIndependent(KmacVariant variant)
	{
		int rate = variant.Rate;
		byte[] source = CreateDeterministicSource(rate + 32);
		byte[] expected = variant.Compute(Key, Concat(source, source), 3 * rate, Customization);
		using KmacSubject xof = variant.Create(Key, Customization);
		xof.Append(source);

		using KmacSubject absorbing = xof.Clone();
		absorbing.Append(source);
		await AssertWrites(expected, absorbing.GetCurrent);
		await AssertWrites(variant.Compute(Key, source, 3 * rate, Customization), xof.GetCurrent);

		xof.Append(source);
		byte[] actual = new byte[expected.Length];
		xof.Read(actual.AsSpan(0, rate + 2));
		KmacSubject reading = xof.Clone();
		byte[] rest = new byte[expected.Length - (rate + 2)];
		xof.Read(rest);
		reading.Read(actual.AsSpan(rate + 2));

		using (Assert.Multiple())
		{
			await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(rest).IsEquivalentTo(expected.AsSpan(rate + 2).ToArray(), CollectionOrdering.Matching);
			await Assert.That(() => reading.Append(source)).ThrowsExactly<InvalidOperationException>();
		}

		// The clone keeps the key and customization string through a reset, and disposing it leaves the original working.
		reading.Reset();
		reading.Append(source);
		await AssertWrites(variant.Compute(Key, source, rate + 1, Customization), reading.Read);

		reading.Dispose();
		await Assert.That(reading.Clone).ThrowsExactly<ObjectDisposedException>();
		xof.Reset();
		await AssertWrites(variant.Compute(Key, [], 9, Customization), xof.GetCurrent);
	}

	[Test]
	[MethodDataSource(typeof(KmacVariant), nameof(KmacVariant.All))]
	public async Task DisposeIsIdempotentAndFinal(KmacVariant variant)
	{
		List<KmacSubject> instances = [variant.Create(Key, Customization)];
		instances[0].Append([1, 2, 3]);

		if (variant.Xof)
		{
			instances.Add(variant.Create(Key, Customization));
			instances[1].Read(new byte[1]);
		}

		foreach (KmacSubject kmac in instances)
		{
			kmac.Dispose();
			kmac.Dispose();

			using (Assert.Multiple())
			{
				await Assert.That(() => kmac.Append([1])).ThrowsExactly<ObjectDisposedException>();
				await Assert.That(() => kmac.GetCurrent(new byte[1])).ThrowsExactly<ObjectDisposedException>();
				await Assert.That(() => kmac.GetAndReset(new byte[1])).ThrowsExactly<ObjectDisposedException>();
				await Assert.That(kmac.Reset).ThrowsExactly<ObjectDisposedException>();

				if (variant.Xof)
				{
					await Assert.That(() => kmac.Read(new byte[1])).ThrowsExactly<ObjectDisposedException>();
					await Assert.That(() => kmac.Read(Span<byte>.Empty)).ThrowsExactly<ObjectDisposedException>();
					await Assert.That(kmac.Clone).ThrowsExactly<ObjectDisposedException>();
				}
			}
		}
	}

	// The state holds the key in its seed; checking it is nonzero first shows that the check could fail.
	[Test]
	[MethodDataSource(typeof(KmacVariant), nameof(KmacVariant.All))]
	public async Task DisposeErasesState(KmacVariant variant)
	{
		List<KmacSubject> instances = [variant.Create(Key, []), variant.Create([], [])];
		instances[0].Append(CreateDeterministicSource(5));

		if (variant.Xof)
		{
			instances.Add(variant.Create(Key, Customization));
			instances[2].Read(new byte[1]);
		}

		foreach (KmacSubject kmac in instances)
		{
			await Assert.That(kmac.StateBytes()).Contains(static value => value is not 0);

			kmac.Dispose();

			await Assert.That(kmac.StateBytes()).All(static value => value is 0);
		}
	}

	[Test]
	[MethodDataSource(typeof(KmacVariant), nameof(KmacVariant.All))]
	public async Task EmptyKeyMatchesReference(KmacVariant variant)
	{
		int rate = variant.Rate;

		foreach (byte[] customization in (byte[][])[[], Customization])
		{
			foreach (int sourceLength in (int[])[0, 1, rate + 1])
			{
				byte[] source = CreateDeterministicSource(sourceLength);
				byte[] expected = variant.Reference([], source, rate + 1, customization);
				using KmacSubject kmac = variant.Create([], customization);
				kmac.Append(source);

				using (Assert.Multiple())
				{
					await AssertWrites(expected, destination => variant.Compute([], source, destination, customization));
					await AssertWrites(expected, kmac.GetAndReset);
				}
			}
		}
	}

	// The input is absorbed before the output is written, so the destination may overlap the key or the source.
	[Test]
	[MethodDataSource(typeof(KmacVariant), nameof(KmacVariant.All))]
	public async Task ComputeSupportsOverlappingInputsAndDestination(KmacVariant variant)
	{
		int rate = variant.Rate;
		const int keyLength = 37;
		int sourceLength = rate + 9;
		int outputLength = 2 * rate + 1;
		byte[] key = CreateDeterministicSource(keyLength);
		byte[] source = CreateDeterministicSource(sourceLength);
		byte[] expected = variant.Compute(key, source, outputLength, Customization);

		foreach (int destinationOffset in (int[])[0, 11, keyLength, keyLength + 17])
		{
			byte[] buffer = new byte[keyLength + sourceLength + outputLength];
			key.CopyTo(buffer, 0);
			source.CopyTo(buffer, keyLength);

			variant.Compute(buffer.AsSpan(0, keyLength), buffer.AsSpan(keyLength, sourceLength), buffer.AsSpan(destinationOffset, outputLength), Customization);

			await Assert.That(buffer.AsSpan(destinationOffset, outputLength).ToArray()).IsEquivalentTo(expected, CollectionOrdering.Matching).Because($"destination at {destinationOffset}");
		}
	}
}
