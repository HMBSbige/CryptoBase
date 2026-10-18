using CryptoBase.Hashes.Sha3;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hashes.Sha3;

// SHA-3 squeezes at most one block, so these tests drive the sponge directly to cover what SHAKE needs:
// any domain separator and output of any length, squeezed incrementally.
public class Sha3SpongeTest
{
	private const int ShakeRate = 136;

	public static IEnumerable<int> Rates => [72, 104, 136, 144];

	public static IEnumerable<byte> DomainSeparators => [KeccakReference.Sha3DomainSeparator, KeccakReference.ShakeDomainSeparator];

	// Message lengths relative to the rate: a lone byte left for the padding, a full block, and partial second blocks.
	public static IEnumerable<int> MessageLengthOffsets => [-1, 0, 1, 5];

	[Test]
	[CombinedDataSources]
	public Task IncrementalSqueezeMatchesOneSqueeze([MethodDataSource(nameof(Rates))] int rate, [MethodDataSource(nameof(DomainSeparators))] byte domainSeparator, [MethodDataSource(nameof(MessageLengthOffsets))] int messageLengthOffset)
	{
		return rate switch
		{
			72 => VerifyIncrementalSqueeze<KeccakRate72>(rate, domainSeparator, messageLengthOffset),
			104 => VerifyIncrementalSqueeze<KeccakRate104>(rate, domainSeparator, messageLengthOffset),
			136 => VerifyIncrementalSqueeze<KeccakRate136>(rate, domainSeparator, messageLengthOffset),
			144 => VerifyIncrementalSqueeze<KeccakRate144>(rate, domainSeparator, messageLengthOffset),
			_ => throw new ArgumentOutOfRangeException(nameof(rate))
		};
	}

	// With the SHAKE domain separator and a 136-byte rate, the sponge is SHAKE256, which the platform may implement.
	[Test]
	[Arguments(0)]
	[Arguments(ShakeRate - 1)]
	[Arguments(ShakeRate)]
	[Arguments(3 * ShakeRate + 7)]
	public async Task ShakeDomainSeparatorGivesShake256(int messageLength)
	{
		byte[] message = CreateDeterministicSource(messageLength);
		const int outputLength = 3 * ShakeRate + 11;
		KeccakSponge<KeccakRate136> sponge = Sha3TestUtils.AbsorbAndPad<KeccakRate136>(message, KeccakReference.ShakeDomainSeparator);
		byte[] output = new byte[outputLength];
		sponge.Squeeze(output);

		await Assert.That(output).IsEquivalentTo(Sha3TestUtils.Shake256Output(message, outputLength), CollectionOrdering.Matching);
	}

	[Test]
	public async Task PaddingSwitchesToSqueezing()
	{
		KeccakSponge<KeccakRate136> sponge = default;
		sponge.Reset();
		await Assert.That(sponge.IsSqueezing).IsFalse();

		sponge.Absorb(CreateDeterministicSource(ShakeRate + 1));
		await Assert.That(sponge.IsSqueezing).IsFalse();

		sponge.Pad(KeccakReference.Sha3DomainSeparator);
		await Assert.That(sponge.IsSqueezing).IsTrue();

		sponge.Squeeze(new byte[2 * ShakeRate]);
		await Assert.That(sponge.IsSqueezing).IsTrue();

		sponge.Reset();
		await Assert.That(sponge.IsSqueezing).IsFalse();
	}

	private static async Task VerifyIncrementalSqueeze<TRate>(int rate, byte domainSeparator, int messageLengthOffset) where TRate : IKeccakRate
	{
		await Assert.That(TRate.RateInBytes).IsEqualTo(rate);

		byte[] message = CreateDeterministicSource(Math.Max(0, rate + messageLengthOffset));
		int outputLength = 4 * rate + 5;
		byte[] expected = KeccakReference.Sponge(message, rate, domainSeparator, outputLength);

		KeccakSponge<TRate> sponge = Sha3TestUtils.AbsorbAndPad<TRate>(message, domainSeparator);
		KeccakSponge<TRate> initial = sponge;

		byte[] output = new byte[outputLength];
		sponge.Squeeze(output);
		await Assert.That(output).IsEquivalentTo(expected, CollectionOrdering.Matching);

		foreach (int[] pieceLengths in PieceLengthPatterns(rate))
		{
			sponge = initial;
			output = new byte[outputLength];
			int offset = 0;

			for (int i = 0; offset < outputLength; ++i)
			{
				int length = Math.Min(pieceLengths[i % pieceLengths.Length], outputLength - offset);
				sponge.Squeeze(output.AsSpan(offset, length));
				offset += length;
			}

			await Assert.That(output).IsEquivalentTo(expected, CollectionOrdering.Matching).Because($"pieces of [{string.Join(", ", pieceLengths)}] bytes");
		}
	}

	// Empty requests must not advance the output, and requests may end exactly on, just before, or just after a block boundary.
	private static IEnumerable<int[]> PieceLengthPatterns(int rate)
	{
		yield return [1];
		yield return [rate - 1];
		yield return [rate];
		yield return [rate + 1];
		yield return [2 * rate + 3];
		yield return [0, 7, rate - 7, 0, 2 * rate, 1];
		yield return [3, 1, 4, 1, 5, 9, 2, 6, 5, 35, 89, 79, 3, 238, 46];
	}
}
