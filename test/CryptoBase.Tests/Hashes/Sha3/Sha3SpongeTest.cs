using CryptoBase.Hashes.Sha3;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hashes.Sha3;

// SHA-3 squeezes at most one block, so these tests drive the sponge directly to cover what SHAKE needs: any domain separator and output of any length, squeezed incrementally.
public class Sha3SpongeTest
{
	private const int ShakeRate = 136;

	public static IEnumerable<int> Rates => [72, 104, 136, 144, 168];

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
			168 => VerifyIncrementalSqueeze<KeccakRate168>(rate, domainSeparator, messageLengthOffset),
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
		byte[] output = Sha3TestUtils.AbsorbPadAndSqueeze<KeccakRate136>(message, KeccakReference.ShakeDomainSeparator, outputLength);

		await Assert.That(output).IsEquivalentTo(Sha3TestUtils.Shake256Output(message, outputLength), CollectionOrdering.Matching);
	}

	// The AVX-512 absorb reads the rows that a full vector would run past a block with masked loads, so input that ends at an inaccessible page must absorb without faulting, whether whole blocks or a partial one end it.
	[Test]
	[MethodDataSource(nameof(Rates))]
	public Task AbsorbReadsNothingPastTheInput(int rate)
	{
		GuardPageBuffer.SkipUnlessSupported();

		return rate switch
		{
			72 => VerifyAbsorbBeforeGuardPage<KeccakRate72>(rate),
			104 => VerifyAbsorbBeforeGuardPage<KeccakRate104>(rate),
			136 => VerifyAbsorbBeforeGuardPage<KeccakRate136>(rate),
			144 => VerifyAbsorbBeforeGuardPage<KeccakRate144>(rate),
			168 => VerifyAbsorbBeforeGuardPage<KeccakRate168>(rate),
			_ => throw new ArgumentOutOfRangeException(nameof(rate))
		};
	}

	// The AVX-512 squeeze writes the rows that a full vector would run past a block with masked stores, so output that ends at an inaccessible page must squeeze without faulting, from any position and whether a whole block or a partial one ends it.
	[Test]
	[MethodDataSource(nameof(Rates))]
	public Task SqueezeWritesNothingPastTheOutput(int rate)
	{
		GuardPageBuffer.SkipUnlessSupported();

		return rate switch
		{
			72 => VerifySqueezeBeforeGuardPage<KeccakRate72>(rate),
			104 => VerifySqueezeBeforeGuardPage<KeccakRate104>(rate),
			136 => VerifySqueezeBeforeGuardPage<KeccakRate136>(rate),
			144 => VerifySqueezeBeforeGuardPage<KeccakRate144>(rate),
			168 => VerifySqueezeBeforeGuardPage<KeccakRate168>(rate),
			_ => throw new ArgumentOutOfRangeException(nameof(rate))
		};
	}

	// One-shot hashing of an input shorter than the rate loads the padded block with masked loads and stores the output with masked stores, so input that ends at an inaccessible page, and output that does, must hash without faulting.
	[Test]
	[MethodDataSource(nameof(Rates))]
	public Task HashDataTouchesNothingPastTheInputOrTheOutput(int rate)
	{
		GuardPageBuffer.SkipUnlessSupported();

		return rate switch
		{
			72 => VerifyHashDataBeforeGuardPages<KeccakRate72>(rate),
			104 => VerifyHashDataBeforeGuardPages<KeccakRate104>(rate),
			136 => VerifyHashDataBeforeGuardPages<KeccakRate136>(rate),
			144 => VerifyHashDataBeforeGuardPages<KeccakRate144>(rate),
			168 => VerifyHashDataBeforeGuardPages<KeccakRate168>(rate),
			_ => throw new ArgumentOutOfRangeException(nameof(rate))
		};
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
		int outputLength = 6 * rate + 5;
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

	private static async Task VerifyAbsorbBeforeGuardPage<TRate>(int rate) where TRate : IKeccakRate
	{
		await Assert.That(TRate.RateInBytes).IsEqualTo(rate);

		foreach (int length in (int[])[rate, 2 * rate, 3 * rate, 3 * rate + 1, 4 * rate - 1])
		{
			byte[] message = CreateDeterministicSource(length);
			byte[] expected = KeccakReference.Sponge(message, rate, KeccakReference.Sha3DomainSeparator, rate);

			await Assert.That(AbsorbBeforeGuardPage<TRate>(message)).IsEquivalentTo(expected, CollectionOrdering.Matching).Because($"{length}-byte message");
		}
	}

	private static byte[] AbsorbBeforeGuardPage<TRate>(byte[] message) where TRate : IKeccakRate
	{
		using GuardPageBuffer buffer = new(message.Length);
		message.CopyTo(buffer.Span);

		return Sha3TestUtils.AbsorbPadAndSqueeze<TRate>(buffer.Span, KeccakReference.Sha3DomainSeparator, TRate.RateInBytes);
	}

	// Each case discards the first skipped bytes, which leaves the sponge at the start, middle or end of a block, then squeezes into memory that ends at the guard page. Ending one byte into a block leaves the last whole block before it nowhere to spill but the guard page.
	private static async Task VerifySqueezeBeforeGuardPage<TRate>(int rate) where TRate : IKeccakRate
	{
		await Assert.That(TRate.RateInBytes).IsEqualTo(rate);

		byte[] message = CreateDeterministicSource(rate + 5);
		(int Skipped, int Length)[] cases =
		[
			(0, rate), (0, 2 * rate), (0, 3 * rate), (0, 3 * rate + 1), (0, 4 * rate - 1),
			(7, 2 * rate), (7, 3 * rate - 6), (7, 4 * rate + 3), (rate, 2 * rate + 1)
		];

		foreach ((int skipped, int length) in cases)
		{
			byte[] expected = KeccakReference.Sponge(message, rate, KeccakReference.ShakeDomainSeparator, skipped + length).AsSpan(skipped).ToArray();

			await Assert.That(SqueezeBeforeGuardPage<TRate>(message, skipped, length)).IsEquivalentTo(expected, CollectionOrdering.Matching).Because($"{length} bytes after {skipped}");
		}
	}

	private static byte[] SqueezeBeforeGuardPage<TRate>(byte[] message, int skipped, int length) where TRate : IKeccakRate
	{
		using GuardPageBuffer buffer = new(length);

		KeccakSponge<TRate> sponge = Sha3TestUtils.AbsorbAndPad<TRate>(message, KeccakReference.ShakeDomainSeparator);
		sponge.Squeeze(new byte[skipped]);
		sponge.Squeeze(buffer.Span);
		return buffer.Span.ToArray();
	}

	// Input lengths around the 40-byte rows and the 64-byte vectors of the AVX-512 path, up to one byte short of the rate; output lengths up to the rate, which one block holds.
	private static async Task VerifyHashDataBeforeGuardPages<TRate>(int rate) where TRate : IKeccakRate
	{
		await Assert.That(TRate.RateInBytes).IsEqualTo(rate);

		foreach (int inputLength in (int[])[0, 1, 7, 39, 40, 41, 63, 64, 65, rate - 41, rate - 40, rate - 1])
		{
			byte[] message = CreateDeterministicSource(inputLength);

			foreach (int outputLength in (int[])[1, 32, 40, 41, 64, rate])
			{
				byte[] expected = KeccakReference.Sponge(message, rate, KeccakReference.ShakeDomainSeparator, outputLength);

				await Assert.That(HashDataBeforeGuardPages<TRate>(message, outputLength)).IsEquivalentTo(expected, CollectionOrdering.Matching).Because($"{inputLength}-byte input, {outputLength}-byte output");
			}
		}
	}

	private static byte[] HashDataBeforeGuardPages<TRate>(byte[] message, int outputLength) where TRate : IKeccakRate
	{
		using GuardPageBuffer input = new(message.Length);
		using GuardPageBuffer output = new(outputLength);
		message.CopyTo(input.Span);
		KeccakSponge<TRate>.HashData(input.Span, output.Span, KeccakReference.ShakeDomainSeparator);
		return output.Span.ToArray();
	}

	// Adds requests that end one or several blocks past the current one, from its start or from within it.
	private static IEnumerable<int[]> PieceLengthPatterns(int rate)
	{
		return XofContractTest.PieceLengthPatterns(rate).Concat([[2 * rate], [2 * rate + 1], [3 * rate], [rate - 1, 3 * rate], [7, 4 * rate + 3]]);
	}
}
