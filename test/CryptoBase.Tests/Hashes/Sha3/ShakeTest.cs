using CryptoBase.Abstractions.Hashes;
using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha3;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hashes.Sha3;

public class ShakeTest
{
	private const int MiB = 1024 * 1024;

	public static IEnumerable<int> SecurityStrengths => [128, 256];

	// The FIPS 202 examples give 4096 bits of output for the empty message and for 200 bytes of 0xA3, whose bit string 11000101 is written LSB first:
	// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHAKE128_Msg0.pdf, SHAKE256_Msg0.pdf, SHAKE128_Msg1600.pdf and SHAKE256_Msg1600.pdf. The first and last 32 bytes stand for the whole output.
	[Test]
	[Arguments(128, 0, "7F9C2BA4E88F827D616045507605853ED73B8093F6EFBC88EB1A6EACFA66EF26", "43E41B45A653F2A5C4492C1ADD544512DDA2529833462B71A41A45BE97290B6F")]
	[Arguments(256, 0, "46B9DD2B0BA88D13233B3FEB743EEB243FCD52EA62B81B82B50C27646ED5762F", "AB0BAE316339894304E35877B0C28A9B1FD166C796B9CC258A064A8F57E27F2A")]
	[Arguments(128, 200, "131AB8D2B594946B9C81333F9BB6E0CE75C3B93104FA3469D3917457385DA037", "44C9FB359FD56AC0A9A75A743CFF6862F17D7259AB075216C0699511643B6439")]
	[Arguments(256, 200, "CD8A920ED141AA0407A22D59288652E9D9F1A7EE0C1E7C1CA699424DA84A904D", "6A1A9D7846436E4DCA5728B6F760EEF0CA92BF0BE5615E96959D767197A0BEEB")]
	public async Task MatchesFips202Examples(int securityStrength, int messageLength, string expectedHead, string expectedTail)
	{
		byte[] message = new byte[messageLength];
		message.AsSpan().Fill(0xA3);
		byte[] output = new byte[512];
		HashData(securityStrength, message, output);

		using (Assert.Multiple())
		{
			await Assert.That(output.AsSpan(0, 32).ToArray()).IsEquivalentTo(Convert.FromHexString(expectedHead), CollectionOrdering.Matching);
			await Assert.That(output.AsSpan(output.Length - 32).ToArray()).IsEquivalentTo(Convert.FromHexString(expectedTail), CollectionOrdering.Matching);
		}
	}

	// Runs everywhere, so it covers the platforms without SHAKE, macOS among them.
	[Test]
	[MethodDataSource(nameof(SecurityStrengths))]
	public async Task MatchesReference(int securityStrength)
	{
		int rate = Rate(securityStrength);

		foreach (int inputLength in HashAlgorithmTestUtils.RateBlockAndPaddingLengths(rate))
		{
			byte[] source = CreateDeterministicSource(inputLength);

			foreach (int outputLength in OutputLengths(rate))
			{
				byte[] expected = KeccakReference.Sponge(source, rate, KeccakReference.ShakeDomainSeparator, outputLength);
				byte[] destination = new byte[outputLength + 2];
				PrepareDestination(destination);
				HashData(securityStrength, source, destination.AsSpan(1, outputLength));
				await AssertOutput(destination, 1, expected);
			}

			byte[] longExpected = KeccakReference.Sponge(source, rate, KeccakReference.ShakeDomainSeparator, 4 * rate + 5);
			await Assert.That(ReadIncrementally(securityStrength, source, longExpected.Length, (uint)inputLength)).IsEquivalentTo(longExpected, CollectionOrdering.Matching);
		}
	}

	[Test]
	[MethodDataSource(nameof(SecurityStrengths))]
	public async Task MatchesPlatformOneShot(int securityStrength)
	{
		SkipUnlessPlatformSupports(securityStrength);
		int rate = Rate(securityStrength);

		foreach (int inputLength in (int[])[0, 1, rate - 1, rate, rate + 1, 5 * rate + 3, MiB])
		{
			byte[] source = CreateDeterministicSource(inputLength);

			foreach (int outputLength in OutputLengths(rate))
			{
				byte[] expected = new byte[outputLength];
				PlatformHashData(securityStrength, source, expected);
				byte[] actual = new byte[outputLength];
				HashData(securityStrength, source, actual);
				await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching).Because($"{inputLength}-byte input, {outputLength}-byte output");
			}
		}
	}

	// Appends the same pieces on both sides, so each call boundary is compared with the platform's.
	[Test]
	[MethodDataSource(nameof(SecurityStrengths))]
	public async Task MatchesPlatformIncrementally(int securityStrength)
	{
		SkipUnlessPlatformSupports(securityStrength);
		int rate = Rate(securityStrength);
		byte[] source = CreateDeterministicSource(7 * rate + 13);

		foreach (int[] pieceLengths in XofContractTest.PieceLengthPatterns(rate))
		{
			using IDisposable platform = CreatePlatform(securityStrength, out Action<ReadOnlySpan<byte>> platformAppend, out _, out Action<Span<byte>> platformCurrent, out Action<Span<byte>> platformFinal);
			using IDisposable xof = CreateXof(securityStrength, out Action<ReadOnlySpan<byte>> append, out _, out Action<Span<byte>> current, out Action<Span<byte>> final);

			for (int round = 0; round < 2; ++round)
			{
				int offset = 0;

				for (int i = 0; offset < source.Length; ++i)
				{
					int length = Math.Min(pieceLengths[i % pieceLengths.Length], source.Length - offset);
					append(source.AsSpan(offset, length));
					platformAppend(source.AsSpan(offset, length));
					offset += length;
				}

				await AssertSameOutput(current, platformCurrent, 3 * rate + 11);
				await AssertSameOutput(final, platformFinal, rate + 1);
			}
		}
	}

	// Reads the same pieces on both sides, so each read boundary is compared with the platform's.
	[Test]
	[MethodDataSource(nameof(SecurityStrengths))]
	public async Task MatchesPlatformReads(int securityStrength)
	{
		SkipUnlessPlatformReads(securityStrength);
		int rate = Rate(securityStrength);
		byte[] source = CreateDeterministicSource(7 * rate + 13);

		foreach (int[] pieceLengths in XofContractTest.PieceLengthPatterns(rate))
		{
			using IDisposable platform = CreatePlatform(securityStrength, out Action<ReadOnlySpan<byte>> platformAppend, out Action<Span<byte>> platformRead, out _, out _);
			using IDisposable xof = CreateXof(securityStrength, out Action<ReadOnlySpan<byte>> append, out Action<Span<byte>> read, out _, out _);
			platformAppend(source);
			append(source);

			for (int i = 0, total = 0; total < 5 * rate; ++i)
			{
				int length = pieceLengths[i % pieceLengths.Length];
				await AssertSameOutput(read, platformRead, length);
				total += length;
			}
		}
	}

	[Test]
	[MethodDataSource(nameof(SecurityStrengths))]
	public async Task HashDataSupportsOverlappingSourceAndDestination(int securityStrength)
	{
		byte[] source = CreateDeterministicSource(Rate(securityStrength) + 9);
		byte[] expected = new byte[2 * Rate(securityStrength) + 1];
		HashData(securityStrength, source, expected);

		await HashAlgorithmTestUtils.VerifyOverlappingHashData(source, expected, (input, output) =>
		{
			HashData(securityStrength, input, output.Slice(0, expected.Length));
			return expected.Length;
		});
	}

	[Test]
	[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Assertions are awaited before reading is disposed.")]
	public async Task CloneCopiesInputAndReadPosition()
	{
		byte[] source = CreateDeterministicSource(200);
		byte[] expected = new byte[3 * 168];
		Xof<Shake128Core>.HashData(Concat(source, source), expected);

		using Xof<Shake128Core> xof = Xof<Shake128Core>.Create();
		xof.Append(source);

		using Xof<Shake128Core> absorbing = xof.Clone();
		absorbing.Append(source);
		byte[] actual = new byte[expected.Length];
		absorbing.GetCurrentHash(actual);
		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);

		xof.Append(source);
		xof.Read(actual.AsSpan(0, 170));
		Xof<Shake128Core> reading = xof.Clone();
		byte[] rest = new byte[expected.Length - 170];
		xof.Read(rest);
		reading.Read(actual.AsSpan(170));

		using (Assert.Multiple())
		{
			await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(rest).IsEquivalentTo(expected.AsSpan(170).ToArray(), CollectionOrdering.Matching);
			await Assert.That(() => reading.Append(source)).ThrowsExactly<InvalidOperationException>();
		}

		reading.Dispose();
		await Assert.That(reading.Clone).ThrowsExactly<ObjectDisposedException>();
	}

	private static int Rate(int securityStrength)
	{
		return 200 - securityStrength / 4;
	}

	private static IEnumerable<int> OutputLengths(int rate)
	{
		return [0, 1, rate - 1, rate, rate + 1, 3 * rate + 11];
	}

	private static void HashData(int securityStrength, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		if (securityStrength is 128)
		{
			Xof<Shake128Core>.HashData(source, destination);
		}
		else
		{
			Xof<Shake256Core>.HashData(source, destination);
		}
	}

	private static byte[] ReadIncrementally(int securityStrength, byte[] source, int outputLength, uint seed)
	{
		return securityStrength is 128 ? ReadIncrementally<Shake128Core>(source, outputLength, seed) : ReadIncrementally<Shake256Core>(source, outputLength, seed);
	}

	private static byte[] ReadIncrementally<TCore>(byte[] source, int outputLength, uint seed) where TCore : unmanaged, IXofCore<TCore>
	{
		using Xof<TCore> xof = Xof<TCore>.Create();
		byte[] output = new byte[outputLength];
		uint state = seed;

		for (int offset = 0; offset < source.Length;)
		{
			state = state * 1664525U + 1013904223U;
			int length = Math.Min((int)(state % 300U), source.Length - offset);
			xof.Append(source.AsSpan(offset, length));
			offset += length;
		}

		for (int offset = 0; offset < outputLength;)
		{
			state = state * 1664525U + 1013904223U;
			int length = Math.Min((int)(state % 300U), outputLength - offset);
			xof.Read(output.AsSpan(offset, length));
			offset += length;
		}

		return output;
	}

	private static void SkipUnlessPlatformSupports(int securityStrength)
	{
		if (!(securityStrength is 128 ? Shake128.IsSupported : Shake256.IsSupported))
		{
			Skip.Test($"The platform lacks SHAKE{securityStrength}.");
		}
	}

	// Reading in pieces needs EVP_DigestSqueeze, which OpenSSL added in 3.3; with an older OpenSSL, Read throws PlatformNotSupportedException.
	private static void SkipUnlessPlatformReads(int securityStrength)
	{
		SkipUnlessPlatformSupports(securityStrength);
		using IDisposable platform = CreatePlatform(securityStrength, out _, out Action<Span<byte>> read, out _, out _);

		try
		{
			read(new byte[1]);
		}
		catch (PlatformNotSupportedException)
		{
			Skip.Test($"The platform's SHAKE{securityStrength} cannot read in pieces.");
		}
	}

	private static void PlatformHashData(int securityStrength, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		if (securityStrength is 128)
		{
			Shake128.HashData(source, destination);
		}
		else
		{
			Shake256.HashData(source, destination);
		}
	}

	private static IDisposable CreatePlatform(int securityStrength, out Action<ReadOnlySpan<byte>> append, out Action<Span<byte>> read, out Action<Span<byte>> current, out Action<Span<byte>> final)
	{
		if (securityStrength is 128)
		{
			Shake128 shake = new();
			(append, read, current, final) = (shake.AppendData, shake.Read, shake.GetCurrentHash, shake.GetHashAndReset);
			return shake;
		}
		else
		{
			Shake256 shake = new();
			(append, read, current, final) = (shake.AppendData, shake.Read, shake.GetCurrentHash, shake.GetHashAndReset);
			return shake;
		}
	}

	private static IDisposable CreateXof(int securityStrength, out Action<ReadOnlySpan<byte>> append, out Action<Span<byte>> read, out Action<Span<byte>> current, out Action<Span<byte>> final)
	{
		if (securityStrength is 128)
		{
			Xof<Shake128Core> xof = Xof<Shake128Core>.Create();
			(append, read, current, final) = (xof.Append, xof.Read, xof.GetCurrentHash, xof.GetHashAndReset);
			return xof;
		}
		else
		{
			Xof<Shake256Core> xof = Xof<Shake256Core>.Create();
			(append, read, current, final) = (xof.Append, xof.Read, xof.GetCurrentHash, xof.GetHashAndReset);
			return xof;
		}
	}

	private static async Task AssertSameOutput(Action<Span<byte>> actual, Action<Span<byte>> expected, int length)
	{
		byte[] expectedOutput = new byte[length];
		expected(expectedOutput);
		byte[] actualOutput = new byte[length];
		actual(actualOutput);
		await Assert.That(actualOutput).IsEquivalentTo(expectedOutput, CollectionOrdering.Matching);
	}
}
