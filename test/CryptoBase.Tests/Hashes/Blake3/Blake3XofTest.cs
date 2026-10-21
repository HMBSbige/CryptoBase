using CryptoBase.Abstractions.Hashes;
using CryptoBase.Hashes.Blake3;
using System.Diagnostics.CodeAnalysis;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hashes.Blake3;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class Blake3XofTest
{
	private const int OutputLength = 4 * 1024 + 37;

	public static IEnumerable<int> InputLengths => [0, 1, 1024, 1025, 3 * 1024 + 7];

	// Reads in pieces continue the stream, so each piece is the output at its position, in every mode.
	[Test]
	[CombinedDataSources]
	public async Task ReadInPiecesMatchesPositionalOutput([MethodDataSource(nameof(InputLengths))] int inputLength, [MethodDataSource(typeof(Blake3TestUtils), nameof(Blake3TestUtils.Modes))] Blake3Mode mode)
	{
		byte[] source = CreateDeterministicSource(inputLength);
		byte[] expected = Blake3TestUtils.ReferenceHash(mode, source, OutputLength);
		using Blake3HashAlgorithm hasher = Blake3TestUtils.CreateHasher(mode);

		foreach (int[] pieceLengths in XofContractTest.PieceLengthPatterns(64).Append([1023, 1025, 4096]))
		{
			hasher.Reset();
			hasher.Append(source);
			byte[] destination = new byte[OutputLength + 2];
			PrepareDestination(destination);

			for (int i = 0, offset = 0; offset < OutputLength; ++i)
			{
				int length = Math.Min(pieceLengths[i % pieceLengths.Length], OutputLength - offset);
				Span<byte> piece = destination.AsSpan(1 + offset, length);
				hasher.Read(piece);

				byte[] positional = new byte[length];
				hasher.GetCurrentHash(positional, (ulong)offset);
				await Assert.That(piece.ToArray()).IsEquivalentTo(positional, CollectionOrdering.Matching);
				offset += length;
			}

			await AssertOutput(destination, 1, expected);
		}
	}

	[Test]
	[MethodDataSource(typeof(Blake3TestUtils), nameof(Blake3TestUtils.Modes))]
	public async Task ReadStartsAtStreamBeginningAfterReset(Blake3Mode mode)
	{
		byte[] source = CreateDeterministicSource(100);
		byte[] expected = Blake3TestUtils.ReferenceHash(mode, source, 200);
		using Blake3HashAlgorithm hasher = Blake3TestUtils.CreateHasher(mode);

		hasher.Append([1, 2, 3]);
		hasher.Read(new byte[150]);
		hasher.Reset();
		hasher.Append(source);

		byte[] actual = new byte[expected.Length];
		hasher.Read(actual.AsSpan(0, 1));
		hasher.Read(actual.AsSpan(1));
		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	[MethodDataSource(typeof(Blake3TestUtils), nameof(Blake3TestUtils.Modes))]
	public async Task CloneCopiesReadPosition(Blake3Mode mode)
	{
		byte[] source = CreateDeterministicSource(2049);
		byte[] expected = Blake3TestUtils.ReferenceHash(mode, source, 300);
		using Blake3HashAlgorithm hasher = Blake3TestUtils.CreateHasher(mode);
		hasher.Append(source);

		byte[] actual = new byte[expected.Length];
		hasher.Read(actual.AsSpan(0, 77));
		using Blake3HashAlgorithm clone = hasher.Clone();
		byte[] rest = new byte[expected.Length - 77];
		hasher.Read(rest);
		clone.Read(actual.AsSpan(77));

		using (Assert.Multiple())
		{
			await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(rest).IsEquivalentTo(expected.AsSpan(77).ToArray(), CollectionOrdering.Matching);
			await Assert.That(() => clone.Append(source)).ThrowsExactly<InvalidOperationException>();
		}

		clone.Reset();
		clone.Append(source);
		byte[] restarted = new byte[expected.Length];
		clone.GetCurrentHash(restarted);
		await Assert.That(restarted).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	// Reading only seals the input; random access through a position still works and leaves the read position alone.
	[Test]
	public async Task ReadingKeepsPositionalOutputAndRejectsOtherInput()
	{
		byte[] source = CreateDeterministicSource(5000);
		byte[] expected = Blake3TestUtils.ReferenceHash(Blake3Mode.Hash, source, 200);
		using Blake3HashAlgorithm hasher = Blake3HashAlgorithm.Create();
		hasher.Append(source);

		byte[] actual = new byte[expected.Length];
		hasher.Read(actual.AsSpan(0, 50));
		byte[] positional = new byte[100];
		hasher.GetCurrentHash(positional, 100);
		hasher.Read(actual.AsSpan(50));

		using (Assert.Multiple())
		{
			await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(positional).IsEquivalentTo(expected.AsSpan(100).ToArray(), CollectionOrdering.Matching);
			await Assert.That(() => hasher.Append(source, 2)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => ((IHashAlgorithm<Blake3HashAlgorithm>)hasher).GetCurrentHash(new byte[32])).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => ((IHashAlgorithm<Blake3HashAlgorithm>)hasher).GetHashAndReset(new byte[32])).ThrowsExactly<InvalidOperationException>();
		}
	}

	// The stream ends at byte 2^64 - 1, and a read that reaches the end leaves nothing more to read.
	[Test]
	public async Task ReadStopsAtStreamEnd()
	{
		using Blake3HashAlgorithm hasher = Blake3HashAlgorithm.Create();
		byte[] expected = new byte[64];
		hasher.GetCurrentHash(expected, ulong.MaxValue - 63);

		hasher.ReadPosition = ulong.MaxValue - 63;
		byte[] actual = new byte[64];
		hasher.Read(actual.AsSpan(0, 63));
		await Assert.That(() => hasher.Read(new byte[2])).ThrowsExactly<ArgumentOutOfRangeException>();
		hasher.Read(actual.AsSpan(63));

		using (Assert.Multiple())
		{
			await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(hasher.ReadPosition).IsEqualTo(new UInt128(1, 0));
			await Assert.That(() => hasher.Read(new byte[1])).ThrowsExactly<ArgumentOutOfRangeException>();
		}

		hasher.Read(Span<byte>.Empty);
	}
}
