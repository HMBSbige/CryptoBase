using CryptoBase.Abstractions.Hashes;
using CryptoBase.Hashes;
using System.Text;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hashes;

internal static class HashAlgorithmTestUtils
{
	internal const int DirectBatchLength = 1024;

	private static readonly int[] BatchBoundaryLengths = [511, 512, 513, 1023, 1024, 1025];
	private static readonly int[] SourceOffsets = [1, 15, 31, 63];

	public static IEnumerable<int> Hash64BlockAndPaddingLengths =>
	[
		0, 1,
		54, 55, 56,
		63, 64, 65,
		118, 119, 120,
		127, 128, 129,
		255, 256, 257,
		511, 512, 513
	];

	public static IEnumerable<int> Hash128BlockAndPaddingLengths =>
	[
		0, 1,
		110, 111, 112,
		127, 128, 129,
		238, 239, 240,
		255, 256, 257
	];

	public static IEnumerable<int> InputIntegrityLengths =>
	[
		0, 1,
		63, 64, 65,
		127, 128, 129,
		511, 512, 513, 527, 528,
		1023, 1024, 1025
	];

	public static IEnumerable<(int, int, int)> Hash64IncrementalBatchCases()
	{
		return HashIncrementalBatchCases(64);
	}

	public static IEnumerable<(int, int, int)> Hash128IncrementalBatchCases()
	{
		return HashIncrementalBatchCases(128);
	}

	private static IEnumerable<(int, int, int)> HashIncrementalBatchCases(int blockSize)
	{
		foreach (int length in BatchBoundaryLengths)
		{
			foreach (int sourceOffset in SourceOffsets)
			{
				yield return (length, sourceOffset, 0);
			}
		}

		yield return (blockSize + DirectBatchLength + 1, 31, blockSize);
	}

	internal static Task VerifyHashVector<T>(string value, string expected, int expectedHashLength) where T : unmanaged, IHashCore<T>
	{
		return HashAlgorithmTestUtils<HashAlgorithm<T>>.VerifyHashVector(value, expected, expectedHashLength);
	}

	internal static async Task VerifyHashVector<T>(string value, string expected, int expectedHashLength, int expectedBlockSize) where T : unmanaged, IHmacHashCore<T>
	{
		await Assert.That(T.HmacBlockSize).IsEqualTo(expectedBlockSize);
		await VerifyHashVector<T>(value, expected, expectedHashLength);
	}

	internal static byte[] GetKnownDigest(byte[] source, IEnumerable<(int Length, string ExpectedHex)> vectors, string algorithmName)
	{
		foreach ((int length, string expectedHex) in vectors)
		{
			if (source.Length == length)
			{
				return Convert.FromHexString(expectedHex);
			}
		}

		throw new InvalidOperationException($@"No {algorithmName} test vector for a {source.Length}-byte source.");
	}

	internal static Task VerifyBoundary<T>(int length, Func<byte[], byte[]> oracle) where T : unmanaged, IHashCore<T>
	{
		return HashAlgorithmTestUtils<HashAlgorithm<T>>.VerifyBoundary(length, oracle);
	}

	internal static Task VerifyBoundary<T>(int length, string expectedHex) where T : unmanaged, IHashCore<T>
	{
		return HashAlgorithmTestUtils<HashAlgorithm<T>>.VerifyBoundary(length, expectedHex);
	}

	internal static Task VerifyIncrementalBlockBatch<T>(int length, int sourceOffset, int blockSize, Func<byte[], byte[]> oracle) where T : unmanaged, IHashCore<T>
	{
		return HashAlgorithmTestUtils<HashAlgorithm<T>>.VerifyIncrementalBlockBatch(length, sourceOffset, blockSize, oracle);
	}

	internal static byte[] CreateDestination<T>() where T : unmanaged, IIncrementalHashCore
	{
		return new byte[T.HashLength + 1];
	}

	internal static Task VerifyBoundary<T>(ReadOnlyMemory<byte> source, byte[] expected) where T : unmanaged, IHashCore<T>
	{
		return HashAlgorithmTestUtils<HashAlgorithm<T>>.VerifyBoundary(source, expected);
	}

	internal static Task VerifyOverlappingHashData<T>(byte[] source, byte[] expected) where T : unmanaged, IHashCore<T>
	{
		return HashAlgorithmTestUtils<HashAlgorithm<T>>.VerifyOverlappingHashData(source, expected);
	}

	internal static async Task VerifyOverlappingHashData(byte[] source, byte[] expected, Func<ReadOnlySpan<byte>, Span<byte>, int> hashData)
	{
		foreach ((int sourceOffset, int destinationOffset) in new[] { (0, 0), (0, 17), (17, 0), (0, source.Length - 1) })
		{
			byte[] buffer = new byte[Math.Max(sourceOffset + source.Length, destinationOffset + expected.Length) + 1];
			PrepareDestination(buffer);
			source.CopyTo(buffer.AsSpan().Slice(sourceOffset));
			byte[] expectedBuffer = (byte[])buffer.Clone();
			expected.CopyTo(expectedBuffer.AsSpan().Slice(destinationOffset));

			int written = hashData(buffer.AsSpan().Slice(sourceOffset, source.Length), buffer.AsSpan().Slice(destinationOffset));

			await Assert.That(written).IsEqualTo(expected.Length);
			await Assert.That(buffer).IsEquivalentTo(expectedBuffer, CollectionOrdering.Matching);
		}
	}

	internal static Task VerifyInputIsUnchanged<T>(int length, int offset) where T : unmanaged, IHashCore<T>
	{
		return HashAlgorithmTestUtils<HashAlgorithm<T>>.VerifyInputIsUnchanged(length, offset);
	}

	internal static void AppendInPieces<TAlgorithm>(TAlgorithm hashAlgorithm, ReadOnlySpan<byte> source, int pieceLength) where TAlgorithm : class, IHashAlgorithm<TAlgorithm>
	{
		ArgumentOutOfRangeException.ThrowIfNegativeOrZero(pieceLength);

		do
		{
			int length = Math.Min(pieceLength, source.Length);
			hashAlgorithm.Append(source.Slice(0, length));
			source = source.Slice(length);
		} while (!source.IsEmpty);
	}

	internal static void AppendInPseudoRandomPieces<TAlgorithm>(TAlgorithm hashAlgorithm, ReadOnlySpan<byte> source, uint state, int maximumPieceLength = 23) where TAlgorithm : class, IHashAlgorithm<TAlgorithm>
	{
		ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumPieceLength);

		do
		{
			state = state * 1664525U + 1013904223U;
			int length = Math.Min((int)(state % (uint)maximumPieceLength) + 1, source.Length);
			hashAlgorithm.Append(source.Slice(0, length));
			source = source.Slice(length);
		} while (!source.IsEmpty);
	}
}

internal static class HashAlgorithmTestUtils<TAlgorithm> where TAlgorithm : class, IHashAlgorithm<TAlgorithm>
{
	internal static async Task VerifyHashVector(string value, string expected, int expectedHashLength)
	{
		await Assert.That(TAlgorithm.HashLength).IsEqualTo(expectedHashLength);

		byte[] source = Encoding.UTF8.GetBytes(value);
		byte[] expectedHash = Convert.FromHexString(expected);
		byte[] destination = CreateDestination();

		PrepareDestination(destination);
		int written = TAlgorithm.HashData(source, destination);
		await AssertOutput(destination, expectedHash, written);

		using TAlgorithm hashAlgorithm = TAlgorithm.Create();
		hashAlgorithm.Append(source);
		PrepareDestination(destination);
		written = hashAlgorithm.GetCurrentHash(destination);
		await AssertOutput(destination, expectedHash, written);

		PrepareDestination(destination);
		written = hashAlgorithm.GetHashAndReset(destination);
		await AssertOutput(destination, expectedHash, written);

		HashAlgorithmTestUtils.AppendInPieces(hashAlgorithm, source, 1);
		PrepareDestination(destination);
		written = hashAlgorithm.GetHashAndReset(destination);
		await AssertOutput(destination, expectedHash, written);
	}

	internal static Task VerifyBoundary(int length, Func<byte[], byte[]> oracle)
	{
		byte[] source = CreateDeterministicSource(length);
		return VerifyBoundary(source, oracle(source));
	}

	internal static Task VerifyBoundary(int length, string expectedHex)
	{
		return VerifyBoundary(CreateDeterministicSource(length), Convert.FromHexString(expectedHex));
	}

	internal static async Task VerifyIncrementalBlockBatch(int length, int sourceOffset, int blockSize, Func<byte[], byte[]> oracle)
	{
		byte[] payload = CreateDeterministicSource(length);
		byte[] expected = oracle(payload);
		byte[] source = new byte[sourceOffset + payload.Length + 17];
		source.AsSpan().Fill(DestinationSentinel);
		payload.CopyTo(source.AsSpan().Slice(sourceOffset, payload.Length));
		byte[] sourceCopy = (byte[])source.Clone();
		byte[] destination = CreateDestination();

		using TAlgorithm hashAlgorithm = TAlgorithm.Create();

		if (blockSize is 0)
		{
			hashAlgorithm.Append(source.AsSpan().Slice(sourceOffset, payload.Length));
		}
		else
		{
			int firstLength = blockSize - 1;
			int middleLength = HashAlgorithmTestUtils.DirectBatchLength + 1;
			hashAlgorithm.Append(source.AsSpan().Slice(sourceOffset, firstLength));
			hashAlgorithm.Append(source.AsSpan().Slice(sourceOffset + firstLength, middleLength));
			hashAlgorithm.Append(source.AsSpan().Slice(sourceOffset + firstLength + middleLength, 1));
		}

		PrepareDestination(destination);
		int written = hashAlgorithm.GetHashAndReset(destination);

		await AssertOutput(destination, expected, written);
		await Assert.That(source).IsEquivalentTo(sourceCopy, CollectionOrdering.Matching);
	}

	internal static byte[] CreateDestination()
	{
		return new byte[TAlgorithm.HashLength + 1];
	}

	internal static async Task VerifyBoundary(ReadOnlyMemory<byte> source, byte[] expected)
	{
		byte[] destination = CreateDestination();

		PrepareDestination(destination);
		int written = TAlgorithm.HashData(source.Span, destination);
		await AssertOutput(destination, expected, written);

		using TAlgorithm hashAlgorithm = TAlgorithm.Create();
		hashAlgorithm.Append(source.Span);
		PrepareDestination(destination);
		written = hashAlgorithm.GetCurrentHash(destination);
		await AssertOutput(destination, expected, written);

		hashAlgorithm.Reset();
		HashAlgorithmTestUtils.AppendInPieces(hashAlgorithm, source.Span, 13);
		PrepareDestination(destination);
		written = hashAlgorithm.GetCurrentHash(destination);
		await AssertOutput(destination, expected, written);

		hashAlgorithm.Reset();
		HashAlgorithmTestUtils.AppendInPseudoRandomPieces(hashAlgorithm, source.Span, (uint)source.Length + 1);
		PrepareDestination(destination);
		written = hashAlgorithm.GetHashAndReset(destination);
		await AssertOutput(destination, expected, written);
	}

	internal static Task VerifyOverlappingHashData(byte[] source, byte[] expected)
	{
		return HashAlgorithmTestUtils.VerifyOverlappingHashData(source, expected, static (input, output) => TAlgorithm.HashData(input, output));
	}

	internal static async Task VerifyInputIsUnchanged(int length, int offset)
	{
		byte[] destination = new byte[TAlgorithm.HashLength];
		byte[] source = CreateDeterministicSource(offset + length + 17);
		byte[] sourceCopy = (byte[])source.Clone();

		using TAlgorithm hashAlgorithm = TAlgorithm.Create();
		hashAlgorithm.Append(source.AsSpan().Slice(offset, length));
		await Assert.That(source).IsEquivalentTo(sourceCopy, CollectionOrdering.Matching);

		hashAlgorithm.GetCurrentHash(destination);
		await Assert.That(source).IsEquivalentTo(sourceCopy, CollectionOrdering.Matching);
		hashAlgorithm.GetHashAndReset(destination);
		await Assert.That(source).IsEquivalentTo(sourceCopy, CollectionOrdering.Matching);

		TAlgorithm.HashData(source.AsSpan().Slice(offset, length), destination);
		await Assert.That(source).IsEquivalentTo(sourceCopy, CollectionOrdering.Matching);
	}
}
