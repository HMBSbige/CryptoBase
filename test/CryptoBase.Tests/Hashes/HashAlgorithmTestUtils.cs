using CryptoBase.Abstractions.Hashes;
using CryptoBase.Hashes;
using System.Text;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hashes;

internal static class HashAlgorithmTestUtils
{
	private const int DirectBatchLength = 1024;

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

	internal static async Task VerifyHashVector<T>(string value, string expected, int expectedHashLength) where T : unmanaged, IHashCore<T>
	{
		await Assert.That(T.HashLength).IsEqualTo(expectedHashLength);

		byte[] source = Encoding.UTF8.GetBytes(value);
		byte[] expectedHash = Convert.FromHexString(expected);
		byte[] destination = CreateDestination<T>();

		PrepareDestination(destination);
		int written = HashAlgorithm<T>.HashData(source, destination);
		await AssertOutput(destination, expectedHash, written);

		using HashAlgorithm<T> hashAlgorithm = HashAlgorithm<T>.Create();
		hashAlgorithm.Append(source);
		PrepareDestination(destination);
		written = hashAlgorithm.GetCurrentHash(destination);
		await AssertOutput(destination, expectedHash, written);

		PrepareDestination(destination);
		written = hashAlgorithm.GetHashAndReset(destination);
		await AssertOutput(destination, expectedHash, written);

		AppendInFixedChunks(hashAlgorithm, source, 1);
		PrepareDestination(destination);
		written = hashAlgorithm.GetHashAndReset(destination);
		await AssertOutput(destination, expectedHash, written);
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
		byte[] source = CreateDeterministicSource(length);
		return VerifyBoundary<T>(source, oracle(source));
	}

	internal static Task VerifyBoundary<T>(int length, string expectedHex) where T : unmanaged, IHashCore<T>
	{
		return VerifyBoundary<T>(CreateDeterministicSource(length), Convert.FromHexString(expectedHex));
	}

	internal static async Task VerifyIncrementalBlockBatch<T>(int length, int sourceOffset, int blockSize, Func<byte[], byte[]> oracle) where T : unmanaged, IHashCore<T>
	{
		byte[] payload = CreateDeterministicSource(length);
		byte[] expected = oracle(payload);
		byte[] source = new byte[sourceOffset + payload.Length + 17];
		source.AsSpan().Fill(DestinationSentinel);
		payload.CopyTo(source.AsSpan().Slice(sourceOffset, payload.Length));
		byte[] sourceCopy = (byte[])source.Clone();
		byte[] destination = CreateDestination<T>();

		using HashAlgorithm<T> hashAlgorithm = HashAlgorithm<T>.Create();

		if (blockSize is 0)
		{
			hashAlgorithm.Append(source.AsSpan().Slice(sourceOffset, payload.Length));
		}
		else
		{
			int firstLength = blockSize - 1;
			int middleLength = DirectBatchLength + 1;
			hashAlgorithm.Append(source.AsSpan().Slice(sourceOffset, firstLength));
			hashAlgorithm.Append(source.AsSpan().Slice(sourceOffset + firstLength, middleLength));
			hashAlgorithm.Append(source.AsSpan().Slice(sourceOffset + firstLength + middleLength, 1));
		}

		PrepareDestination(destination);
		int written = hashAlgorithm.GetHashAndReset(destination);

		await AssertOutput(destination, expected, written);
		await Assert.That(source).IsEquivalentTo(sourceCopy, CollectionOrdering.Matching);
	}

	internal static byte[] CreateDestination<T>() where T : unmanaged, IIncrementalHashCore
	{
		return new byte[T.HashLength + 1];
	}

	internal static async Task VerifyBoundary<T>(ReadOnlyMemory<byte> source, byte[] expected) where T : unmanaged, IHashCore<T>
	{
		byte[] destination = CreateDestination<T>();

		PrepareDestination(destination);
		int written = HashAlgorithm<T>.HashData(source.Span, destination);
		await AssertOutput(destination, expected, written);

		using HashAlgorithm<T> hashAlgorithm = HashAlgorithm<T>.Create();
		hashAlgorithm.Append(source.Span);
		PrepareDestination(destination);
		written = hashAlgorithm.GetCurrentHash(destination);
		await AssertOutput(destination, expected, written);

		hashAlgorithm.Reset();
		AppendInFixedChunks(hashAlgorithm, source.Span, 13);
		PrepareDestination(destination);
		written = hashAlgorithm.GetCurrentHash(destination);
		await AssertOutput(destination, expected, written);

		hashAlgorithm.Reset();
		AppendInPseudoRandomChunks(hashAlgorithm, source.Span, (uint)source.Length + 1);
		PrepareDestination(destination);
		written = hashAlgorithm.GetHashAndReset(destination);
		await AssertOutput(destination, expected, written);
	}

	internal static async Task VerifyInputIsUnchanged<T>(int length, int offset) where T : unmanaged, IHashCore<T>
	{
		byte[] destination = new byte[T.HashLength];
		byte[] source = CreateDeterministicSource(offset + length + 17);
		byte[] sourceCopy = (byte[])source.Clone();

		using HashAlgorithm<T> hashAlgorithm = HashAlgorithm<T>.Create();
		hashAlgorithm.Append(source.AsSpan().Slice(offset, length));
		await Assert.That(source).IsEquivalentTo(sourceCopy, CollectionOrdering.Matching);

		hashAlgorithm.GetCurrentHash(destination);
		await Assert.That(source).IsEquivalentTo(sourceCopy, CollectionOrdering.Matching);
		hashAlgorithm.GetHashAndReset(destination);
		await Assert.That(source).IsEquivalentTo(sourceCopy, CollectionOrdering.Matching);

		HashAlgorithm<T>.HashData(source.AsSpan().Slice(offset, length), destination);
		await Assert.That(source).IsEquivalentTo(sourceCopy, CollectionOrdering.Matching);
	}

	private static void AppendInPseudoRandomChunks<T>(T hashAlgorithm, ReadOnlySpan<byte> source, uint state, int maximumChunkLength = 23) where T : class, IHashAlgorithm<T>
	{
		ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumChunkLength);

		if (source.IsEmpty)
		{
			hashAlgorithm.Append(source);
			return;
		}

		while (!source.IsEmpty)
		{
			state = state * 1664525U + 1013904223U;
			int length = Math.Min((int)(state % (uint)maximumChunkLength) + 1, source.Length);
			hashAlgorithm.Append(source.Slice(0, length));
			source = source.Slice(length);
		}
	}

	private static void AppendInFixedChunks<T>(HashAlgorithm<T> hashAlgorithm, ReadOnlySpan<byte> source, int chunkSize) where T : unmanaged, IHashCore<T>
	{
		if (source.IsEmpty)
		{
			hashAlgorithm.Append(source);
			return;
		}

		while (!source.IsEmpty)
		{
			int length = Math.Min(chunkSize, source.Length);
			hashAlgorithm.Append(source.Slice(0, length));
			source = source.Slice(length);
		}
	}
}
