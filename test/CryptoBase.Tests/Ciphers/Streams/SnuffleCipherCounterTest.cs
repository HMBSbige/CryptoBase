using CryptoBase.Ciphers.Streams;
using static CryptoBase.Tests.Ciphers.Streams.SnuffleCipherTestUtils;

namespace CryptoBase.Tests.Ciphers.Streams;

public class SnuffleCipherCounterTest
{
	[Test]
	[CombinedDataSources]
	public async Task BulkProcessingMatchesByteWiseAtLowCounterBoundary
	(
		[MethodDataSource(typeof(SnuffleCipherTestUtils), nameof(CipherCases))]
		SnuffleCase cipher,
		[Arguments(1, 4, 5, 6, 7, 8, 9, 10, 11, 12, 15, 16, 17, 20, 24, 31, 32, 64)]
		int blocksBeforeCarry
	)
	{
		byte[] source = TestUtils.CreateDeterministicSource(4097);
		byte[] expected = new byte[source.Length];
		byte[] actual = new byte[source.Length];
		using SnuffleCipher byteWise = cipher.Create();
		using SnuffleCipher bulk = cipher.Create();

		// The IETF variant stops at this implementation's 32-bit counter limit.
		// The 64-bit variants cross the low-word carry at different SIMD batch positions.
		ulong counter = (1UL << 32) - (ulong)blocksBeforeCarry;
		int length = cipher.MaxCounter is uint.MaxValue ? (blocksBeforeCarry - 1) * 64 : source.Length;
		SetCounter(byteWise, counter);
		SetCounter(bulk, counter);

		for (int i = 0; i < length; ++i)
		{
			byteWise.Xor(source.AsSpan(i, 1), expected.AsSpan(i, 1));
		}

		bulk.Xor(source.AsSpan(0, length), actual);
		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	[MethodDataSource(typeof(SnuffleCipherTestUtils), nameof(CipherCases))]
	public async Task SetCounterMatchesSequentialStreamAfterPartialBlocks(SnuffleCase cipher)
	{
		using SnuffleCipher oracle = cipher.Create();
		byte[] expected = new byte[321];
		oracle.Xor(new byte[expected.Length], expected);
		byte[] source = new byte[129];
		byte[] actual = new byte[source.Length];

		foreach (int consumed in new[] { 1, 63, 64, 65 })
		{
			using SnuffleCipher crypto = cipher.Create();
			crypto.Xor(source.AsSpan().Slice(0, consumed), actual);

			foreach (ulong counter in new ulong[] { 3, 1, 1, 0 })
			{
				SetCounter(crypto, counter);
				crypto.Xor(source.AsSpan().Slice(0, 1), actual);
				crypto.Xor(source.AsSpan().Slice(1), actual.AsSpan().Slice(1));

				byte[] expectedSegment = expected.AsSpan().Slice((int)counter * 64, actual.Length).ToArray();
				await Assert.That(actual).IsEquivalentTo(expectedSegment, CollectionOrdering.Matching);
			}
		}
	}
}
