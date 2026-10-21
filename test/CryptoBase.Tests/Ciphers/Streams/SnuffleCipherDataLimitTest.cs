using CryptoBase.Ciphers.Streams;
using System.Diagnostics.CodeAnalysis;
using static CryptoBase.Tests.Ciphers.Streams.SnuffleCipherTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Ciphers.Streams;

public class SnuffleCipherDataLimitTest
{
	[Test]
	[MethodDataSource(typeof(SnuffleCipherTestUtils), nameof(CipherCases))]
	[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
	public async Task CounterLimitRejectsWholeOperationWithoutAdvancingState(SnuffleCase cipher)
	{
		using SnuffleCipher crypto = cipher.Create();
		using SnuffleCipher oracle = cipher.Create();
		ulong penultimateCounter = cipher.MaxCounter - 1;
		byte[] source = CreateDeterministicSource(129);
		byte[] destination = new byte[source.Length];
		byte[] expected = new byte[128];

		SetCounter(crypto, penultimateCounter);
		PrepareDestination(destination);
		await Assert.That(() => crypto.Xor(source, destination)).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(destination).All(static value => value is DestinationSentinel);

		// The bulk path reaches the final counter block; the byte-wise oracle uses the single-block path.
		SetCounter(oracle, penultimateCounter);
		crypto.Xor(source.AsSpan().Slice(0, 128), destination);

		for (int i = 0; i < expected.Length; ++i)
		{
			oracle.Xor(source.AsSpan(i, 1), expected.AsSpan(i, 1));
		}

		await Assert.That(destination.AsMemory(0, 128)).IsEquivalentTo(expected, CollectionOrdering.Matching);

		await Assert.That(() => crypto.Xor(source.AsSpan().Slice(128), destination.AsSpan().Slice(128))).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(destination[128]).IsEqualTo(DestinationSentinel);
		crypto.Xor(ReadOnlySpan<byte>.Empty, Span<byte>.Empty);

		// The rewound stream must still use the original nonce.
		SetCounter(crypto, 0);
		SetCounter(oracle, 0);
		expected = new byte[source.Length];
		crypto.Xor(source, destination);
		oracle.Xor(source, expected);
		await Assert.That(destination).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}
}
