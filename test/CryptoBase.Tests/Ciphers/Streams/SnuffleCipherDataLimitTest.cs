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
		byte[] source = CreateDeterministicSource(65);
		byte[] destination = new byte[source.Length];
		byte[] expected = new byte[64];

		SetCounter(crypto, penultimateCounter);
		destination.AsSpan().Fill(DestinationSentinel);
		await Assert.That(() => crypto.Xor(source, destination)).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(destination).All(static value => value is DestinationSentinel);

		SetCounter(oracle, penultimateCounter);
		crypto.Xor(source.AsSpan().Slice(0, 64), destination);
		oracle.Xor(source.AsSpan().Slice(0, 64), expected);
		await Assert.That(destination.AsMemory(0, 64)).IsEquivalentTo(expected, CollectionOrdering.Matching);

		destination[64] = DestinationSentinel;
		await Assert.That(() => crypto.Xor(source.AsSpan().Slice(64), destination.AsSpan().Slice(64))).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(destination[64]).IsEqualTo(DestinationSentinel);

		SetCounter(crypto, 0);
		SetCounter(oracle, 0);
		expected = new byte[source.Length];
		crypto.Xor(source, destination);
		oracle.Xor(source, expected);
		await Assert.That(destination).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}
}
