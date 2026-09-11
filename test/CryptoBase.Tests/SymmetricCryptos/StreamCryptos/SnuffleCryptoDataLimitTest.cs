using CryptoBase.SymmetricCryptos.StreamCryptos;
using System.Diagnostics.CodeAnalysis;
using static CryptoBase.Tests.SymmetricCryptos.StreamCryptos.SnuffleCryptoTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.SymmetricCryptos.StreamCryptos;

public class SnuffleCryptoDataLimitTest
{
	[Test]
	[Arguments(SnuffleAlgorithm.ChaCha20)]
	[Arguments(SnuffleAlgorithm.ChaCha20Original)]
	[Arguments(SnuffleAlgorithm.XChaCha20)]
	[Arguments(SnuffleAlgorithm.Salsa20)]
	[Arguments(SnuffleAlgorithm.XSalsa20)]
	[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
	public async Task CounterLimitRejectsWholeOperationWithoutAdvancingState(SnuffleAlgorithm algorithm)
	{
		using SnuffleCrypto crypto = Create(algorithm);
		using SnuffleCrypto oracle = Create(algorithm);
		ulong penultimateCounter = algorithm is SnuffleAlgorithm.ChaCha20 ? uint.MaxValue - 1U : ulong.MaxValue - 1;
		byte[] source = CreateDeterministicSource(65);
		byte[] destination = new byte[source.Length];
		byte[] expected = new byte[64];

		SetCounter(crypto, penultimateCounter);
		destination.AsSpan().Fill(DestinationSentinel);
		await Assert.That(() => crypto.Update(source, destination)).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(destination).All(static value => value is DestinationSentinel);

		SetCounter(oracle, penultimateCounter);
		crypto.Update(source.AsSpan().Slice(0, 64), destination);
		oracle.Update(source.AsSpan().Slice(0, 64), expected);
		await Assert.That(destination.AsMemory(0, 64)).IsEquivalentTo(expected, CollectionOrdering.Matching);

		destination[64] = DestinationSentinel;
		await Assert.That(() => crypto.Update(source.AsSpan().Slice(64), destination.AsSpan().Slice(64)))
			.ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(destination[64]).IsEqualTo(DestinationSentinel);

		crypto.Reset();
		oracle.Reset();
		expected = new byte[source.Length];
		crypto.Update(source, destination);
		oracle.Update(source, expected);
		await Assert.That(destination).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	private static void SetCounter(SnuffleCrypto crypto, ulong counter)
	{
		switch (crypto)
		{
			case ChaCha20Crypto chaCha20:
				chaCha20.SetCounter(checked((uint)counter));
				break;
			case Salsa20Crypto salsa20:
				salsa20.SetCounter(counter);
				break;
			case ChaCha20OriginalCrypto chaCha20Original:
				chaCha20Original.SetCounter(counter);
				break;
			default:
				throw new ArgumentOutOfRangeException(nameof(crypto));
		}
	}
}
