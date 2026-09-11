using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.SymmetricCryptos.StreamCryptos;
using System.Diagnostics.CodeAnalysis;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.SymmetricCryptos.StreamCryptos;

public class StreamCryptoContractTest
{
	[Test]
	[Arguments(StreamAlgorithm.RC4)]
	[Arguments(StreamAlgorithm.ChaCha20)]
	[Arguments(StreamAlgorithm.ChaCha20Original)]
	[Arguments(StreamAlgorithm.XChaCha20)]
	[Arguments(StreamAlgorithm.Salsa20)]
	[Arguments(StreamAlgorithm.XSalsa20)]
	[Arguments(StreamAlgorithm.AesCtr)]
	[Arguments(StreamAlgorithm.SM4Ctr)]
	[Arguments(StreamAlgorithm.AesCfb)]
	[Arguments(StreamAlgorithm.SM4Cfb)]
	[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
	public async Task RejectedDestinationDoesNotAdvanceStateOrWrite(StreamAlgorithm algorithm)
	{
		using IStreamCrypto subject = Create(algorithm);
		using IStreamCrypto oracle = Create(algorithm);
		byte[] source = CreateDeterministicSource(65);
		byte[] shortDestination = new byte[source.Length - 1];
		shortDestination.AsSpan().Fill(DestinationSentinel);

		await Assert.That(() => subject.Update(source, shortDestination)).ThrowsExactly<ArgumentOutOfRangeException>();

		await Assert.That(shortDestination).All(static value => value is DestinationSentinel);
		byte[] actual = new byte[source.Length];
		byte[] expected = new byte[source.Length];
		subject.Update(source, actual);
		oracle.Update(source, expected);
		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	[Arguments(StreamAlgorithm.RC4)]
	[Arguments(StreamAlgorithm.ChaCha20)]
	[Arguments(StreamAlgorithm.ChaCha20Original)]
	[Arguments(StreamAlgorithm.XChaCha20)]
	[Arguments(StreamAlgorithm.Salsa20)]
	[Arguments(StreamAlgorithm.XSalsa20)]
	[Arguments(StreamAlgorithm.AesCtr)]
	[Arguments(StreamAlgorithm.SM4Ctr)]
	[Arguments(StreamAlgorithm.AesCfb)]
	[Arguments(StreamAlgorithm.SM4Cfb)]
	public async Task ExactInPlaceOperationMatchesSeparateDestination(StreamAlgorithm algorithm)
	{
		using IStreamCrypto inPlace = Create(algorithm);
		using IStreamCrypto separate = Create(algorithm);
		byte[] source = CreateDeterministicSource(129);
		byte[] inPlaceBuffer = (byte[])source.Clone();
		byte[] expected = new byte[source.Length];

		inPlace.Update(inPlaceBuffer, inPlaceBuffer);
		separate.Update(source, expected);

		await Assert.That(inPlaceBuffer).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	public async Task RC4RejectsEmptyKey()
	{
		await Assert.That(CreateRC4WithEmptyKey).ThrowsExactly<ArgumentOutOfRangeException>();
	}

	[Test]
	public async Task SnuffleConstructorsRejectInvalidKeyAndNonceLengths()
	{
		await Assert.That(CreateChaCha20WithInvalidKey).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(CreateChaCha20WithInvalidNonce).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(CreateChaCha20OriginalWithInvalidKey).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(CreateChaCha20OriginalWithInvalidNonce).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(CreateXChaCha20WithInvalidKey).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(CreateXChaCha20WithInvalidNonce).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(CreateSalsa20WithInvalidKey).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(CreateSalsa20WithInvalidNonce).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(CreateXSalsa20WithInvalidKey).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(CreateXSalsa20WithInvalidNonce).ThrowsExactly<ArgumentOutOfRangeException>();
	}

	[Test]
	public async Task SM4CfbFactoryMatchesKnownFirstBlock()
	{
		byte[] keyAndIv = Convert.FromHexString("0123456789abcdeffedcba9876543210");
		byte[] plaintext = new byte[16];
		byte[] ciphertext = new byte[16];
		using IStreamCrypto encryptor = StreamCryptoCreate.SM4Cfb(true, keyAndIv, keyAndIv);
		using IStreamCrypto decryptor = StreamCryptoCreate.SM4Cfb(false, keyAndIv, keyAndIv);

		encryptor.Update(plaintext, ciphertext);

		await Assert.That(Convert.ToHexString(ciphertext)).IsEqualTo("681EDF34D206965E86B3E94F536E4246");
		decryptor.Update(ciphertext, ciphertext);
		await Assert.That(ciphertext).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
	}

	public enum StreamAlgorithm
	{
		RC4,
		ChaCha20,
		ChaCha20Original,
		XChaCha20,
		Salsa20,
		XSalsa20,
		AesCtr,
		SM4Ctr,
		AesCfb,
		SM4Cfb
	}

	private static IStreamCrypto Create(StreamAlgorithm algorithm)
	{
		byte[] key32 = CreateDeterministicSource(32);
		byte[] key16 = key32.AsSpan(0, 16).ToArray();

		return algorithm switch
		{
			StreamAlgorithm.RC4 => new RC4Crypto(key16),
			StreamAlgorithm.ChaCha20 => new ChaCha20Crypto(key32, CreateDeterministicSource(12)),
			StreamAlgorithm.ChaCha20Original => new ChaCha20OriginalCrypto(key32, CreateDeterministicSource(8)),
			StreamAlgorithm.XChaCha20 => new XChaCha20Crypto(key32, CreateDeterministicSource(24)),
			StreamAlgorithm.Salsa20 => new Salsa20Crypto(key32, CreateDeterministicSource(8)),
			StreamAlgorithm.XSalsa20 => new XSalsa20Crypto(key32, CreateDeterministicSource(24)),
			StreamAlgorithm.AesCtr => StreamCryptoCreate.AesCtr(key32, CreateDeterministicSource(16)),
			StreamAlgorithm.SM4Ctr => StreamCryptoCreate.SM4Ctr(key16, CreateDeterministicSource(16)),
			StreamAlgorithm.AesCfb => StreamCryptoCreate.AesCfb(true, key32, CreateDeterministicSource(16)),
			StreamAlgorithm.SM4Cfb => StreamCryptoCreate.SM4Cfb(true, key16, CreateDeterministicSource(16)),
			_ => throw new ArgumentOutOfRangeException(nameof(algorithm))
		};
	}

	private static void CreateRC4WithEmptyKey()
	{
		new RC4Crypto([]).Dispose();
	}

	private static void CreateChaCha20WithInvalidKey()
	{
		new ChaCha20Crypto(new byte[31], new byte[12]).Dispose();
	}

	private static void CreateChaCha20WithInvalidNonce()
	{
		new ChaCha20Crypto(new byte[32], new byte[11]).Dispose();
	}

	private static void CreateChaCha20OriginalWithInvalidKey()
	{
		new ChaCha20OriginalCrypto(new byte[24], new byte[8]).Dispose();
	}

	private static void CreateChaCha20OriginalWithInvalidNonce()
	{
		new ChaCha20OriginalCrypto(new byte[32], new byte[7]).Dispose();
	}

	private static void CreateXChaCha20WithInvalidKey()
	{
		new XChaCha20Crypto(new byte[31], new byte[24]).Dispose();
	}

	private static void CreateXChaCha20WithInvalidNonce()
	{
		new XChaCha20Crypto(new byte[32], new byte[23]).Dispose();
	}

	private static void CreateSalsa20WithInvalidKey()
	{
		new Salsa20Crypto(new byte[24], new byte[8]).Dispose();
	}

	private static void CreateSalsa20WithInvalidNonce()
	{
		new Salsa20Crypto(new byte[32], new byte[7]).Dispose();
	}

	private static void CreateXSalsa20WithInvalidKey()
	{
		new XSalsa20Crypto(new byte[31], new byte[24]).Dispose();
	}

	private static void CreateXSalsa20WithInvalidNonce()
	{
		new XSalsa20Crypto(new byte[32], new byte[23]).Dispose();
	}
}
