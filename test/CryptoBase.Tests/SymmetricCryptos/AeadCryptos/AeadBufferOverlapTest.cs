using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.SymmetricCryptos.AeadCryptos;
using CryptoBase.SymmetricCryptos.BlockCryptoModes;
using CryptoBase.SymmetricCryptos.BlockCryptos.Aes;
using System.Diagnostics.CodeAnalysis;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.SymmetricCryptos.AeadCryptos;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class AeadBufferOverlapTest
{
	private const int KeySize = 32;

	[Test]
	[Arguments(AeadAlgorithm.DefaultChaCha20Poly1305, -1)]
	[Arguments(AeadAlgorithm.DefaultChaCha20Poly1305, 1)]
	[Arguments(AeadAlgorithm.ChaCha20Poly1305, -1)]
	[Arguments(AeadAlgorithm.ChaCha20Poly1305, 1)]
	[Arguments(AeadAlgorithm.XChaCha20Poly1305, -1)]
	[Arguments(AeadAlgorithm.XChaCha20Poly1305, 1)]
	[Arguments(AeadAlgorithm.DefaultAesGcm, -1)]
	[Arguments(AeadAlgorithm.DefaultAesGcm, 1)]
	[Arguments(AeadAlgorithm.AesGcm, -1)]
	[Arguments(AeadAlgorithm.AesGcm, 1)]
	public async Task OffsetSourceDestinationOverlapsAreRejectedBeforeWriting(AeadAlgorithm algorithm, int destinationOffset)
	{
		byte[] key = CreateDeterministicSource(KeySize);
		using IAeadCrypto crypto = CreateCrypto(algorithm, key);
		byte[] nonce = CreateDeterministicSource(crypto.NonceSizeInBytes);
		byte[] associatedData = CreateDeterministicSource(29);
		byte[] plaintext = CreateDeterministicSource(73);
		byte[] ciphertext = new byte[plaintext.Length];
		byte[] tag = new byte[crypto.TagSizeInBytes];
		crypto.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

		int sourceOffset = destinationOffset < 0 ? 1 : 0;
		int outputOffset = destinationOffset > 0 ? 1 : 0;

		byte[] encryptionBuffer = new byte[plaintext.Length + 1];
		plaintext.CopyTo(encryptionBuffer.AsSpan().Slice(sourceOffset));
		byte[] encryptionBufferCopy = encryptionBuffer.ToArray();
		byte[] encryptionTag = new byte[crypto.TagSizeInBytes];
		PrepareDestination(encryptionTag);

		await Assert.That(() => crypto.Encrypt(nonce, encryptionBuffer.AsSpan().Slice(sourceOffset, plaintext.Length), encryptionBuffer.AsSpan().Slice(outputOffset, plaintext.Length), encryptionTag, associatedData)).ThrowsExactly<ArgumentException>().WithParameterName("destination");
		await Assert.That(encryptionBuffer).IsEquivalentTo(encryptionBufferCopy, CollectionOrdering.Matching);
		await Assert.That(encryptionTag).All(static value => value is DestinationSentinel);

		byte[] decryptionBuffer = new byte[ciphertext.Length + 1];
		ciphertext.CopyTo(decryptionBuffer.AsSpan().Slice(sourceOffset));
		byte[] decryptionBufferCopy = decryptionBuffer.ToArray();

		await Assert.That(() => crypto.Decrypt(nonce, decryptionBuffer.AsSpan().Slice(sourceOffset, ciphertext.Length), tag, decryptionBuffer.AsSpan().Slice(outputOffset, ciphertext.Length), associatedData)).ThrowsExactly<ArgumentException>().WithParameterName("destination");
		await Assert.That(decryptionBuffer).IsEquivalentTo(decryptionBufferCopy, CollectionOrdering.Matching);
	}

	[Test]
	[Arguments(AeadAlgorithm.DefaultChaCha20Poly1305, 29)]
	[Arguments(AeadAlgorithm.DefaultChaCha20Poly1305, 257)]
	[Arguments(AeadAlgorithm.ChaCha20Poly1305, 29)]
	[Arguments(AeadAlgorithm.XChaCha20Poly1305, 29)]
	[Arguments(AeadAlgorithm.DefaultAesGcm, 29)]
	[Arguments(AeadAlgorithm.DefaultAesGcm, 257)]
	[Arguments(AeadAlgorithm.AesGcm, 29)]
	public async Task AssociatedDataOverlappingDestinationIsConsumedBeforeWriting(AeadAlgorithm algorithm, int associatedDataSizeInBytes)
	{
		const int DestinationOffset = 7;
		byte[] key = CreateDeterministicSource(KeySize);
		using IAeadCrypto crypto = CreateCrypto(algorithm, key);
		byte[] nonce = CreateDeterministicSource(crypto.NonceSizeInBytes);
		byte[] associatedData = CreateDeterministicSource(associatedDataSizeInBytes);
		byte[] plaintext = CreateDeterministicSource(257);
		byte[] expectedCiphertext = new byte[plaintext.Length];
		byte[] expectedTag = new byte[crypto.TagSizeInBytes];
		crypto.Encrypt(nonce, plaintext, expectedCiphertext, expectedTag, associatedData);

		byte[] encryptionBuffer = new byte[DestinationOffset + plaintext.Length];
		associatedData.CopyTo(encryptionBuffer);
		byte[] actualTag = new byte[crypto.TagSizeInBytes];
		crypto.Encrypt(nonce, plaintext, encryptionBuffer.AsSpan().Slice(DestinationOffset, plaintext.Length), actualTag, encryptionBuffer.AsSpan().Slice(0, associatedData.Length));

		await Assert.That(encryptionBuffer.AsMemory(DestinationOffset)).IsEquivalentTo(expectedCiphertext, CollectionOrdering.Matching);
		await Assert.That(actualTag).IsEquivalentTo(expectedTag, CollectionOrdering.Matching);

		byte[] decryptionBuffer = new byte[DestinationOffset + plaintext.Length];
		associatedData.CopyTo(decryptionBuffer);
		crypto.Decrypt(nonce, expectedCiphertext, expectedTag, decryptionBuffer.AsSpan().Slice(DestinationOffset, plaintext.Length), decryptionBuffer.AsSpan().Slice(0, associatedData.Length));

		await Assert.That(decryptionBuffer.AsMemory(DestinationOffset)).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
	}

	[Test]
	[Arguments(AeadAlgorithm.DefaultChaCha20Poly1305)]
	[Arguments(AeadAlgorithm.ChaCha20Poly1305)]
	[Arguments(AeadAlgorithm.XChaCha20Poly1305)]
	[Arguments(AeadAlgorithm.DefaultAesGcm)]
	[Arguments(AeadAlgorithm.AesGcm)]
	public async Task TagDestinationOverlapsAreRejectedBeforeWriting(AeadAlgorithm algorithm)
	{
		const int OverlapLength = 8;
		byte[] key = CreateDeterministicSource(KeySize);
		using IAeadCrypto crypto = CreateCrypto(algorithm, key);
		byte[] nonce = CreateDeterministicSource(crypto.NonceSizeInBytes);
		byte[] associatedData = CreateDeterministicSource(29);
		byte[] plaintext = CreateDeterministicSource(73);
		byte[] ciphertext = new byte[plaintext.Length];
		byte[] tag = new byte[crypto.TagSizeInBytes];
		crypto.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

		byte[] encryptionBuffer = new byte[plaintext.Length + crypto.TagSizeInBytes - OverlapLength];
		PrepareDestination(encryptionBuffer);
		byte[] encryptionBufferCopy = encryptionBuffer.ToArray();

		await Assert.That(() => crypto.Encrypt(nonce, plaintext, encryptionBuffer.AsSpan().Slice(0, plaintext.Length), encryptionBuffer.AsSpan().Slice(plaintext.Length - OverlapLength, crypto.TagSizeInBytes), associatedData)).ThrowsExactly<ArgumentException>().WithParameterName("tag");
		await Assert.That(encryptionBuffer).IsEquivalentTo(encryptionBufferCopy, CollectionOrdering.Matching);

		byte[] decryptionBuffer = new byte[plaintext.Length + crypto.TagSizeInBytes - OverlapLength];
		PrepareDestination(decryptionBuffer);
		tag.CopyTo(decryptionBuffer.AsSpan().Slice(plaintext.Length - OverlapLength, crypto.TagSizeInBytes));
		byte[] decryptionBufferCopy = decryptionBuffer.ToArray();

		await Assert.That(() => crypto.Decrypt(nonce, ciphertext, decryptionBuffer.AsSpan().Slice(plaintext.Length - OverlapLength, crypto.TagSizeInBytes), decryptionBuffer.AsSpan().Slice(0, plaintext.Length), associatedData)).ThrowsExactly<ArgumentException>().WithParameterName("tag");
		await Assert.That(decryptionBuffer).IsEquivalentTo(decryptionBufferCopy, CollectionOrdering.Matching);
	}

	private static IAeadCrypto CreateCrypto(AeadAlgorithm algorithm, ReadOnlySpan<byte> key)
	{
		return algorithm switch
		{
			AeadAlgorithm.DefaultChaCha20Poly1305 => new DefaultChaCha20Poly1305Crypto(key),
			AeadAlgorithm.ChaCha20Poly1305 => new ChaCha20Poly1305Crypto(key),
			AeadAlgorithm.XChaCha20Poly1305 => new XChaCha20Poly1305Crypto(key),
			AeadAlgorithm.DefaultAesGcm => new DefaultAesGcmCrypto(key),
			AeadAlgorithm.AesGcm => new GcmMode128<AesCipher>(AesCipher.Create(key)),
			_ => throw new ArgumentOutOfRangeException(nameof(algorithm))
		};
	}

	public enum AeadAlgorithm
	{
		DefaultChaCha20Poly1305,
		ChaCha20Poly1305,
		XChaCha20Poly1305,
		DefaultAesGcm,
		AesGcm
	}
}
