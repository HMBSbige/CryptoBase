using CryptoBase.Abstractions.Ciphers;
using CryptoBase.Ciphers.Aead;
using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Modes.Gcm;
using System.Diagnostics.CodeAnalysis;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Ciphers.Aead;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
[GenerateGenericTest(typeof(ChaCha20Poly1305Cipher))]
[GenerateGenericTest(typeof(XChaCha20Poly1305Cipher))]
[GenerateGenericTest(typeof(GcmMode128<AesCipher>))]
public class AeadBufferOverlapTest<T> where T : IAeadCipher<T>
{
	private const int KeySize = 32;

	[Test]
	[Arguments(-1)]
	[Arguments(1)]
	public async Task OffsetSourceDestinationOverlapsAreRejectedBeforeWriting(int destinationOffset)
	{
		byte[] key = CreateDeterministicSource(KeySize);
		using T crypto = T.Create(key);
		byte[] nonce = CreateDeterministicSource(T.NonceSize);
		byte[] associatedData = CreateDeterministicSource(29);
		byte[] plaintext = CreateDeterministicSource(73);
		byte[] ciphertext = new byte[plaintext.Length];
		byte[] tag = new byte[T.TagSize];
		crypto.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

		int sourceOffset = destinationOffset < 0 ? 1 : 0;
		int outputOffset = destinationOffset > 0 ? 1 : 0;

		byte[] encryptionBuffer = new byte[plaintext.Length + 1];
		plaintext.CopyTo(encryptionBuffer.AsSpan().Slice(sourceOffset));
		byte[] encryptionBufferCopy = encryptionBuffer.ToArray();
		byte[] encryptionTag = new byte[T.TagSize];
		PrepareDestination(encryptionTag);

		await Assert.That(() => crypto.Encrypt(nonce, encryptionBuffer.AsSpan().Slice(sourceOffset, plaintext.Length), encryptionBuffer.AsSpan().Slice(outputOffset, plaintext.Length), encryptionTag, associatedData)).ThrowsExactly<ArgumentException>().WithParameterName("destination");
		await Assert.That(encryptionBuffer).IsEquivalentTo(encryptionBufferCopy, CollectionOrdering.Matching);
		await Assert.That(encryptionTag).All(static value => value is DestinationSentinel);

		byte[] decryptionBuffer = new byte[ciphertext.Length + 1];
		ciphertext.CopyTo(decryptionBuffer.AsSpan().Slice(sourceOffset));
		byte[] decryptionBufferCopy = decryptionBuffer.ToArray();

		await Assert.That(() => crypto.TryDecrypt(nonce, decryptionBuffer.AsSpan().Slice(sourceOffset, ciphertext.Length), tag, decryptionBuffer.AsSpan().Slice(outputOffset, ciphertext.Length), associatedData)).ThrowsExactly<ArgumentException>().WithParameterName("destination");
		await Assert.That(decryptionBuffer).IsEquivalentTo(decryptionBufferCopy, CollectionOrdering.Matching);
	}

	[Test]
	[Arguments(29)]
	[Arguments(255)]
	public async Task AssociatedDataOverlappingDestinationIsConsumedBeforeWriting(int associatedDataSizeInBytes)
	{
		const int destinationOffset = 7;
		byte[] key = CreateDeterministicSource(KeySize);
		using T crypto = T.Create(key);
		byte[] nonce = CreateDeterministicSource(T.NonceSize);
		byte[] associatedData = CreateDeterministicSource(associatedDataSizeInBytes);
		byte[] plaintext = CreateDeterministicSource(257);
		byte[] expectedCiphertext = new byte[plaintext.Length];
		byte[] expectedTag = new byte[T.TagSize];
		crypto.Encrypt(nonce, plaintext, expectedCiphertext, expectedTag, associatedData);

		byte[] encryptionBuffer = new byte[destinationOffset + plaintext.Length];
		associatedData.CopyTo(encryptionBuffer);
		byte[] actualTag = new byte[T.TagSize];
		crypto.Encrypt(nonce, plaintext, encryptionBuffer.AsSpan().Slice(destinationOffset, plaintext.Length), actualTag, encryptionBuffer.AsSpan().Slice(0, associatedData.Length));

		await Assert.That(encryptionBuffer.AsMemory(destinationOffset)).IsEquivalentTo(expectedCiphertext, CollectionOrdering.Matching);
		await Assert.That(actualTag).IsEquivalentTo(expectedTag, CollectionOrdering.Matching);

		byte[] decryptionBuffer = new byte[destinationOffset + plaintext.Length];
		associatedData.CopyTo(decryptionBuffer);
		await Assert.That(crypto.TryDecrypt(nonce, expectedCiphertext, expectedTag, decryptionBuffer.AsSpan().Slice(destinationOffset, plaintext.Length), decryptionBuffer.AsSpan().Slice(0, associatedData.Length))).IsTrue();

		await Assert.That(decryptionBuffer.AsMemory(destinationOffset)).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
	}

	[Test]
	public async Task TagDestinationOverlapsAreRejectedBeforeWriting()
	{
		const int overlapLength = 8;
		byte[] key = CreateDeterministicSource(KeySize);
		using T crypto = T.Create(key);
		byte[] nonce = CreateDeterministicSource(T.NonceSize);
		byte[] associatedData = CreateDeterministicSource(29);
		byte[] plaintext = CreateDeterministicSource(73);
		byte[] ciphertext = new byte[plaintext.Length];
		byte[] tag = new byte[T.TagSize];
		crypto.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

		byte[] encryptionBuffer = new byte[plaintext.Length + T.TagSize - overlapLength];
		PrepareDestination(encryptionBuffer);
		byte[] encryptionBufferCopy = encryptionBuffer.ToArray();

		await Assert.That(() => crypto.Encrypt(nonce, plaintext, encryptionBuffer.AsSpan().Slice(0, plaintext.Length), encryptionBuffer.AsSpan().Slice(plaintext.Length - overlapLength, T.TagSize), associatedData)).ThrowsExactly<ArgumentException>().WithParameterName("tag");
		await Assert.That(encryptionBuffer).IsEquivalentTo(encryptionBufferCopy, CollectionOrdering.Matching);

		byte[] decryptionBuffer = new byte[plaintext.Length + T.TagSize - overlapLength];
		PrepareDestination(decryptionBuffer);
		tag.CopyTo(decryptionBuffer.AsSpan().Slice(plaintext.Length - overlapLength, T.TagSize));
		byte[] decryptionBufferCopy = decryptionBuffer.ToArray();

		await Assert.That(() => crypto.TryDecrypt(nonce, ciphertext, decryptionBuffer.AsSpan().Slice(plaintext.Length - overlapLength, T.TagSize), decryptionBuffer.AsSpan().Slice(0, plaintext.Length), associatedData)).ThrowsExactly<ArgumentException>().WithParameterName("tag");
		await Assert.That(decryptionBuffer).IsEquivalentTo(decryptionBufferCopy, CollectionOrdering.Matching);
	}
}
