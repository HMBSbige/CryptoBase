using CryptoBase.Abstractions.Ciphers;
using CryptoBase.Ciphers.Aead;
using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Blocks.SM4;
using CryptoBase.Ciphers.Modes;
using System.Diagnostics.CodeAnalysis;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Ciphers.Aead;

[InheritsTests]
public class AesGcmBufferOverlapTest() : AeadBufferOverlapTest<GcmMode128<AesCipher>>(32);

[InheritsTests]
public class SM4GcmBufferOverlapTest() : AeadBufferOverlapTest<GcmMode128<SM4Cipher>>(16);

[InheritsTests]
public class AesCcmBufferOverlapTest() : AeadBufferOverlapTest<CcmMode128<AesCipher>>(32);

[InheritsTests]
public class SM4CcmBufferOverlapTest() : AeadBufferOverlapTest<CcmMode128<SM4Cipher>>(16);

[InheritsTests]
public class AesCcm8BufferOverlapTest() : AeadBufferOverlapTest<Ccm8Mode128<AesCipher>>(32);

[InheritsTests]
public class SM4Ccm8BufferOverlapTest() : AeadBufferOverlapTest<Ccm8Mode128<SM4Cipher>>(16);

[InheritsTests]
public class ChaCha20Poly1305BufferOverlapTest() : AeadBufferOverlapTest<ChaCha20Poly1305Cipher>(32);

[InheritsTests]
public class XChaCha20Poly1305BufferOverlapTest() : AeadBufferOverlapTest<XChaCha20Poly1305Cipher>(32);

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public abstract class AeadBufferOverlapTest<T>(int keyLength) where T : IAeadCipher<T>
{
	[Test]
	[Arguments(-1)]
	[Arguments(1)]
	public async Task OffsetSourceDestinationOverlapsAreRejectedBeforeWriting(int destinationOffset)
	{
		byte[] key = CreateDeterministicSource(keyLength);
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
	[MatrixDataSource]
	public async Task AssociatedDataOverlappingDestinationIsConsumedBeforeWriting([Matrix(29, 255)] int associatedDataSizeInBytes, [Matrix(257, 4097)] int plaintextLength)
	{
		const int destinationOffset = 7;
		byte[] key = CreateDeterministicSource(keyLength);
		using T crypto = T.Create(key);
		byte[] nonce = CreateDeterministicSource(T.NonceSize);
		byte[] associatedData = CreateDeterministicSource(associatedDataSizeInBytes);
		byte[] plaintext = CreateDeterministicSource(plaintextLength);
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
		byte[] key = CreateDeterministicSource(keyLength);
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
