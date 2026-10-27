using CryptoBase.Abstractions.Ciphers;
using CryptoBase.Ciphers.Aead;
using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Blocks.SM4;
using CryptoBase.Ciphers.Modes;
using System.Diagnostics.CodeAnalysis;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Ciphers.Aead;

[InheritsTests]
public class AesGcmContractTest() : AeadContractTest<GcmMode<AesCipher>>(32);

[InheritsTests]
public class SM4GcmContractTest() : AeadContractTest<GcmMode<SM4Cipher>>(16);

[InheritsTests]
public class AesCcmContractTest() : AeadContractTest<CcmMode<AesCipher>>(32);

[InheritsTests]
public class SM4CcmContractTest() : AeadContractTest<CcmMode<SM4Cipher>>(16);

[InheritsTests]
public class AesCcm8ContractTest() : AeadContractTest<Ccm8Mode<AesCipher>>(32);

[InheritsTests]
public class SM4Ccm8ContractTest() : AeadContractTest<Ccm8Mode<SM4Cipher>>(16);

[InheritsTests]
public class ChaCha20Poly1305ContractTest() : AeadContractTest<ChaCha20Poly1305Cipher>(32);

[InheritsTests]
public class XChaCha20Poly1305ContractTest() : AeadContractTest<XChaCha20Poly1305Cipher>(32);

[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Assertions are awaited before the cipher is disposed.")]
public abstract class AeadContractTest<T>(int keyLength) where T : IAeadCipher<T>
{
	[Test]
	[MatrixDataSource]
	public async Task InvalidArgumentsDoNotWriteAndAllowRetry([Matrix(0, 1, 16, 257, 4096, 4097)] int length)
	{
		using T cipher = T.Create(CreateDeterministicSource(keyLength));
		byte[] nonce = CreateDeterministicSource(T.NonceSize);
		byte[] aad = CreateDeterministicSource(19);
		byte[] plaintext = CreateDeterministicSource(length);
		byte[] ciphertext = new byte[length + 7];
		byte[] tag = new byte[T.TagSize];
		PrepareDestination(ciphertext);
		await Assert.That(() => cipher.Encrypt(nonce.AsSpan(1), plaintext, ciphertext, tag, aad)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("nonce");
		await Assert.That(ciphertext).All(static x => x is DestinationSentinel);
		await Assert.That(() => cipher.TryDecrypt(nonce, plaintext, tag.AsSpan(1), ciphertext, aad)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("tag");
		await Assert.That(ciphertext).All(static x => x is DestinationSentinel);

		if (length > 0)
		{
			await Assert.That(() => cipher.Encrypt(nonce, plaintext, ciphertext.AsSpan(0, length - 1), tag, aad)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("destination");
			await Assert.That(ciphertext).All(static x => x is DestinationSentinel);
			await Assert.That(() => cipher.TryDecrypt(nonce, plaintext, tag, ciphertext.AsSpan(0, length - 1), aad)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("destination");
			await Assert.That(ciphertext).All(static x => x is DestinationSentinel);
		}

		cipher.Encrypt(nonce, plaintext, ciphertext, tag, aad);
		await Assert.That(ciphertext.AsMemory(length)).All(static x => x is DestinationSentinel);
		byte[] output = new byte[length + 7];
		PrepareDestination(output);
		await Assert.That(cipher.TryDecrypt(nonce, ciphertext.AsSpan(0, length), tag, output, aad)).IsTrue();
		await AssertOutput(output, plaintext);
	}

	[Test]
	[Arguments(-1)]
	[Arguments(1)]
	public async Task InvalidTagLengthsAreRejectedBeforeWriting(int tagLengthDelta)
	{
		using T cipher = T.Create(CreateDeterministicSource(keyLength));
		byte[] nonce = CreateDeterministicSource(T.NonceSize);
		byte[] aad = CreateDeterministicSource(19);
		byte[] plaintext = CreateDeterministicSource(73);
		byte[] ciphertext = new byte[plaintext.Length];
		byte[] tag = new byte[T.TagSize];
		cipher.Encrypt(nonce, plaintext, ciphertext, tag, aad);

		byte[] invalidTag = new byte[T.TagSize + tagLengthDelta];
		PrepareDestination(invalidTag);
		byte[] buffer = plaintext.ToArray();
		await Assert.That(() => cipher.Encrypt(nonce, buffer, buffer, invalidTag, aad)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("tag");
		await Assert.That(buffer).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
		await Assert.That(invalidTag).All(static x => x is DestinationSentinel);

		// The valid tag prefix must not authenticate a truncated or extended tag.
		tag.AsSpan().Slice(0, Math.Min(tag.Length, invalidTag.Length)).CopyTo(invalidTag);
		byte[] invalidTagCopy = invalidTag.ToArray();
		ciphertext.CopyTo(buffer, 0);
		await Assert.That(() => cipher.TryDecrypt(nonce, buffer, invalidTag, buffer, aad)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("tag");
		await Assert.That(buffer).IsEquivalentTo(ciphertext, CollectionOrdering.Matching);
		await Assert.That(invalidTag).IsEquivalentTo(invalidTagCopy, CollectionOrdering.Matching);

		await Assert.That(cipher.TryDecrypt(nonce, buffer, tag, buffer, aad)).IsTrue();
		await Assert.That(buffer).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
	}

	[Test]
	[MatrixDataSource]
	public async Task SuccessfulOperationsPreserveTailAndSupportInPlace([Matrix(0, 1, 16, 257, 4096, 4097)] int length)
	{
		using T cipher = T.Create(CreateDeterministicSource(keyLength));
		byte[] nonce = CreateDeterministicSource(T.NonceSize);
		byte[] aad = CreateDeterministicSource(19);
		byte[] plaintext = CreateDeterministicSource(length);
		byte[] ciphertext = new byte[length + 7];
		byte[] tag = new byte[T.TagSize];
		PrepareDestination(ciphertext);
		cipher.Encrypt(nonce, plaintext, ciphertext, tag, aad);
		await Assert.That(ciphertext.AsMemory(length)).All(static x => x is DestinationSentinel);

		byte[] output = new byte[length + 7];
		PrepareDestination(output);
		await Assert.That(cipher.TryDecrypt(nonce, ciphertext.AsSpan(0, length), tag, output, aad)).IsTrue();
		await AssertOutput(output, plaintext);

		byte[] inPlaceTag = new byte[T.TagSize];
		cipher.Encrypt(nonce, output.AsSpan(0, length), output, inPlaceTag, aad);
		await Assert.That(output).IsEquivalentTo(ciphertext, CollectionOrdering.Matching);
		await Assert.That(inPlaceTag).IsEquivalentTo(tag, CollectionOrdering.Matching);

		await Assert.That(cipher.TryDecrypt(nonce, output.AsSpan(0, length), inPlaceTag, output, aad)).IsTrue();
		await AssertOutput(output, plaintext);
	}

	[Test]
	public async Task EveryTagBitIsAuthenticated()
	{
		const int length = 257;
		using T cipher = T.Create(CreateDeterministicSource(keyLength));
		byte[] nonce = CreateDeterministicSource(T.NonceSize);
		byte[] aad = CreateDeterministicSource(29);
		byte[] plaintext = CreateDeterministicSource(length);
		byte[] ciphertext = new byte[length];
		byte[] tag = new byte[T.TagSize];
		byte[] output = new byte[length + 7];
		cipher.Encrypt(nonce, plaintext, ciphertext, tag, aad);

		for (int index = 0; index < tag.Length; ++index)
		{
			for (int bit = 0; bit < 8; ++bit)
			{
				tag[index] ^= (byte)(1 << bit);
				PrepareDestination(output);
				await Assert.That(cipher.TryDecrypt(nonce, ciphertext, tag, output, aad)).IsFalse();
				await Assert.That(output.AsMemory(0, length)).All(static x => x is 0);
				await Assert.That(output.AsMemory(length)).All(static x => x is DestinationSentinel);
				tag[index] ^= (byte)(1 << bit);
			}
		}

		await Assert.That(cipher.TryDecrypt(nonce, ciphertext, tag, output, aad)).IsTrue();
		await AssertOutput(output, plaintext);
	}

	[Test]
	[MatrixDataSource]
	public async Task AuthenticationFailureClearsOnlyOutputPrefix([Matrix(0, 1, 16, 257, 4096, 4097)] int length)
	{
		using T cipher = T.Create(CreateDeterministicSource(keyLength));
		byte[] nonce = CreateDeterministicSource(T.NonceSize);
		byte[] aad = CreateDeterministicSource(19);
		byte[] plaintext = CreateDeterministicSource(length);
		byte[] ciphertext = new byte[length + 7];
		byte[] tag = new byte[T.TagSize];
		PrepareDestination(ciphertext);
		cipher.Encrypt(nonce, plaintext, ciphertext, tag, aad);
		byte[] output = new byte[length + 7];

		for (int target = 0; target < 4; ++target)
		{
			if (target is 3 && length is 0)
			{
				continue;
			}

			byte[] badNonce = nonce.ToArray();
			byte[] badAad = aad.ToArray();
			byte[] badTag = tag.ToArray();
			byte[] badCiphertext = ciphertext.ToArray();
			byte[] tampered = target switch { 0 => badNonce, 1 => badAad, 2 => badTag, _ => badCiphertext };
			tampered[0] ^= 1;
			PrepareDestination(output);
			await Assert.That(cipher.TryDecrypt(badNonce, badCiphertext.AsSpan(0, length), badTag, output, badAad)).IsFalse();
			await Assert.That(output.AsMemory(0, length)).All(static x => x is 0);
			await Assert.That(output.AsMemory(length)).All(static x => x is DestinationSentinel);
			await Assert.That(cipher.TryDecrypt(badNonce, badCiphertext.AsSpan(0, length), badTag, badCiphertext, badAad)).IsFalse();
			await Assert.That(badCiphertext.AsMemory(0, length)).All(static x => x is 0);
			await Assert.That(badCiphertext.AsMemory(length)).All(static x => x is DestinationSentinel);
		}

		await Assert.That(cipher.TryDecrypt(nonce, ciphertext.AsSpan(0, length), tag, ciphertext, aad)).IsTrue();
		await AssertOutput(ciphertext, plaintext);
	}

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
