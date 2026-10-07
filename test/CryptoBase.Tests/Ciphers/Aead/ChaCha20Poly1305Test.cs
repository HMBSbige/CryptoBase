using CryptoBase.Ciphers.Aead;
using System.Security.Cryptography;

namespace CryptoBase.Tests.Ciphers.Aead;

public class ChaCha20Poly1305Test
{
	[Test]
	[Arguments(0)]
	[Arguments(13)]
	public async Task MatchesReferenceAtEveryLength(int associatedDataLength)
	{
		if (!ChaCha20Poly1305.IsSupported)
		{
			return;
		}

		byte[] key = TestUtils.CreateDeterministicSource(32);
		byte[] nonce = TestUtils.CreateDeterministicSource(ChaCha20Poly1305Cipher.NonceSize);
		byte[] associatedData = TestUtils.CreateDeterministicSource(associatedDataLength);
		using ChaCha20Poly1305 expected = new(key);
		using ChaCha20Poly1305Cipher crypto = new(key);

		for (int length = 0; length <= 300; ++length)
		{
			byte[] plaintext = TestUtils.CreateDeterministicSource(length);
			byte[] expectedCiphertext = new byte[length];
			byte[] expectedTag = new byte[16];
			byte[] ciphertext = new byte[length];
			byte[] tag = new byte[16];
			byte[] decrypted = new byte[length];
			expected.Encrypt(nonce, plaintext, expectedCiphertext, expectedTag, associatedData);

			crypto.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

			await Assert.That(ciphertext).IsEquivalentTo(expectedCiphertext, CollectionOrdering.Matching);
			await Assert.That(tag).IsEquivalentTo(expectedTag, CollectionOrdering.Matching);
			await Assert.That(crypto.TryDecrypt(nonce, ciphertext, tag, decrypted, associatedData)).IsTrue();
			await Assert.That(decrypted).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
		}
	}
}
