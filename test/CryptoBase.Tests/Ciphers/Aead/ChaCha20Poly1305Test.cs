using CryptoBase.Ciphers.Aead;
using System.Security.Cryptography;

namespace CryptoBase.Tests.Ciphers.Aead;

public class ChaCha20Poly1305Test
{
	public static IEnumerable<(int Length, bool InPlace)> MessageCases()
	{
		int[] boundaries = [384, 448, 512, 576, 640, 704, 768, 832, 896, 960, 1024, 1088, 1216, 1280, 1536, 1984, 2048, 3072, 4096, 8192, 16384, 65536];
		int[] lengths = [.. Enumerable.Range(0, 301), .. boundaries.SelectMany(static boundary => new[] { boundary - 1, boundary, boundary + 1 }), 1031, 1500, 131073];
		int[] inPlaceLengths = [192, 193, 448, 449, 960, 961, 1024, 1025, 1500, 1984, 2047, 3072, 3073, 4096, 4097, 16384, 16385];

		foreach (int length in lengths.Order())
		{
			yield return (length, false);

			if (inPlaceLengths.Contains(length))
			{
				yield return (length, true);
			}
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task MatchesReferenceAtEveryLength([Matrix(0, 13, 4097)] int associatedDataLength, [MatrixMethod<ChaCha20Poly1305Test>(nameof(MessageCases))] (int Length, bool InPlace) scenario)
	{
		if (!ChaCha20Poly1305.IsSupported)
		{
			Skip.Test("The BCL ChaCha20-Poly1305 reference is not supported here.");
		}

		(int length, bool inPlace) = scenario;
		byte[] key = TestUtils.CreateDeterministicSource(32);
		byte[] nonce = TestUtils.CreateDeterministicSource(ChaCha20Poly1305Cipher.NonceSize);
		byte[] associatedData = TestUtils.CreateDeterministicSource(associatedDataLength);
		using ChaCha20Poly1305 expected = new(key);
		using ChaCha20Poly1305Cipher crypto = new(key);

		byte[] plaintext = TestUtils.CreateDeterministicSource(length);
		byte[] expectedCiphertext = new byte[length];
		byte[] expectedTag = new byte[16];
		byte[] ciphertext = inPlace ? plaintext.ToArray() : new byte[length];
		byte[] tag = new byte[16];
		byte[] decrypted = inPlace ? ciphertext : new byte[length];
		expected.Encrypt(nonce, plaintext, expectedCiphertext, expectedTag, associatedData);

		crypto.Encrypt(nonce, inPlace ? ciphertext : plaintext, ciphertext, tag, associatedData);

		await Assert.That(ciphertext).IsEquivalentTo(expectedCiphertext, CollectionOrdering.Matching);
		await Assert.That(tag).IsEquivalentTo(expectedTag, CollectionOrdering.Matching);
		await Assert.That(crypto.TryDecrypt(nonce, ciphertext, tag, decrypted, associatedData)).IsTrue();
		await Assert.That(decrypted).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
	}
}
