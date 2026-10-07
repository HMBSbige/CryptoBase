using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Modes;
using System.Security.Cryptography;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Ciphers.Aead;

public class AesGcmTest
{
	[Test]
	[MatrixDataSource]
	public async Task IndependentMessagesMatchBcl
	(
		[Matrix(16, 24, 32)] int keyLength,
		[Matrix(0, 1, 15, 16, 17, 32, 33, 48, 49, 64, 65, 127, 128, 129, 257, 513, 2047, 2048, 2049, 4097, 16385)]
		int messageLength,
		[Matrix(0, 7, 15, 16, 17, 126)] int associatedDataLength
	)
	{
		byte[] key = CreateDeterministicSource(keyLength);
		using GcmMode128<AesCipher> gcm = GcmMode128<AesCipher>.Create(key);
		using AesGcm reference = new(key, GcmMode128<AesCipher>.TagSize);
		byte[] nonce = CreateDeterministicSource(12);
		await AssertMessageMatchesBcl(gcm, reference, nonce, messageLength, associatedDataLength);
	}

	[Test]
	[MatrixDataSource]
	public async Task ReusedInstanceMatchesBcl([Matrix(16, 24, 32)] int keyLength)
	{
		byte[] key = CreateDeterministicSource(keyLength);
		using GcmMode128<AesCipher> gcm = GcmMode128<AesCipher>.Create(key);
		using AesGcm reference = new(key, GcmMode128<AesCipher>.TagSize);
		int messageNumber = 0;

		foreach (int length in new[] { 0, 1, 15, 16, 17, 127, 128, 129, 257, 513, 2047, 2048, 2049, 4097, 16385, 513, 17, 0 })
		{
			byte[] nonce = CreateDeterministicSource(12);
			nonce[11] = (byte)messageNumber++;
			await AssertMessageMatchesBcl(gcm, reference, nonce, length, messageNumber * 7);
		}
	}

	[Test]
	[Arguments(0)]
	[Arguments(13)]
	public async Task EveryLengthMatchesBclInPlaceAndRejectsTamperedTags(int associatedDataLength)
	{
		byte[] key = CreateDeterministicSource(16);
		using GcmMode128<AesCipher> gcm = GcmMode128<AesCipher>.Create(key);
		using AesGcm reference = new(key, GcmMode128<AesCipher>.TagSize);
		byte[] nonce = CreateDeterministicSource(12);
		byte[] associatedData = CreateDeterministicSource(associatedDataLength);

		for (int length = 0; length <= 300; ++length)
		{
			await AssertMessageMatchesBcl(gcm, reference, nonce, length, associatedDataLength);

			byte[] plaintext = CreateDeterministicSource(length);
			byte[] expected = new byte[length];
			byte[] expectedTag = new byte[16];
			reference.Encrypt(nonce, plaintext, expected, expectedTag, associatedData);

			byte[] buffer = plaintext.ToArray();
			byte[] tag = new byte[16];
			gcm.Encrypt(nonce, buffer, buffer, tag, associatedData);
			await Assert.That(buffer).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(tag).IsEquivalentTo(expectedTag, CollectionOrdering.Matching);
			await Assert.That(gcm.TryDecrypt(nonce, buffer, tag, buffer, associatedData)).IsTrue();
			await Assert.That(buffer).IsEquivalentTo(plaintext, CollectionOrdering.Matching);

			tag[length % 16] ^= 1;
			byte[] rejected = new byte[length];
			PrepareDestination(rejected);
			await Assert.That(gcm.TryDecrypt(nonce, expected, tag, rejected, associatedData)).IsFalse();
			await Assert.That(rejected).All(static value => value is 0);
		}
	}

	private static async Task AssertMessageMatchesBcl(GcmMode128<AesCipher> gcm, AesGcm reference, byte[] nonce, int messageLength, int associatedDataLength)
	{
		byte[] plaintext = CreateDeterministicSource(messageLength);
		byte[] associatedData = CreateDeterministicSource(associatedDataLength);
		byte[] expected = new byte[messageLength];
		byte[] actual = new byte[messageLength];
		byte[] expectedTag = new byte[16];
		byte[] actualTag = new byte[16];
		reference.Encrypt(nonce, plaintext, expected, expectedTag, associatedData);
		gcm.Encrypt(nonce, plaintext, actual, actualTag, associatedData);
		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
		await Assert.That(actualTag).IsEquivalentTo(expectedTag, CollectionOrdering.Matching);

		byte[] recovered = new byte[messageLength];
		await Assert.That(gcm.TryDecrypt(nonce, actual, actualTag, recovered, associatedData)).IsTrue();
		await Assert.That(recovered).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
	}
}
