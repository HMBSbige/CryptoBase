using CryptoBase.Abstractions.Ciphers;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Ciphers.Aead;

internal static class CcmTestUtils
{
	internal static async Task AssertMessage<T>(T cipher, byte[] nonce, byte[] plaintext, byte[] associatedData, byte[] expected, byte[] expectedTag) where T : IAeadCipher<T>
	{
		int length = plaintext.Length;
		byte[] source = CreateGuardedBuffer(3, length);
		plaintext.CopyTo(source, 3);
		byte[] destination = CreateGuardedBuffer(5, length);
		byte[] tag = CreateGuardedBuffer(7, T.TagSize);

		cipher.Encrypt(nonce, source.AsSpan(3, length), destination.AsSpan(5), tag.AsSpan(7, T.TagSize), associatedData);
		await AssertOutput(destination, 5, expected);
		await AssertOutput(tag, 7, expectedTag);
		await AssertOutput(source, 3, plaintext);
		await Assert.That(cipher.TryDecrypt(nonce, expected, expectedTag, destination.AsSpan(5), associatedData)).IsTrue();
		await AssertOutput(destination, 5, plaintext);

		PrepareDestination(tag);
		cipher.Encrypt(nonce, destination.AsSpan(5, length), destination.AsSpan(5), tag.AsSpan(7, T.TagSize), associatedData);
		await AssertOutput(destination, 5, expected);
		await AssertOutput(tag, 7, expectedTag);
		await Assert.That(cipher.TryDecrypt(nonce, destination.AsSpan(5, length), expectedTag, destination.AsSpan(5), associatedData)).IsTrue();
		await AssertOutput(destination, 5, plaintext);

		byte[] badTag = expectedTag.ToArray();
		badTag[^1] ^= 0x80;
		PrepareDestination(destination);
		await Assert.That(cipher.TryDecrypt(nonce, expected, badTag, destination.AsSpan(5), associatedData)).IsFalse();
		await AssertOutput(destination, 5, new byte[length]);
	}
}
