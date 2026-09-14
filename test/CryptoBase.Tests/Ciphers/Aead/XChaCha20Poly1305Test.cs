using CryptoBase.Ciphers.Aead;
using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.Tests.Ciphers.Aead;

public class XChaCha20Poly1305Test
{
	/// <summary>
	/// https://tools.ietf.org/html/draft-irtf-cfrg-xchacha-03
	/// </summary>
	[Test]
	[Arguments
	(
		@"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F",
		@"404142434445464748494a4b4c4d4e4f5051525354555657",
		@"50515253C0C1C2C3C4C5C6C7",
		@"C0875924C1C7987947DEAFD8780ACF49",
		@"4C616469657320616E642047656E746C656D656E206F662074686520636C617373206F66202739393A204966204920636F756C64206F6666657220796F75206F6E6C79206F6E652074697020666F7220746865206675747572652C2073756E73637265656E20776F756C642062652069742E",
		@"BD6D179D3E83D43B9576579493C0E939572A1700252BFACCBED2902C21396CBB731C7F1B0B4AA6440BF3A82F4EDA7E39AE64C6708C54C216CB96B72E1213B4522F8C9BA40DB5D945B11B69B982C1BB9E3F3FAC2BC369488F76B2383565D3FFF921F9664C97637DA9768812F615C68B13B52E"
	)]
	public async Task Test(string keyHex, string nonceHex, string associatedDataHex, string tagHex, string plainHex, string cipherHex)
	{
		byte[] key = Convert.FromHexString(keyHex);
		await XChaCha20Poly1305Cipher.Create(key).AeadTest(nonceHex, associatedDataHex, tagHex, plainHex, cipherHex);
	}

	[Test]
	[Arguments(16 - 1)]
	[Arguments(16 + 1)]
	[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
	public async Task InvalidTagLengthDoesNotWriteAndPreservesInPlace(int tagLength)
	{
		byte[] key = TestUtils.CreateDeterministicSource(XChaCha20Poly1305Cipher.KeySize);
		byte[] nonce = TestUtils.CreateDeterministicSource(XChaCha20Poly1305Cipher.NonceSize);
		byte[] associatedData = TestUtils.CreateDeterministicSource(29);
		byte[] plaintext = TestUtils.CreateDeterministicSource(73);
		byte[] invalidTag = new byte[tagLength];
		TestUtils.PrepareDestination(invalidTag);

		using XChaCha20Poly1305Cipher crypto = new(key);

		byte[] encryptBuffer = plaintext.ToArray();
		await Assert.That(() => crypto.Encrypt(nonce, encryptBuffer, encryptBuffer, invalidTag, associatedData)).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(encryptBuffer).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
		await Assert.That(invalidTag).All(static value => value is TestUtils.DestinationSentinel);

		byte[] decryptBuffer = TestUtils.CreateDeterministicSource(plaintext.Length);
		byte[] ciphertext = decryptBuffer.ToArray();
		await Assert.That(() => crypto.TryDecrypt(nonce, decryptBuffer, invalidTag, decryptBuffer, associatedData)).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(decryptBuffer).IsEquivalentTo(ciphertext, CollectionOrdering.Matching);
		await Assert.That(invalidTag).All(static value => value is TestUtils.DestinationSentinel);

		byte[] roundTripBuffer = plaintext.ToArray();
		byte[] tag = new byte[XChaCha20Poly1305Cipher.TagSize];
		crypto.Encrypt(nonce, roundTripBuffer, roundTripBuffer, tag, associatedData);
		await Assert.That(crypto.TryDecrypt(nonce, roundTripBuffer, tag, roundTripBuffer, associatedData)).IsTrue();

		await Assert.That(roundTripBuffer).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
	}
}
