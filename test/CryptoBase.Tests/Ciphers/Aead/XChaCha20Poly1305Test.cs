using CryptoBase.Ciphers.Aead;
using CryptoBase.Ciphers.Streams;
using CryptoBase.Macs.Poly1305;
using System.Buffers.Binary;

namespace CryptoBase.Tests.Ciphers.Aead;

public class XChaCha20Poly1305Test
{
	[Test]
	[MatrixDataSource]
	public async Task MatchesConstructionAtEveryLength([Matrix(0, 13, 4097)] int associatedDataLength, [MatrixMethod<ChaCha20Poly1305Test>(nameof(ChaCha20Poly1305Test.MessageCases))] (int Length, bool InPlace) scenario)
	{
		(int length, bool inPlace) = scenario;
		byte[] key = TestUtils.CreateDeterministicSource(XChaCha20Poly1305Cipher.KeySize);
		byte[] nonce = TestUtils.CreateDeterministicSource(XChaCha20Poly1305Cipher.NonceSize);
		byte[] associatedData = TestUtils.CreateDeterministicSource(associatedDataLength);
		using XChaCha20Poly1305Cipher crypto = new(key);

		byte[] plaintext = TestUtils.CreateDeterministicSource(length);
		byte[] keyStream = new byte[64 + length];

		using (XChaCha20Cipher stream = new(key, nonce))
		{
			stream.Xor(keyStream, keyStream);
		}

		byte[] expectedCiphertext = new byte[length];

		for (int i = 0; i < length; ++i)
		{
			expectedCiphertext[i] = (byte)(plaintext[i] ^ keyStream[64 + i]);
		}

		int paddedAssociatedDataLength = associatedDataLength + 15 & ~15;
		byte[] macInput = new byte[paddedAssociatedDataLength + (length + 15 & ~15) + 16];
		associatedData.CopyTo(macInput, 0);
		expectedCiphertext.CopyTo(macInput, paddedAssociatedDataLength);
		BinaryPrimitives.WriteUInt64LittleEndian(macInput.AsSpan(macInput.Length - 16), (ulong)associatedDataLength);
		BinaryPrimitives.WriteUInt64LittleEndian(macInput.AsSpan(macInput.Length - 8), (ulong)length);
		byte[] expectedTag = new byte[XChaCha20Poly1305Cipher.TagSize];
		Poly1305Algorithm.Mac(keyStream.AsSpan(0, Poly1305Algorithm.KeyLengthInBytes), macInput, expectedTag);

		await ChaCha20Poly1305Test.VerifyEncryptAndDecrypt(crypto, nonce, plaintext, associatedData, inPlace, expectedCiphertext, expectedTag);
	}
}
