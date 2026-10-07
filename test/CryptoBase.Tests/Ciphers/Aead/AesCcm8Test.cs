using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Modes;
using CryptoBase.Ciphers.Modes.Ccm;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Ciphers.Aead;

public class AesCcm8Test
{
	private const int TagLength = 8;

	[Test]
	[MatrixDataSource]
	public async Task MessagesMatchReference([Matrix(16, 24, 32)] int keyLength, [MatrixMethod<AesCcmTest>(nameof(AesCcmTest.MessageLengths))] int length, [Matrix(0, 29, 0xFF0A)] int associatedDataLength)
	{
		byte[] key = CreateDeterministicSource(keyLength);
		byte[] nonce = CreateDeterministicSource(Ccm8Mode128<AesCipher>.NonceSize);
		byte[] associatedData = CreateDeterministicSource(associatedDataLength);
		byte[] plaintext = CreateDeterministicSource(length);
		(byte[] expected, byte[] expectedTag) = AesCcmTest.EncryptReference(key, nonce, plaintext, associatedData, TagLength);

		using (Ccm8Mode128<AesCipher> cipher = Ccm8Mode128<AesCipher>.Create(key))
		{
			await CcmTestUtils.AssertMessage(cipher, nonce, plaintext, associatedData, expected, expectedTag);
		}

		await AesCcmTest.AssertBuffered<CcmTag8>(key, nonce, plaintext, associatedData, expected, expectedTag);
	}
}
