using CryptoBase.Abstractions.Ciphers;
using CryptoBase.Ciphers.Blocks.SM4;
using CryptoBase.Ciphers.Modes;
using CryptoBase.Tests.Ciphers.Blocks.SM4;
using CryptoBase.Tests.Ciphers.Modes;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Ciphers.Aead;

public class SM4CcmTest
{
	[Test]
	[GenerateGenericTest(typeof(CcmMode<SM4Cipher>))]
	[GenerateGenericTest(typeof(Ccm8Mode<SM4Cipher>))]
	[MatrixDataSource]
	public async Task MessagesMatchReference<T>([Matrix(0, 1, 15, 16, 17, 31, 32, 33, 255, 256, 257, 4097)] int length, [Matrix(0, 14, 29, 0xFF0A)] int associatedDataLength) where T : IAeadCipher<T>
	{
		byte[] key = CreateDeterministicSource(SM4Cipher.KeySize);
		byte[] nonce = CreateDeterministicSource(T.NonceSize);
		byte[] associatedData = CreateDeterministicSource(associatedDataLength);
		byte[] plaintext = CreateDeterministicSource(length);
		(byte[] expected, byte[] expectedTag) = CcmReference.Encrypt(blocks => SM4Reference.Transform(key, blocks), nonce, plaintext, associatedData, T.TagSize);
		using T cipher = T.Create(key);
		await AeadTestUtils.AssertMessage(cipher, nonce, plaintext, associatedData, expected, expectedTag);
	}
}
