using CryptoBase.Ciphers.Blocks.SM4;
using CryptoBase.Ciphers.Modes;
using CryptoBase.Tests.Ciphers.Blocks.SM4;
using CryptoBase.Tests.Ciphers.Modes;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Ciphers.Aead;

public class SM4CcmTest
{
	[Test]
	[MatrixDataSource]
	public async Task MessagesMatchReference([Matrix(0, 1, 15, 16, 17, 31, 32, 33, 255, 256, 257, 4097)] int length, [Matrix(0, 14, 29, 0xFF0A)] int associatedDataLength)
	{
		byte[] key = CreateDeterministicSource(SM4Cipher.KeySize);
		byte[] nonce = CreateDeterministicSource(CcmMode128<SM4Cipher>.NonceSize);
		byte[] associatedData = CreateDeterministicSource(associatedDataLength);
		byte[] plaintext = CreateDeterministicSource(length);
		(byte[] expected, byte[] expectedTag) = CcmReference.Encrypt(blocks => SM4Reference.Transform(key, blocks), nonce, plaintext, associatedData);
		using CcmMode128<SM4Cipher> cipher = CcmMode128<SM4Cipher>.Create(key);
		await CcmTestUtils.AssertMessage(cipher, nonce, plaintext, associatedData, expected, expectedTag);
	}

	[Test]
	[MatrixDataSource]
	public async Task Ccm8MessagesMatchReference([Matrix(0, 1, 15, 16, 17, 31, 32, 33, 255, 256, 257, 4097)] int length, [Matrix(0, 14, 29, 0xFF0A)] int associatedDataLength)
	{
		byte[] key = CreateDeterministicSource(SM4Cipher.KeySize);
		byte[] nonce = CreateDeterministicSource(Ccm8Mode128<SM4Cipher>.NonceSize);
		byte[] associatedData = CreateDeterministicSource(associatedDataLength);
		byte[] plaintext = CreateDeterministicSource(length);
		(byte[] expected, byte[] expectedTag) = CcmReference.Encrypt(blocks => SM4Reference.Transform(key, blocks), nonce, plaintext, associatedData, Ccm8Mode128<SM4Cipher>.TagSize);
		using Ccm8Mode128<SM4Cipher> cipher = Ccm8Mode128<SM4Cipher>.Create(key);
		await CcmTestUtils.AssertMessage(cipher, nonce, plaintext, associatedData, expected, expectedTag);
	}
}
