using CryptoBase.Ciphers.Blocks.SM4;
using CryptoBase.Ciphers.Modes;
using CryptoBase.Tests.Ciphers.Blocks.SM4;
using CryptoBase.Tests.Ciphers.Modes;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Ciphers.Aead;

public class SM4CcmTest
{
	/// <summary>
	/// https://www.rfc-editor.org/rfc/rfc8998#appendix-A.2
	/// </summary>
	[Test]
	[Arguments
	(
		@"0123456789ABCDEFFEDCBA9876543210",
		@"00001234567800000000ABCD",
		@"FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2",
		@"16842D4FA186F56AB33256971FA110F4",
		@"AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDEEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFFEEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA",
		@"48AF93501FA62ADBCD414CCE6034D895DDA1BF8F132F042098661572E7483094FD12E518CE062C98ACEE28D95DF4416BED31A2F04476C18BB40C84A74B97DC5B"
	)]
	public async Task Test(string keyHex, string nonceHex, string associatedDataHex, string tagHex, string plainHex, string cipherHex)
	{
		byte[] key = Convert.FromHexString(keyHex);
		await CcmMode128<SM4Cipher>.Create(key).AeadTest(nonceHex, associatedDataHex, tagHex, plainHex, cipherHex);
	}

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
