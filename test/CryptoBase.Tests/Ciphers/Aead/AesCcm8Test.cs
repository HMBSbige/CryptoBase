using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Modes;
using CryptoBase.Ciphers.Modes.Ccm;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Ciphers.Aead;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class AesCcm8Test
{
	private const int TagLength = 8;

	[Test]
	// https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/aes_ccm_test.json
	// tcId 359
	[Arguments
	(
		@"5afb73f37d05147566a7ac9734eba3ff",
		@"026dd125c98ef1507f6d1d15",
		@"",
		@"a4c4b136625f0243",
		@"",
		@""
	)]
	// tcId 362
	[Arguments
	(
		@"ea5a915fd7be0aaf14b88f5dc4fd719a",
		@"aeecf19f7d3379ee55ba6468",
		@"13791aad5812a362291a4f6d63687d33",
		@"2fb637ff91d6fd9e",
		@"d313e09cd48b06f16ef9178e42624bd0",
		@"f9bc9a66186b6a60035d144dfb34c4af"
	)]
	// tcId 363
	[Arguments
	(
		@"89121103c350e29f7cd580f05bbfeaac",
		@"f6d6e802abdf43230030a896",
		@"",
		@"1b300de35538c252",
		@"636840ffbc66191bc37bf2e6bddf28bda9",
		@"c6912062548dba55e6184e8f507d7f9c7d"
	)]
	// tcId 366
	[Arguments
	(
		@"c08339a6f80b84e201e3d6030cdb3f02",
		@"1cbf2ca31330abe749db588b",
		@"b535a847dfc962012d913a4076f58f9f",
		@"34d622fe4ba3cac5",
		@"4f9fd6ad1656cce99af7469960073a241569ce32dad558111b50306053a0b6",
		@"c91d4c8bf7fdba49b87001fc3ec95f455ba32bc05ba336bc3d58f4ad08b5bc"
	)]
	// tcId 408
	[Arguments
	(
		@"5b04c342efd5e89aa5d38ef32eedeaf2ac035f43b9b4201d",
		@"14d4781e21592efc4409b944",
		@"3fd3b691d0511d71f5dbec4f1320fc8c",
		@"2f84ac2d50bef75e",
		@"",
		@""
	)]
	// tcId 411
	[Arguments
	(
		@"4d8576ff635ec7d99c47be7412a2846fc638c9f9fb0f5531",
		@"8a5340f4a85e3a9cf7430feb",
		@"",
		@"566321b12ecec687",
		@"0b896337a59af8e9ca15f33cd6daaae0ac",
		@"5fdf4a0fce8be9cf740b61d120883bcc1e"
	)]
	// tcId 413
	[Arguments
	(
		@"e923bbfbbdb81cec8632634940c924bc9a230f1587f0ed63",
		@"4190004bf966af35e049445d",
		@"",
		@"8990a6b1f386cc7c",
		@"a38f8e64a391a09b8a298d4feb0113e308cbfc6edbc3cd59a25a31a3f0d534",
		@"01c7765b1396fc6d362c0077a3a1ef9c3fe54b87688b7a64120d8a202de39c"
	)]
	// tcId 457
	[Arguments
	(
		@"b967091c98bb64922430833d1b553326b8e91b6ef7141971cc8e8cc5f6ef6170",
		@"a5dd076d8a9dc3d7ec43d04f",
		@"",
		@"e9c93619d33d268d",
		@"c8a331b554e6c7b0783c53fee6f1618e",
		@"99b5c22225e5325f9aa9599a34deec59"
	)]
	// tcId 460
	[Arguments
	(
		@"47f664e6790f3e25bc410d847f38662f045f0aa3641429edf8099f4b4df32f06",
		@"f092a357b5ef0c975ee169c4",
		@"338b4cc60ec151fa283c1cb10e722d9d",
		@"41158292a1d87cfd",
		@"b01dfe724166a2bc98cbb96cf540028a0e",
		@"d7746f186aabfa36685481ec8a7f0022e8"
	)]
	// tcId 462
	[Arguments
	(
		@"110480ea9c9f4c5e6b5be01a2aafc861d1370c243aff9faafd0a92a9d18e5845",
		@"0e5cf683e13204cf91a2d4b6",
		@"c490a5fa19b97c3e3adf20bc4df51140",
		@"e39b0d1174f7609b",
		@"c92ec3d6a2c2fa19c45be7107a48a9ea0fe46a92978b5dabb3f94b457b5fbd",
		@"bb5110dd12bd3d12144c8de55b3b2677fc7084d56afcc6a76a5228fff8dbd3"
	)]
	public async Task Test(string keyHex, string nonceHex, string associatedDataHex, string tagHex, string plainHex, string cipherHex)
	{
		byte[] key = Convert.FromHexString(keyHex);
		await Ccm8Mode128<AesCipher>.Create(key).AeadTest(nonceHex, associatedDataHex, tagHex, plainHex, cipherHex);
	}

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

	[Test]
	[MatrixDataSource]
	public async Task MessagesMatchBcl([Matrix(16, 24, 32)] int keyLength, [Matrix(0, 1, 16, 17, 4097)] int length, [Matrix(0, 30, 0xFF0A)] int associatedDataLength)
	{
		if (!AesCcm.IsSupported)
		{
			Skip.Test("AES-CCM is not supported by the platform.");
		}

		byte[] key = CreateDeterministicSource(keyLength);
		byte[] nonce = CreateDeterministicSource(Ccm8Mode128<AesCipher>.NonceSize);
		byte[] associatedData = CreateDeterministicSource(associatedDataLength);
		byte[] plaintext = CreateDeterministicSource(length);
		(byte[] expected, byte[] expectedTag) = AesCcmTest.EncryptBcl(key, nonce, plaintext, associatedData, TagLength);
		using Ccm8Mode128<AesCipher> cipher = Ccm8Mode128<AesCipher>.Create(key);
		await CcmTestUtils.AssertMessage(cipher, nonce, plaintext, associatedData, expected, expectedTag);
	}

	// The tag length is part of B0, so a CCM_8 tag is not a prefix of the 16-byte CCM tag.
	[Test]
	public async Task TagDiffersFromTruncatedCcmTag()
	{
		byte[] key = CreateDeterministicSource(16);
		byte[] nonce = CreateDeterministicSource(Ccm8Mode128<AesCipher>.NonceSize);
		byte[] plaintext = CreateDeterministicSource(17);
		byte[] ciphertext = new byte[plaintext.Length];
		byte[] tag = new byte[Ccm8Mode128<AesCipher>.TagSize];
		byte[] fullTag = new byte[CcmMode128<AesCipher>.TagSize];

		using (Ccm8Mode128<AesCipher> cipher = Ccm8Mode128<AesCipher>.Create(key))
		{
			cipher.Encrypt(nonce, plaintext, ciphertext, tag);
		}

		using (CcmMode128<AesCipher> cipher = CcmMode128<AesCipher>.Create(key))
		{
			cipher.Encrypt(nonce, plaintext, new byte[plaintext.Length], fullTag);
		}

		await Assert.That(tag.AsSpan().SequenceEqual(fullTag.AsSpan(0, TagLength))).IsFalse();
	}

	[Test]
	public async Task FullLengthTagIsRejected()
	{
		byte[] key = CreateDeterministicSource(16);
		byte[] nonce = CreateDeterministicSource(Ccm8Mode128<AesCipher>.NonceSize);
		byte[] plaintext = CreateDeterministicSource(17);
		byte[] ciphertext = new byte[plaintext.Length];
		byte[] tag = new byte[CcmMode128<AesCipher>.TagSize];
		using Ccm8Mode128<AesCipher> cipher = Ccm8Mode128<AesCipher>.Create(key);

		await Assert.That(() => cipher.Encrypt(nonce, plaintext, ciphertext, tag)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("tag");
		await Assert.That(() => cipher.TryDecrypt(nonce, ciphertext, tag, plaintext)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("tag");
	}
}
