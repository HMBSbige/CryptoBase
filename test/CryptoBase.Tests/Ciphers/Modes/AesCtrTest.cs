using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Modes;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Ciphers.Modes;

public class AesCtrTest
{
	/// <summary>
	/// NIST SP 800-38A, AES-128 CTR example.
	/// </summary>
	[Test]
	public async Task StandardVector()
	{
		byte[] key = Convert.FromHexString("2B7E151628AED2A6ABF7158809CF4F3C");
		byte[] counter = Convert.FromHexString("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF");
		byte[] plaintext = Convert.FromHexString("6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710");
		byte[] ciphertext = Convert.FromHexString("874D6191B620E3261BEF6864990DB6CE9806F66B7970FDFF8617187BB9FFFDFF5AE4DF3EDBD5D35E5B4F09020DB03EAB1E031DDA2FBE03D1792170A0F3009CEE");

		await VerifyStreamVector(CtrMode128<AesCipher>.Create(key, counter), plaintext, ciphertext);
	}
}
