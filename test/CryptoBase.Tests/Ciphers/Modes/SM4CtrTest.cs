using CryptoBase.Ciphers.Blocks.SM4;
using CryptoBase.Ciphers.Modes;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Ciphers.Modes;

public class SM4CtrTest
{
	[Test]
	[Arguments
	(
		"B7FAD2F367B9999C95E207CA2E16616D",
		"CBD328D0C128002C6A44384590E6DBC9",
		"5B0C121AD672AAFF1009FC4294584AED651748C3E15765834A914755DC7D7FDCE7E1EDB7C821570AA9199E9C923CC4AEF36E1D270DE0BE2CC70E81A981B4369A",
		"B4632B189DF350F6D21C143B6CC7D0A29392FB0FF92410FB231669CA43E1BCFB6348CF02EAB1DFB0CB6349329C7CF4F5CEF1336B990DC087C5165652DE22C731"
	)]
	public async Task KnownVector(string keyHex, string counterHex, string plaintextHex, string ciphertextHex)
	{
		byte[] key = Convert.FromHexString(keyHex);
		byte[] counter = Convert.FromHexString(counterHex);
		byte[] plaintext = Convert.FromHexString(plaintextHex);
		byte[] ciphertext = Convert.FromHexString(ciphertextHex);

		await VerifyStreamVector(CtrMode128<SM4Cipher>.Create(key, counter), plaintext, ciphertext);
	}
}
