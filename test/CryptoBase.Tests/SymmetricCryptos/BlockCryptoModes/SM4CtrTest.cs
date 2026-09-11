using CryptoBase.SymmetricCryptos.BlockCryptoModes;
using CryptoBase.SymmetricCryptos.BlockCryptos.SM4;
using CryptoBase.SymmetricCryptos.StreamCryptos;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.SymmetricCryptos.BlockCryptoModes;

public class SM4CtrTest
{
	[Test]
	[Arguments(32)]
	[Arguments(128)]
	public async Task KnownVectorMatchesCounterWidth(int counterSize)
	{
		byte[] key = Convert.FromHexString("B7FAD2F367B9999C95E207CA2E16616D");
		byte[] counter = Convert.FromHexString("CBD328D0C128002C6A44384590E6DBC9");
		byte[] plaintext = Convert.FromHexString("5B0C121AD672AAFF1009FC4294584AED651748C3E15765834A914755DC7D7FDCE7E1EDB7C821570AA9199E9C923CC4AEF36E1D270DE0BE2CC70E81A981B4369A");
		byte[] ciphertext = Convert.FromHexString("B4632B189DF350F6D21C143B6CC7D0A29392FB0FF92410FB231669CA43E1BCFB6348CF02EAB1DFB0CB6349329C7CF4F5CEF1336B990DC087C5165652DE22C731");

		await VerifyStreamVector(counterSize is 32 ? new CtrMode128Ctr32<SM4Cipher>(SM4Cipher.Create(key), counter) : StreamCryptoCreate.SM4Ctr(key, counter), "SM4-CTR", plaintext, ciphertext);
	}
}
