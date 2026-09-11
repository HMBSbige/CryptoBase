using CryptoBase.SymmetricCryptos.BlockCryptos.SM4;

namespace CryptoBase.Tests.SymmetricCryptos.BlockCryptos.SM4;

public class SM4Test
{
	[Test]
	public async Task StandardVectorEncryptsAndDecrypts()
	{
		byte[] key = Convert.FromHexString("0123456789ABCDEFFEDCBA9876543210");
		byte[] plaintext = Convert.FromHexString("0123456789ABCDEFFEDCBA9876543210");
		byte[] ciphertext = Convert.FromHexString("681EDF34D206965E86B3E94F536E4246");

		await TestUtils.TestBlock16<SM4Cipher>(key, plaintext, ciphertext);
	}

	[Test]
	public async Task BatchWidthsMatchSingleBlockReference()
	{
		byte[] key = Convert.FromHexString("0123456789ABCDEFFEDCBA9876543210");

		await TestUtils.TestNBlock16<SM4Cipher>(key);
	}
}
