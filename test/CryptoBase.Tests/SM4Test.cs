using CryptoBase.Abstractions;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.Abstractions.Vectors;
using CryptoBase.BouncyCastle.SymmetricCryptos.BlockCryptos;
using CryptoBase.DataFormatExtensions;
using CryptoBase.SymmetricCryptos.BlockCryptos.SM4;
using System.Security.Cryptography;

namespace CryptoBase.Tests;

public class SM4Test
{
	[Theory]
	[InlineData(@"0123456789ABCDEFFEDCBA9876543210", @"0123456789ABCDEFFEDCBA9876543210", @"681EDF34D206965E86B3E94F536E4246", @"595298C7C6FD271F0402F804C33D3F66")]
	public void Test(string keyHex, string hex1, string hex2, string hex3)
	{
		ReadOnlySpan<byte> key = keyHex.FromHex();
		ReadOnlySpan<byte> plain = hex1.FromHex();
		ReadOnlySpan<byte> cipher = hex2.FromHex();
		ReadOnlySpan<byte> cipher1000000 = hex3.FromHex();

		TestUtils.TestBlock16<BcSm4Cipher>(key, plain, cipher);
		TestUtils.TestBlock16<Sm4Cipher>(key, plain, cipher);

		Test1000000<BcSm4Cipher>(key, plain, cipher1000000);
		Test1000000<Sm4Cipher>(key, plain, cipher1000000);

		return;

		static void Test1000000<T>(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plain, ReadOnlySpan<byte> cipher) where T : IBlock16Cipher<T>
		{
			using T crypto = T.Create(key);

			VectorBuffer16 t = plain.AsVectorBuffer16();

			for (int i = 0; i < 1000000; ++i)
			{
				t = crypto.Encrypt(t);
			}

			Assert.Equal(cipher, t);

			t = cipher.AsVectorBuffer16();

			for (int i = 0; i < 1000000; ++i)
			{
				t = crypto.Decrypt(t);
			}

			Assert.Equal(plain, t);
		}
	}

	[Fact]
	public void TestN()
	{
		ReadOnlySpan<byte> key = RandomNumberGenerator.GetBytes(16);

		TestUtils.TestNBlock16<BcSm4Cipher>(key);
		TestUtils.TestNBlock16<Sm4Cipher>(key);
	}
}
