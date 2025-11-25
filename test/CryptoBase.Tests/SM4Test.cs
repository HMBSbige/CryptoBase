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
	private static void Test_Internal(IBlockCrypto16 crypto, string hex1, string hex2, string hex3)
	{
		Assert.Equal(@"SM4", crypto.Name);
		Assert.Equal(16, crypto.BlockSize);

		Span<byte> h1 = hex1.FromHex();
		Span<byte> h2 = hex2.FromHex();
		Span<byte> h3 = hex3.FromHex();

		Assert.Equal(h2, crypto.Encrypt(h1.AsVectorBuffer16()));
		Assert.Equal(h2, crypto.Encrypt(h1.AsVectorBuffer16()));

		VectorBuffer16 t = h1.AsVectorBuffer16();

		for (int i = 0; i < 1000000; ++i)
		{
			t = crypto.Encrypt(t);
		}

		Assert.Equal(h3, t);

		Assert.Equal(h1, crypto.Decrypt(h2.AsVectorBuffer16()));
		Assert.Equal(h1, crypto.Decrypt(h2.AsVectorBuffer16()));

		t = h3.AsVectorBuffer16();

		for (int i = 0; i < 1000000; ++i)
		{
			t = crypto.Decrypt(t);
		}

		Assert.Equal(h1, t);

		crypto.Dispose();
	}

	[Theory]
	[InlineData(@"0123456789ABCDEFFEDCBA9876543210", @"0123456789ABCDEFFEDCBA9876543210", @"681EDF34D206965E86B3E94F536E4246", @"595298C7C6FD271F0402F804C33D3F66")]
	public void Test(string keyHex, string hex1, string hex2, string hex3)
	{
		byte[] key = keyHex.FromHex();
		Test_Internal(new BcSm4Crypto(key), hex1, hex2, hex3);
		Test_Internal(new SM4Crypto(key), hex1, hex2, hex3);
	}

	[Fact]
	public void TestN()
	{
		ReadOnlySpan<byte> key = RandomNumberGenerator.GetBytes(16);

		TestUtils.TestNBlock16(new BcSm4Crypto(key));
		TestUtils.TestNBlock16(new SM4Crypto(key));
	}
}
