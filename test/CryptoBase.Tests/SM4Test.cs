using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.BlockCryptos;
using CryptoBase.DataFormatExtensions;
using CryptoBase.SymmetricCryptos.BlockCryptos.SM4;
using System.Security.Cryptography;

namespace CryptoBase.Tests;

public class SM4Test
{
	private static void Test_Internal(IBlockCrypto crypto, string hex1, string hex2, string hex3)
	{
		Assert.Equal(@"SM4", crypto.Name);
		Assert.Equal(16, crypto.BlockSize);

		Span<byte> h1 = hex1.FromHex();
		Span<byte> h2 = hex2.FromHex();
		Span<byte> h3 = hex3.FromHex();
		Span<byte> o1 = new byte[crypto.BlockSize];

		crypto.Encrypt(h1, o1);
		Assert.True(o1.SequenceEqual(h2));

		crypto.Encrypt(h1, o1);
		Assert.True(o1.SequenceEqual(h2));

		Span<byte> t = h1;

		for (int i = 0; i < 1000000; ++i)
		{
			crypto.Encrypt(t, o1);
			t = o1;
		}

		Assert.True(t.SequenceEqual(h3));

		crypto.Decrypt(h2, o1);
		Assert.True(o1.SequenceEqual(h1));

		crypto.Decrypt(h2, o1);
		Assert.True(o1.SequenceEqual(h1));

		t = h3;

		for (int i = 0; i < 1000000; ++i)
		{
			crypto.Decrypt(t, o1);
			t = o1;
		}

		Assert.True(t.SequenceEqual(h1));

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
