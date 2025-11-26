using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.BlockCryptos;
using CryptoBase.DataFormatExtensions;
using CryptoBase.SymmetricCryptos.BlockCryptos.SM4;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace CryptoBase.Tests;

public class SM4Test
{
	// [MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Test_Internal(IBlockCrypto16 crypto, string hex1, string hex2, string hex3)
	{
		Assert.Equal(@"SM4", crypto.Name);
		Assert.Equal(16, crypto.BlockSize);

		Span<byte> h1 = hex1.FromHex();
		Span<byte> h2 = hex2.FromHex();
		Span<byte> h3 = hex3.FromHex();

		Span<byte> o1 = new byte[crypto.BlockSize];
		// Span<byte> o1 = stackalloc byte[crypto.BlockSize];
		h1.CopyTo(o1);

		for (int i = 0; i < 10000000; ++i)
		{
			crypto.Encrypt(o1, o1);
		}

		Assert.Equal(h3, o1);

		crypto.Dispose();
	}

	[Theory]
	[InlineData(@"0123456789ABCDEFFEDCBA9876543210", @"0123456789ABCDEFFEDCBA9876543210", @"681EDF34D206965E86B3E94F536E4246", @"ef0ed914b9306c7415dceb71e554c56a")]
	public void Test(string keyHex, string hex1, string hex2, string hex3)
	{
		byte[] key = keyHex.FromHex();
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
