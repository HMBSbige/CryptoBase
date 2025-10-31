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

	private static void TestN_Internal(IBlockCrypto crypto)
	{
		ReadOnlySpan<byte> source = RandomNumberGenerator.GetBytes(16 * crypto.BlockSize);
		Span<byte> expectedCipher = stackalloc byte[source.Length];
		Span<byte> destination = stackalloc byte[source.Length];

		for (int i = 0; i < 16; ++i)
		{
			crypto.Encrypt(source.Slice(i * crypto.BlockSize), expectedCipher.Slice(i * crypto.BlockSize));
		}

		for (int i = 0; i < 8; ++i)
		{
			crypto.Encrypt2(source.Slice(i * 2 * crypto.BlockSize), destination.Slice(i * 2 * crypto.BlockSize));
		}

		Assert.True(expectedCipher.SequenceEqual(destination));

		for (int i = 0; i < 8; ++i)
		{
			crypto.Decrypt2(expectedCipher.Slice(i * 2 * crypto.BlockSize), destination.Slice(i * 2 * crypto.BlockSize));
		}

		Assert.True(destination.SequenceEqual(source));

		for (int i = 0; i < 4; ++i)
		{
			crypto.Encrypt4(source.Slice(i * 4 * crypto.BlockSize), destination.Slice(i * 4 * crypto.BlockSize));
		}

		Assert.True(expectedCipher.SequenceEqual(destination));

		for (int i = 0; i < 4; ++i)
		{
			crypto.Decrypt4(expectedCipher.Slice(i * 4 * crypto.BlockSize), destination.Slice(i * 4 * crypto.BlockSize));
		}

		Assert.True(destination.SequenceEqual(source));

		for (int i = 0; i < 2; ++i)
		{
			crypto.Encrypt8(source.Slice(i * 8 * crypto.BlockSize), destination.Slice(i * 8 * crypto.BlockSize));
		}

		Assert.True(expectedCipher.SequenceEqual(destination));

		for (int i = 0; i < 2; ++i)
		{
			crypto.Decrypt8(expectedCipher.Slice(i * 8 * crypto.BlockSize), destination.Slice(i * 8 * crypto.BlockSize));
		}

		Assert.True(destination.SequenceEqual(source));

		crypto.Encrypt16(source, destination);
		Assert.True(expectedCipher.SequenceEqual(destination));
		crypto.Decrypt16(expectedCipher, destination);
		Assert.True(destination.SequenceEqual(source));

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

		TestN_Internal(new BcSm4Crypto(key));
		TestN_Internal(new SM4Crypto(key));
	}
}
