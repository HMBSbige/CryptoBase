using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.DataFormatExtensions;
using CryptoBase.SymmetricCryptos.BlockCryptoModes;
using CryptoBase.SymmetricCryptos.BlockCryptos.AES;

namespace CryptoBase.Tests;

public class AESCBCTest
{
	private static void Test_Internal(IBlockCrypto crypto, ReadOnlySpan<byte> plain, ReadOnlySpan<byte> ciper)
	{
		Assert.Equal(@"AES-CBC", crypto.Name);
		Assert.Equal(16, crypto.BlockSize);

		Span<byte> o = stackalloc byte[ciper.Length];

		crypto.Encrypt(plain, o);
		Assert.True(o.SequenceEqual(ciper));

		crypto.Decrypt(ciper, o);
		Assert.True(o.SequenceEqual(plain));

		crypto.Dispose();
	}

	/// <summary>
	/// https://gchq.github.io/CyberChef/#recipe=AES_Encrypt(%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D,'CBC/NoPadding','Hex','Hex',%7B'option':'Hex','string':''%7D)
	/// </summary>
	[Theory]
	[InlineData(@"000102030405060708090a0b0c0d0e0f",
		@"fe3577795961e1fbbbb82528c74d2e99",
		@"00112233445566778899aabbccddeeff",
		@"976b0f03fb159e3f82298814b4b7173c")]
	[InlineData(@"000102030405060708090a0b0c0d0e0f1011121314151617",
		@"fe3577795961e1fbbbb82528c74d2e99",
		@"00112233445566778899aabbccddeeff",
		@"e26d6f1ca88b566eddf49b1ef372db6e")]
	[InlineData(@"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		@"fe3577795961e1fbbbb82528c74d2e99",
		@"00112233445566778899aabbccddeeff",
		@"93010f33350c4e774778bea533e18cf2")]
	public void Test(string keyHex, string ivHex, string hex1, string hex2)
	{
		ReadOnlySpan<byte> key = keyHex.FromHex();
		ReadOnlySpan<byte> iv = ivHex.FromHex();
		ReadOnlySpan<byte> plain = hex1.FromHex();
		ReadOnlySpan<byte> cipher = hex2.FromHex();

		Test_Internal(new AESCBCCrypto(key, iv), plain, cipher);
		Test_Internal(new CBCBlockMode(AESUtils.CreateECB(key), iv), plain, cipher);
	}
}
