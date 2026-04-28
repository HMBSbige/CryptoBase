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
	[Test]
	[Arguments(@"0123456789ABCDEFFEDCBA9876543210", @"0123456789ABCDEFFEDCBA9876543210", @"681EDF34D206965E86B3E94F536E4246", @"595298C7C6FD271F0402F804C33D3F66")]
	public async Task Test(string keyHex, string hex1, string hex2, string hex3)
	{
		byte[] key = keyHex.FromHex();
		byte[] plain = hex1.FromHex();
		byte[] cipher = hex2.FromHex();
		byte[] cipher1000000 = hex3.FromHex();

		await TestUtils.TestBlock16<BcSm4Cipher>(key, plain, cipher);
		await TestUtils.TestBlock16<Sm4Cipher>(key, plain, cipher);

		await Test1000000<BcSm4Cipher>(key, plain, cipher1000000);
		await Test1000000<Sm4Cipher>(key, plain, cipher1000000);


		static async Task Test1000000<T>(byte[] key, byte[] plain, byte[] cipher) where T : IBlock16Cipher<T>
		{
			using T crypto = T.Create(key);

			await Assert.That(Encrypt1000000(crypto, plain, cipher)).IsTrue();
			await Assert.That(Decrypt1000000(crypto, cipher, plain)).IsTrue();
		}

		static bool Encrypt1000000<T>(T crypto, byte[] plain, byte[] cipher) where T : IBlock16Cipher<T>
		{
			VectorBuffer16 t = plain.AsVectorBuffer16();

			for (int i = 0; i < 1000000; ++i)
			{
				t = crypto.Encrypt(t);
			}

			return cipher.AsSpan().SequenceEqual(t);
		}

		static bool Decrypt1000000<T>(T crypto, byte[] cipher, byte[] plain) where T : IBlock16Cipher<T>
		{
			VectorBuffer16 t = cipher.AsVectorBuffer16();

			for (int i = 0; i < 1000000; ++i)
			{
				t = crypto.Decrypt(t);
			}

			return plain.AsSpan().SequenceEqual(t);
		}

	}

	[Test]
	public async Task TestN()
	{
		byte[] key = RandomNumberGenerator.GetBytes(16);

		await TestUtils.TestNBlock16<BcSm4Cipher>(key);
		await TestUtils.TestNBlock16<Sm4Cipher>(key);
	}
}
