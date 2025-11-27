using CryptoBase.Abstractions;
using CryptoBase.Abstractions.Digests;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.DataFormatExtensions;
using System.Security.Cryptography;
using System.Text;

namespace CryptoBase.Tests;

public static class TestUtils
{
	public static void LargeMessageTest(IHash hash, string str, string result)
	{
		Span<byte> origin = Encoding.UTF8.GetBytes(str);
		Span<byte> outBuffer = stackalloc byte[hash.Length];

		uint times = (uint)((uint.MaxValue + 10ul) / (double)origin.Length) + 10;

		for (int i = 0; i < times; ++i)
		{
			hash.Update(origin);
		}

		hash.GetHash(outBuffer);

		Assert.Equal(result, outBuffer.ToHex());

		hash.Dispose();
	}

	public static void AEADTest(this IAEADCrypto crypto,
		string nonceHex, string associatedDataHex, string tagHex,
		string plainHex, string cipherHex)
	{
		ReadOnlySpan<byte> nonce = nonceHex.FromHex();
		ReadOnlySpan<byte> associatedData = associatedDataHex.FromHex();
		ReadOnlySpan<byte> tag = tagHex.FromHex();
		ReadOnlySpan<byte> plain = plainHex.FromHex();
		ReadOnlySpan<byte> cipher = cipherHex.FromHex();
		Span<byte> o1 = stackalloc byte[plain.Length];
		Span<byte> o2 = stackalloc byte[tag.Length];

		crypto.Encrypt(nonce, plain, o1, o2, associatedData);
		Assert.Equal(cipher, o1);
		Assert.Equal(tag, o2);

		crypto.Encrypt(nonce, plain, o1, o2, associatedData);
		Assert.Equal(cipher, o1);
		Assert.Equal(tag, o2);

		crypto.Decrypt(nonce, cipher, tag, o1, associatedData);
		Assert.Equal(plain, o1);

		crypto.Decrypt(nonce, cipher, tag, o1, associatedData);
		Assert.Equal(plain, o1);

		crypto.Dispose();
	}

	public static void LargeMessageTest(IHash hash, string str, int times, string result)
	{
		Span<byte> origin = Encoding.UTF8.GetBytes(str);
		Span<byte> outBuffer = stackalloc byte[hash.Length];

		for (int i = 0; i < times; ++i)
		{
			hash.Update(origin);
		}

		hash.GetHash(outBuffer);

		Assert.Equal(result, outBuffer.ToHex());

		hash.Dispose();
	}

	public static void MacTest(IMac mac, ReadOnlySpan<byte> message, string expected)
	{
		mac.Update(message);

		Span<byte> digest = new byte[mac.Length];
		mac.GetMac(digest);
		Assert.Equal(expected, digest.ToHex());
	}

	public static void TestBlocks(IStreamCrypto crypto, int length)
	{
		ReadOnlySpan<byte> data = RandomNumberGenerator.GetBytes(length);
		Span<byte> expected = stackalloc byte[length];
		Span<byte> cipher = stackalloc byte[length];

		for (int i = 0; i < length; ++i)
		{
			crypto.Update(data.Slice(i, 1), expected.Slice(i, 1));
		}

		crypto.Reset();

		crypto.Update(data, cipher);

		Assert.Equal(expected, cipher);
	}

	public static void TestNBlock16(IBlockCrypto crypto)
	{
		ReadOnlySpan<byte> source = RandomNumberGenerator.GetBytes(2 * 64 * crypto.BlockSize);
		Span<byte> expectedCipher = stackalloc byte[source.Length];

		for (int i = 0; i < source.Length / crypto.BlockSize; ++i)
		{
			crypto.Encrypt(source.Slice(i * crypto.BlockSize), expectedCipher.Slice(i * crypto.BlockSize));
		}

		foreach (int multiplier in Enumerable.Range(0, 5).Select(x => 1 << x))
		{
			int chunkSize = multiplier * crypto.BlockSize;

			for (int i = 0; i < source.Length / chunkSize; ++i)
			{
				ReadOnlySpan<byte> plainSlice = source.Slice(i * chunkSize, chunkSize);
				ReadOnlySpan<byte> expectedCipherSlice = expectedCipher.Slice(i * chunkSize, chunkSize);
				Span<byte> tmp = new byte[chunkSize];

				switch (multiplier)
				{
					case 1:
					{
						crypto.Encrypt(plainSlice, tmp);
						Assert.Equal(expectedCipherSlice, tmp);

						crypto.Decrypt(expectedCipherSlice, tmp);
						Assert.Equal(plainSlice, tmp);

						break;
					}
					case 2:
					{
						crypto.Encrypt2(plainSlice, tmp);
						Assert.Equal(expectedCipherSlice, tmp);

						crypto.Decrypt2(expectedCipherSlice, tmp);
						Assert.Equal(plainSlice, tmp);

						break;
					}
					case 4:
					{
						crypto.Encrypt4(plainSlice, tmp);
						Assert.Equal(expectedCipherSlice, tmp);

						crypto.Decrypt4(expectedCipherSlice, tmp);
						Assert.Equal(plainSlice, tmp);

						break;
					}
					case 8:
					{
						crypto.Encrypt8(plainSlice, tmp);
						Assert.Equal(expectedCipherSlice, tmp);

						crypto.Decrypt8(expectedCipherSlice, tmp);
						Assert.Equal(plainSlice, tmp);

						break;
					}
					case 16:
					{
						crypto.Encrypt16(plainSlice, tmp);
						Assert.Equal(expectedCipherSlice, tmp);

						crypto.Decrypt16(expectedCipherSlice, tmp);
						Assert.Equal(plainSlice, tmp);
						break;
					}
					case 32:
					{
						crypto.Encrypt32(plainSlice, tmp);
						Assert.Equal(expectedCipherSlice, tmp);

						crypto.Decrypt32(expectedCipherSlice, tmp);
						Assert.Equal(plainSlice, tmp);
						break;
					}
					default:
					{
						Assert.Fail();
						break;
					}
				}
			}
		}

		crypto.Dispose();
	}

	public static void TestBlock16<T>(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plain, ReadOnlySpan<byte> cipher) where T : IBlock16Crypto<T>
	{
		Assert.True(T.IsSupported);
		using T crypto = T.Create(key);

		Assert.Equal(cipher, crypto.Encrypt(plain.AsVectorBuffer16()));
		Assert.Equal(cipher, crypto.Encrypt(plain.AsVectorBuffer16()));

		Assert.Equal(plain, crypto.Decrypt(cipher.AsVectorBuffer16()));
		Assert.Equal(plain, crypto.Decrypt(cipher.AsVectorBuffer16()));
	}
}
