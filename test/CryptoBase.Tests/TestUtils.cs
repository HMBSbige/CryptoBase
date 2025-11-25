using CryptoBase.Abstractions;
using CryptoBase.Abstractions.Digests;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.DataFormatExtensions;
using System.Runtime.CompilerServices;
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
		Assert.True(o1.SequenceEqual(cipher));
		Assert.True(o2.SequenceEqual(tag));

		crypto.Encrypt(nonce, plain, o1, o2, associatedData);
		Assert.True(o1.SequenceEqual(cipher));
		Assert.True(o2.SequenceEqual(tag));

		crypto.Decrypt(nonce, cipher, tag, o1, associatedData);
		Assert.True(o1.SequenceEqual(plain));

		crypto.Decrypt(nonce, cipher, tag, o1, associatedData);
		Assert.True(o1.SequenceEqual(plain));

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

		Assert.True(cipher.SequenceEqual(expected));
	}

	public static void TestNBlock16(IBlockCrypto16 crypto)
	{
		ReadOnlySpan<byte> source = RandomNumberGenerator.GetBytes(2 * 64 * crypto.BlockSize);
		ReadOnlySpan<byte> expectedCipher = stackalloc byte[source.Length];

		for (int i = 0; i < source.Length / crypto.BlockSize; ++i)
		{
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref expectedCipher.GetReference(), i * crypto.BlockSize), crypto.Encrypt(source.Slice(i * crypto.BlockSize).AsVectorBuffer16()));
		}

		foreach (int multiplier in Enumerable.Range(0, 6).Select(x => 1 << x))
		{
			int chunkSize = multiplier * crypto.BlockSize;

			for (int i = 0; i < source.Length / chunkSize; ++i)
			{
				ReadOnlySpan<byte> plainSlice = source.Slice(i * chunkSize, chunkSize);
				ReadOnlySpan<byte> expectedCipherSlice = expectedCipher.Slice(i * chunkSize, chunkSize);

				switch (multiplier)
				{
					case 1:
					{
						Assert.Equal(expectedCipherSlice, crypto.Encrypt(plainSlice.AsVectorBuffer16()));
						Assert.Equal(plainSlice, crypto.Decrypt(expectedCipherSlice.AsVectorBuffer16()));
						break;
					}
					case 2:
					{
						Assert.Equal(expectedCipherSlice, crypto.Encrypt(plainSlice.AsVectorBuffer32()));
						Assert.Equal(plainSlice, crypto.Decrypt(expectedCipherSlice.AsVectorBuffer32()));
						break;
					}
					case 4:
					{
						Assert.Equal(expectedCipherSlice, crypto.Encrypt(plainSlice.AsVectorBuffer64()));
						Assert.Equal(plainSlice, crypto.Decrypt(expectedCipherSlice.AsVectorBuffer64()));
						break;
					}
					case 8:
					{
						Assert.Equal(expectedCipherSlice, crypto.Encrypt(plainSlice.AsVectorBuffer128()));
						Assert.Equal(plainSlice, crypto.Decrypt(expectedCipherSlice.AsVectorBuffer128()));
						break;
					}
					case 16:
					{
						Assert.Equal(expectedCipherSlice, crypto.Encrypt(plainSlice.AsVectorBuffer256()));
						Assert.Equal(plainSlice, crypto.Decrypt(expectedCipherSlice.AsVectorBuffer256()));
						break;
					}
					case 32:
					{
						Assert.Equal(expectedCipherSlice, crypto.Encrypt(plainSlice.AsVectorBuffer512()));
						Assert.Equal(plainSlice, crypto.Decrypt(expectedCipherSlice.AsVectorBuffer512()));
						break;
					}
					case 64:
					{
						Assert.Equal(expectedCipherSlice, crypto.Encrypt(plainSlice.AsVectorBuffer1024()));
						Assert.Equal(plainSlice, crypto.Decrypt(expectedCipherSlice.AsVectorBuffer1024()));
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
}
