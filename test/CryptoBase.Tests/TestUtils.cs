using CryptoBase.Abstractions;
using CryptoBase.Abstractions.Digests;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.Abstractions.Vectors;
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

	public static void TestBlock16<T>(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plain, ReadOnlySpan<byte> cipher) where T : IBlock16Cipher<T>
	{
		Assert.True(T.IsSupported);
		using T crypto = T.Create(key);

		Assert.Equal(cipher, crypto.Encrypt(plain.AsVectorBuffer16()));
		Assert.Equal(cipher, crypto.Encrypt(plain.AsVectorBuffer16()));

		Assert.Equal(plain, crypto.Decrypt(cipher.AsVectorBuffer16()));
		Assert.Equal(plain, crypto.Decrypt(cipher.AsVectorBuffer16()));
	}

	public static void TestNBlock16<T>(ReadOnlySpan<byte> key) where T : IBlock16Cipher<T>
	{
		Assert.True(T.IsSupported);
		using T crypto = T.Create(key);

		ReadOnlySpan<byte> source = RandomNumberGenerator.GetBytes(2 * 64 * 16);
		Span<byte> expectedCipher = stackalloc byte[source.Length];

		for (int i = 0; i < source.Length / 16; ++i)
		{
			Unsafe.WriteUnaligned(ref expectedCipher.Slice(i * 16).GetReference(), crypto.Encrypt(source.Slice(i * 16).AsVectorBuffer16()));
		}

		foreach (int multiplier in Enumerable.Range(0, 5).Select(x => 1 << x))
		{
			int chunkSize = multiplier * 16;

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

						if (T.HardwareAcceleration.HasFlag(BlockCipherHardwareAcceleration.Block8V256))
						{
							Assert.Equal(expectedCipherSlice, crypto.EncryptV256(plainSlice.AsVectorBuffer128()));
							Assert.Equal(plainSlice, crypto.DecryptV256(expectedCipherSlice.AsVectorBuffer128()));
						}
						else
						{
							Assert.Throws<NotSupportedException>(() => crypto.EncryptV256(default(VectorBuffer128)));
							Assert.Throws<NotSupportedException>(() => crypto.DecryptV256(default(VectorBuffer128)));
						}

						break;
					}
					case 16:
					{
						if (T.HardwareAcceleration.HasFlag(BlockCipherHardwareAcceleration.Block16V256))
						{
							Assert.Equal(expectedCipherSlice, crypto.EncryptV256(plainSlice.AsVectorBuffer256()));
							Assert.Equal(plainSlice, crypto.DecryptV256(expectedCipherSlice.AsVectorBuffer256()));
						}
						else
						{
							Assert.Throws<NotSupportedException>(() => crypto.EncryptV256(default(VectorBuffer256)));
							Assert.Throws<NotSupportedException>(() => crypto.DecryptV256(default(VectorBuffer256)));
						}

						if (T.HardwareAcceleration.HasFlag(BlockCipherHardwareAcceleration.Block16V512))
						{
							Assert.Equal(expectedCipherSlice, crypto.EncryptV512(plainSlice.AsVectorBuffer256()));
							Assert.Equal(plainSlice, crypto.DecryptV512(expectedCipherSlice.AsVectorBuffer256()));
						}
						else
						{
							Assert.Throws<NotSupportedException>(() => crypto.EncryptV512(default(VectorBuffer256)));
							Assert.Throws<NotSupportedException>(() => crypto.DecryptV512(default(VectorBuffer256)));
						}

						break;
					}
					case 32:
					{
						if (T.HardwareAcceleration.HasFlag(BlockCipherHardwareAcceleration.Block32V512))
						{
							Assert.Equal(expectedCipherSlice, crypto.EncryptV512(plainSlice.AsVectorBuffer512()));
							Assert.Equal(plainSlice, crypto.DecryptV512(expectedCipherSlice.AsVectorBuffer512()));
						}
						else
						{
							Assert.Throws<NotSupportedException>(() => crypto.EncryptV512(default(VectorBuffer512)));
							Assert.Throws<NotSupportedException>(() => crypto.DecryptV512(default(VectorBuffer512)));
						}

						break;
					}
					default:
					{
						Assert.Fail("not implemented");
						break;
					}
				}
			}
		}
	}
}
