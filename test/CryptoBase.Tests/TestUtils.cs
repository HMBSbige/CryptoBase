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
	public static async Task LargeMessageTest(IHash hash, string str, string result)
	{
		string actual;

		using (hash)
		{
			byte[] origin = Encoding.UTF8.GetBytes(str);
			byte[] outBuffer = new byte[hash.Length];

			uint times = (uint)((uint.MaxValue + 10ul) / (double)origin.Length) + 10;

			for (int i = 0; i < times; ++i)
			{
				hash.Update(origin);
			}

			hash.GetHash(outBuffer);
			actual = outBuffer.ToHex();
		}

		await Assert.That(actual).IsEqualTo(result);
	}

	public static async Task AEADTest(this IAEADCrypto crypto, string expectedName,
		string nonceHex, string associatedDataHex, string tagHex,
		string plainHex, string cipherHex)
	{
		using (crypto)
		{
			await Assert.That(crypto.Name).IsEqualTo(expectedName);

			byte[] nonce = nonceHex.FromHex();
			byte[] associatedData = associatedDataHex.FromHex();
			byte[] tag = tagHex.FromHex();
			byte[] plain = plainHex.FromHex();
			byte[] cipher = cipherHex.FromHex();
			byte[] outPlain = new byte[plain.Length];
			byte[] outTag = new byte[tag.Length];

			crypto.Encrypt(nonce, plain, outPlain, outTag, associatedData);
			await Assert.That(cipher.SequenceEqual(outPlain)).IsTrue();
			await Assert.That(tag.SequenceEqual(outTag)).IsTrue();

			crypto.Encrypt(nonce, plain, outPlain, outTag, associatedData);
			await Assert.That(cipher.SequenceEqual(outPlain)).IsTrue();
			await Assert.That(tag.SequenceEqual(outTag)).IsTrue();

			crypto.Decrypt(nonce, cipher, tag, outPlain, associatedData);
			await Assert.That(plain.SequenceEqual(outPlain)).IsTrue();

			crypto.Decrypt(nonce, cipher, tag, outPlain, associatedData);
			await Assert.That(plain.SequenceEqual(outPlain)).IsTrue();
		}
	}

	public static async Task LargeMessageTest(IHash hash, string str, int times, string result)
	{
		string actual;

		using (hash)
		{
			byte[] origin = Encoding.UTF8.GetBytes(str);
			byte[] outBuffer = new byte[hash.Length];

			for (int i = 0; i < times; ++i)
			{
				hash.Update(origin);
			}

			hash.GetHash(outBuffer);
			actual = outBuffer.ToHex();
		}

		await Assert.That(actual).IsEqualTo(result);
	}

	public static async Task MacTest(IMac mac, byte[] message, string expected)
	{
		mac.Update(message);

		byte[] digest = new byte[mac.Length];
		mac.GetMac(digest);
		await Assert.That(digest.ToHex()).IsEqualTo(expected);
	}

	public static async Task TestBlocks(IStreamCrypto crypto, int length)
	{
		byte[] data = RandomNumberGenerator.GetBytes(length);
		byte[] expected = new byte[length];
		byte[] cipher = new byte[length];

		for (int i = 0; i < length; ++i)
		{
			crypto.Update(data.AsSpan().Slice(i, 1), expected.AsSpan().Slice(i, 1));
		}

		crypto.Reset();
		crypto.Update(data, cipher);

		await Assert.That(expected.SequenceEqual(cipher)).IsTrue();
	}

	public static async Task TestBlock16<T>(byte[] key, byte[] plain, byte[] cipher) where T : IBlock16Cipher<T>
	{
		await Assert.That(T.IsSupported).IsTrue();
		using T crypto = T.Create(key);

		await Assert.That(cipher.AsSpan().SequenceEqual(crypto.Encrypt(plain.AsVectorBuffer16()))).IsTrue();
		await Assert.That(cipher.AsSpan().SequenceEqual(crypto.Encrypt(plain.AsVectorBuffer16()))).IsTrue();

		await Assert.That(plain.AsSpan().SequenceEqual(crypto.Decrypt(cipher.AsVectorBuffer16()))).IsTrue();
		await Assert.That(plain.AsSpan().SequenceEqual(crypto.Decrypt(cipher.AsVectorBuffer16()))).IsTrue();
	}

	public static async Task TestNBlock16<T>(byte[] key) where T : IBlock16Cipher<T>
	{
		await Assert.That(T.IsSupported).IsTrue();
		using T crypto = T.Create(key);

		byte[] source = RandomNumberGenerator.GetBytes(2 * 64 * 16);
		byte[] expectedCipher = new byte[source.Length];

		for (int i = 0; i < source.Length / 16; ++i)
		{
			Unsafe.WriteUnaligned(ref expectedCipher.AsSpan().Slice(i * 16).GetReference(), crypto.Encrypt(source.AsSpan().Slice(i * 16).AsVectorBuffer16()));
		}

		foreach (int multiplier in (int[])[1, 2, 4, 8, 16, 32])
		{
			int chunkSize = multiplier * 16;

			for (int i = 0; i < source.Length / chunkSize; ++i)
			{
				int offset = i * chunkSize;

				switch (multiplier)
				{
					case 1:
					{
						await Assert.That(expectedCipher.AsSpan().Slice(offset, chunkSize).SequenceEqual(crypto.Encrypt(source.AsSpan().Slice(offset, chunkSize).AsVectorBuffer16()))).IsTrue();
						await Assert.That(source.AsSpan().Slice(offset, chunkSize).SequenceEqual(crypto.Decrypt(expectedCipher.AsSpan().Slice(offset, chunkSize).AsVectorBuffer16()))).IsTrue();
						break;
					}
					case 2:
					{
						await Assert.That(expectedCipher.AsSpan().Slice(offset, chunkSize).SequenceEqual(crypto.Encrypt(source.AsSpan().Slice(offset, chunkSize).AsVectorBuffer32()))).IsTrue();
						await Assert.That(source.AsSpan().Slice(offset, chunkSize).SequenceEqual(crypto.Decrypt(expectedCipher.AsSpan().Slice(offset, chunkSize).AsVectorBuffer32()))).IsTrue();
						break;
					}
					case 4:
					{
						await Assert.That(expectedCipher.AsSpan().Slice(offset, chunkSize).SequenceEqual(crypto.Encrypt(source.AsSpan().Slice(offset, chunkSize).AsVectorBuffer64()))).IsTrue();
						await Assert.That(source.AsSpan().Slice(offset, chunkSize).SequenceEqual(crypto.Decrypt(expectedCipher.AsSpan().Slice(offset, chunkSize).AsVectorBuffer64()))).IsTrue();
						break;
					}
					case 8:
					{
						await Assert.That(expectedCipher.AsSpan().Slice(offset, chunkSize).SequenceEqual(crypto.Encrypt(source.AsSpan().Slice(offset, chunkSize).AsVectorBuffer128()))).IsTrue();
						await Assert.That(source.AsSpan().Slice(offset, chunkSize).SequenceEqual(crypto.Decrypt(expectedCipher.AsSpan().Slice(offset, chunkSize).AsVectorBuffer128()))).IsTrue();

						if (T.HardwareAcceleration.HasFlag(BlockCipherHardwareAcceleration.Block8V256))
						{
							await Assert.That(expectedCipher.AsSpan().Slice(offset, chunkSize).SequenceEqual(crypto.EncryptV256(source.AsSpan().Slice(offset, chunkSize).AsVectorBuffer128()))).IsTrue();
							await Assert.That(source.AsSpan().Slice(offset, chunkSize).SequenceEqual(crypto.DecryptV256(expectedCipher.AsSpan().Slice(offset, chunkSize).AsVectorBuffer128()))).IsTrue();
						}
						else
						{
							await Assert.ThrowsAsync<NotSupportedException>(async () =>
							{
								crypto.EncryptV256(default(VectorBuffer128));
								await Task.CompletedTask;
							});
							await Assert.ThrowsAsync<NotSupportedException>(async () =>
							{
								crypto.DecryptV256(default(VectorBuffer128));
								await Task.CompletedTask;
							});
						}

						break;
					}
					case 16:
					{
						if (T.HardwareAcceleration.HasFlag(BlockCipherHardwareAcceleration.Block16V256))
						{
							await Assert.That(expectedCipher.AsSpan().Slice(offset, chunkSize).SequenceEqual(crypto.EncryptV256(source.AsSpan().Slice(offset, chunkSize).AsVectorBuffer256()))).IsTrue();
							await Assert.That(source.AsSpan().Slice(offset, chunkSize).SequenceEqual(crypto.DecryptV256(expectedCipher.AsSpan().Slice(offset, chunkSize).AsVectorBuffer256()))).IsTrue();
						}
						else
						{
							await Assert.ThrowsAsync<NotSupportedException>(async () =>
							{
								crypto.EncryptV256(default(VectorBuffer256));
								await Task.CompletedTask;
							});
							await Assert.ThrowsAsync<NotSupportedException>(async () =>
							{
								crypto.DecryptV256(default(VectorBuffer256));
								await Task.CompletedTask;
							});
						}

						if (T.HardwareAcceleration.HasFlag(BlockCipherHardwareAcceleration.Block16V512))
						{
							await Assert.That(expectedCipher.AsSpan().Slice(offset, chunkSize).SequenceEqual(crypto.EncryptV512(source.AsSpan().Slice(offset, chunkSize).AsVectorBuffer256()))).IsTrue();
							await Assert.That(source.AsSpan().Slice(offset, chunkSize).SequenceEqual(crypto.DecryptV512(expectedCipher.AsSpan().Slice(offset, chunkSize).AsVectorBuffer256()))).IsTrue();
						}
						else
						{
							await Assert.ThrowsAsync<NotSupportedException>(async () =>
							{
								crypto.EncryptV512(default(VectorBuffer256));
								await Task.CompletedTask;
							});
							await Assert.ThrowsAsync<NotSupportedException>(async () =>
							{
								crypto.DecryptV512(default(VectorBuffer256));
								await Task.CompletedTask;
							});
						}

						break;
					}
					case 32:
					{
						if (T.HardwareAcceleration.HasFlag(BlockCipherHardwareAcceleration.Block32V512))
						{
							await Assert.That(expectedCipher.AsSpan().Slice(offset, chunkSize).SequenceEqual(crypto.EncryptV512(source.AsSpan().Slice(offset, chunkSize).AsVectorBuffer512()))).IsTrue();
							await Assert.That(source.AsSpan().Slice(offset, chunkSize).SequenceEqual(crypto.DecryptV512(expectedCipher.AsSpan().Slice(offset, chunkSize).AsVectorBuffer512()))).IsTrue();
						}
						else
						{
							await Assert.ThrowsAsync<NotSupportedException>(async () =>
							{
								crypto.EncryptV512(default(VectorBuffer512));
								await Task.CompletedTask;
							});
							await Assert.ThrowsAsync<NotSupportedException>(async () =>
							{
								crypto.DecryptV512(default(VectorBuffer512));
								await Task.CompletedTask;
							});
						}

						break;
					}
					default:
					{
						throw new InvalidOperationException("not implemented");
					}
				}
			}
		}
	}
}
