using CryptoBase.Abstractions;
using CryptoBase.Abstractions.Digests;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.DataFormatExtensions;
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
}
