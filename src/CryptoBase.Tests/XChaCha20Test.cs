using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.StreamCryptos;
using CryptoBase.DataFormatExtensions;
using CryptoBase.SymmetricCryptos.StreamCryptos;
using CryptoBase.SymmetricCryptos.StreamCryptos.XChaCha20;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CryptoBase.Tests;

[TestClass]
public class XChaCha20Test
{
	private static void TestCounter1(SnuffleCryptoBase crypto, string hex, string hex2)
	{
		Assert.AreEqual(@"XChaCha20", crypto.Name);
		Assert.AreEqual(24, crypto.IvSize);

		Span<byte> h1 = hex.FromHex();
		Span<byte> h2 = hex2.FromHex();
		Span<byte> i1 = stackalloc byte[368];
		Span<byte> o1 = stackalloc byte[i1.Length];

		h1.CopyTo(i1[64..]);

		crypto.Update(i1, o1);
		Assert.IsTrue(o1.Slice(64, 304).SequenceEqual(h2));

		crypto.Reset();

		h1.CopyTo(i1[64..]);

		crypto.Update(i1, o1);
		Assert.IsTrue(o1.Slice(64, 304).SequenceEqual(h2));

		crypto.Dispose();
	}

	private static void TestCounter0(SnuffleCryptoBase crypto, string hex, string hex2)
	{
		Assert.AreEqual(@"XChaCha20", crypto.Name);
		Assert.AreEqual(24, crypto.IvSize);

		Span<byte> h1 = hex.FromHex();
		Span<byte> h2 = hex2.FromHex();
		Span<byte> o1 = stackalloc byte[h1.Length];

		crypto.Update(h1, o1);
		Assert.IsTrue(o1.SequenceEqual(h2));

		crypto.Reset();

		crypto.Update(h1, o1);
		Assert.IsTrue(o1.SequenceEqual(h2));

		crypto.Dispose();
	}

	/// <summary>
	/// https://tools.ietf.org/html/draft-irtf-cfrg-xchacha-03#appendix-A.3.2
	/// </summary>
	[TestMethod]
	[DataRow(@"808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
		@"404142434445464748494a4b4c4d4e4f5051525354555658",
		@"5468652064686f6c65202870726f6e6f756e6365642022646f6c65222920697320616c736f206b6e6f776e2061732074686520417369617469632077696c6420646f672c2072656420646f672c20616e642077686973746c696e6720646f672e2049742069732061626f7574207468652073697a65206f662061204765726d616e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c757369766520616e6420736b696c6c6564206a756d70657220697320636c6173736966696564207769746820776f6c7665732c20636f796f7465732c206a61636b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d69632066616d696c792043616e696461652e",
		@"7d0a2e6b7f7c65a236542630294e063b7ab9b555a5d5149aa21e4ae1e4fbce87ecc8e08a8b5e350abe622b2ffa617b202cfad72032a3037e76ffdcdc4376ee053a190d7e46ca1de04144850381b9cb29f051915386b8a710b8ac4d027b8b050f7cba5854e028d564e453b8a968824173fc16488b8970cac828f11ae53cabd20112f87107df24ee6183d2274fe4c8b1485534ef2c5fbc1ec24bfc3663efaa08bc047d29d25043532db8391a8a3d776bf4372a6955827ccb0cdd4af403a7ce4c63d595c75a43e045f0cce1f29c8b93bd65afc5974922f214a40b7c402cdb91ae73c0b63615cdad0480680f16515a7ace9d39236464328a37743ffc28f4ddb324f4d0f5bbdc270c65b1749a6efff1fbaa09536175ccd29fb9e6057b307320d316838a9c71f70b5b5907a66f7ea49aadc409")]
	public void TestCounter1(string keyHex, string ivHex, string hex, string hex2)
	{
		var key = keyHex.FromHex();
		var iv = ivHex.FromHex();
		TestCounter1(new BcXChaCha20Crypto(key, iv), hex, hex2);
		TestCounter1(new XChaCha20CryptoSF(key, iv), hex, hex2);
		TestCounter1(new XChaCha20CryptoX86(key, iv), hex, hex2);
		TestCounter1(StreamCryptoCreate.XChaCha20(key, iv), hex, hex2);
	}

	[TestMethod]
	[DataRow(@"808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
		@"404142434445464748494a4b4c4d4e4f5051525354555658",
		@"5468652064686f6c65202870726f6e6f756e6365642022646f6c65222920697320616c736f206b6e6f776e2061732074686520417369617469632077696c6420646f672c2072656420646f672c20616e642077686973746c696e6720646f672e2049742069732061626f7574207468652073697a65206f662061204765726d616e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c757369766520616e6420736b696c6c6564206a756d70657220697320636c6173736966696564207769746820776f6c7665732c20636f796f7465732c206a61636b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d69632066616d696c792043616e696461652e",
		@"4559abba4e48c16102e8bb2c05e6947f50a786de162f9b0b7e592a9b53d0d4e98d8d6410d540a1a6375b26d80dace4fab52384c731acbf16a5923c0c48d3575d4d0d2c673b666faa731061277701093a6bf7a158a8864292a41c48e3a9b4c0daece0f8d98d0d7e05b37a307bbb66333164ec9e1b24ea0d6c3ffddcec4f68e7443056193a03c810e11344ca06d8ed8a2bfb1e8d48cfa6bc0eb4e2464b748142407c9f431aee769960e15ba8b96890466ef2457599852385c661f752ce20f9da0c09ab6b19df74e76a95967446f8d0fd415e7bee2a12a114c20eb5292ae7a349ae577820d5520a1f3fb62a17ce6a7e68fa7c79111d8860920bc048ef43fe84486ccb87c25f0ae045f0cce1e7989a9aa220a28bdd4827e751a24a6d5c62d790a66393b93111c1a55dd7421a10184974c7c5")]
	public void TestCounter0(string keyHex, string ivHex, string hex, string hex2)
	{
		var key = keyHex.FromHex();
		var iv = ivHex.FromHex();
		TestCounter0(new BcXChaCha20Crypto(key, iv), hex, hex2);
		TestCounter0(new XChaCha20CryptoSF(key, iv), hex, hex2);
		TestCounter0(new XChaCha20CryptoX86(key, iv), hex, hex2);
		TestCounter0(StreamCryptoCreate.XChaCha20(key, iv), hex, hex2);
	}
}
