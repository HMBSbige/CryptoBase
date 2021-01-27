using CryptoBase;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.StreamCryptos;
using CryptoBase.SymmetricCryptos.StreamCryptos.Salsa20;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace UnitTest
{
	[TestClass]
	public class Salsa20Test
	{
		private static void Test(SnuffleCryptoBase crypto, int originSize, string hex, int originSize2, string hex2)
		{
			Assert.AreEqual(@"Salsa20", crypto.Name);
			Assert.AreEqual(8, crypto.IvSize);

			Span<byte> h1 = hex.FromHex();
			Span<byte> h2 = hex2.FromHex();

			Span<byte> i1 = stackalloc byte[originSize];
			Span<byte> i2 = stackalloc byte[originSize2];
			Span<byte> o1 = stackalloc byte[i1.Length];
			Span<byte> o2 = stackalloc byte[i2.Length];

			crypto.Encrypt(i1, o1);
			Assert.IsTrue(o1.SequenceEqual(h1));

			crypto.Encrypt(i2, o2);
			Assert.IsTrue(o2.SequenceEqual(h2));

			crypto.Reset();

			crypto.Decrypt(h1, o1);
			Assert.IsTrue(o1.SequenceEqual(i1));

			crypto.Decrypt(h2, o2);
			Assert.IsTrue(o2.SequenceEqual(i2));

			crypto.Dispose();
		}

		private static void Test255(ISymmetricCrypto crypto, string hex, string hex2)
		{
			Span<byte> h1 = hex.FromHex();
			Span<byte> h2 = hex2.FromHex();
			Span<byte> i1 = stackalloc byte[64];
			Span<byte> o1 = stackalloc byte[64];

			Span<byte> i2 = stackalloc byte[128];
			Span<byte> o2 = stackalloc byte[128];

			crypto.Encrypt(i1, o1);
			Assert.IsTrue(o1.SequenceEqual(h1));

			crypto.Encrypt(i2, o2);

			crypto.Encrypt(i1, o1);
			Assert.IsTrue(o1.SequenceEqual(h2));

			crypto.Reset();

			crypto.Decrypt(h1, o1);
			Assert.IsTrue(o1.SequenceEqual(i1));

			crypto.Encrypt(i2, o2);

			crypto.Encrypt(h2, o1);
			Assert.IsTrue(o1.SequenceEqual(i1));

			crypto.Dispose();
		}

		private static void Test65535(ISymmetricCrypto crypto, string hex, string hex2)
		{
			Span<byte> h1 = hex.FromHex();
			Span<byte> h2 = hex2.FromHex();
			Span<byte> i1 = stackalloc byte[65536];
			Span<byte> o1 = stackalloc byte[65536];

			crypto.Encrypt(i1, o1);

			Assert.IsTrue(o1.Slice(0, 64).SequenceEqual(h1));
			Assert.IsTrue(o1.Slice(65472, 64).SequenceEqual(h2));

			crypto.Dispose();
		}

		/// <summary>
		/// https://github.com/das-labor/legacy/blob/master/microcontroller-2/crypto-lib/testvectors/salsa20-full-verified.test-vectors
		/// </summary>
		[TestMethod]
		[DataRow(@"80000000000000000000000000000000", @"0000000000000000", 7, @"4DFA5E481DA23E", 11, @"A09A31022050859936DA52")]
		[DataRow(@"6363636363636363636363636363636363636363636363636363636363636363", @"0000000000000000", 33, @"D417644E8A37FF8840772A55960C4B064DA371869EA07FD02D7F8EFEF0BDB7CE30", 17, @"8173B8BAFDCA6064CEBE09609377B6542C")]
		[DataRow(@"0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D", @"0D74DB42A91077DE", 5, @"F5FAD53F79", 37, @"F9DF58C4AEA0D0ED9A9601F278112CA7180D565B420A48019670EAF24CE493A86263F677B4")]
		[DataRow(@"0558ABFE51A4F74A9DF04396E93C8FE23588DB2E81D4277ACD2073C6196CBF12", @"167DE44BB21980E7", 16, @"3944F6DC9F85B128083879FDF190F7DE", 16, @"E4053A07BC09896D51D0690BD4DA4AC1")]
		[DataRow(@"0A5DB00356A9FC4FA2F5489BEE4194E73A8DE03386D92C7FD22578CB1E71C417", @"1F86ED54BB2289F0", 30, @"3FE85D5BB1960A82480B5E6F4E965A4460D7A54501664F7D60B54B06100A", 30, @"37FFDCF6BDE5CE3F4886BA77DD5B44E95644E40A8AC65801155DB90F0252")]
		[DataRow(@"0F62B5085BAE0154A7FA4DA0F34699EC3F92E5388BDE3184D72A7DD02376C91C", @"288FF65DC42B92F9", 37, @"5E5E71F90199340304ABB22A37B6625BF883FB89CE3B21F54A10B81066EF87DA30B77699AA", 37, @"7379DA595C77DD59542DA208E5954F89E40EB7AA80A84A6176663FD910CDE567CF1FF60F70")]
		public void Test(string keyHex, string ivHex, int originSize, string hex, int originSize2, string hex2)
		{
			var key = keyHex.FromHex();
			var iv = ivHex.FromHex();
			Test(new BcSalsa20Crypto(key, iv), originSize, hex, originSize2, hex2);
			Test(new SlowSalsa20Crypto(key, iv), originSize, hex, originSize2, hex2);
			Test(new FastSalsa20Crypto(key, iv), originSize, hex, originSize2, hex2);
		}

		[TestMethod]
		[DataRow(@"80000000000000000000000000000000", @"0000000000000000",
			@"4DFA5E481DA23EA09A31022050859936DA52FCEE218005164F267CB65F5CFD7F2B4F97E0FF16924A52DF269515110A07F9E460BC65EF95DA58F740B7D1DBB0AA",
			@"DA9C1581F429E0A00F7D67E23B730676783B262E8EB43A25F55FB90B3E753AEF8C6713EC66C51881111593CCB3E8CB8F8DE124080501EEEB389C4BCB6977CF95")]
		public void Test255(string keyHex, string ivHex, string hex, string hex2)
		{
			var key = keyHex.FromHex();
			var iv = ivHex.FromHex();
			Test255(new BcSalsa20Crypto(key, iv), hex, hex2);
			Test255(new SlowSalsa20Crypto(key, iv), hex, hex2);
			Test255(new FastSalsa20Crypto(key, iv), hex, hex2);
		}

		[TestMethod]
		[DataRow(@"0F62B5085BAE0154A7FA4DA0F34699EC3F92E5388BDE3184D72A7DD02376C91C", @"288FF65DC42B92F9",
				@"5E5E71F90199340304ABB22A37B6625BF883FB89CE3B21F54A10B81066EF87DA30B77699AA7379DA595C77DD59542DA208E5954F89E40EB7AA80A84A6176663F",
				@"2DA2174BD150A1DFEC1796E921E9D6E24ECF0209BCBEA4F98370FCE629056F64917283436E2D3F45556225307D5CC5A565325D8993B37F1654195C240BF75B16")]
		public void Test65535(string keyHex, string ivHex, string hex, string hex2)
		{
			var key = keyHex.FromHex();
			var iv = ivHex.FromHex();
			Test65535(new BcSalsa20Crypto(key, iv), hex, hex2);
			Test65535(new SlowSalsa20Crypto(key, iv), hex, hex2);
			Test65535(new FastSalsa20Crypto(key, iv), hex, hex2);
		}
	}
}
