using CryptoBase;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.SymmetricCryptos.StreamCryptos.Salsa20;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace UnitTest
{
	[TestClass]
	public class Salsa20Test
	{
		private static void Test(ISymmetricCrypto crypto, int originSize, string hex, string hex2)
		{
			Assert.AreEqual(@"Salsa20", crypto.Name);

			Span<byte> h1 = hex.FromHex();
			Span<byte> h2 = hex2.FromHex();

			Span<byte> i = new byte[originSize];
			Span<byte> o = stackalloc byte[i.Length];

			crypto.Encrypt(i, o);
			Assert.IsTrue(o.SequenceEqual(h1));

			crypto.Encrypt(i, o);
			Assert.IsTrue(o.SequenceEqual(h2));

			crypto.Reset();

			crypto.Decrypt(h1, o);
			Assert.IsTrue(o.SequenceEqual(i));

			crypto.Decrypt(h2, o);
			Assert.IsTrue(o.SequenceEqual(i));

			crypto.Dispose();
		}

		/// <summary>
		/// https://github.com/das-labor/legacy/blob/master/microcontroller-2/crypto-lib/testvectors/salsa20-full-verified.test-vectors
		/// </summary>
		[TestMethod]
		[DataRow(@"80000000000000000000000000000000", @"0000000000000000", 16, @"4DFA5E481DA23EA09A31022050859936", @"DA52FCEE218005164F267CB65F5CFD7F")]
		[DataRow(@"00400000000000000000000000000000", @"0000000000000000", 16, @"0471076057830FB99202291177FBFE5D", @"38C888944DF8917CAB82788B91B53D1C")]
		[DataRow(@"00002000000000000000000000000000", @"0000000000000000", 16, @"BACFE4145E6D4182EA4A0F59D4076C7E", @"83FFD17E7540E5B7DE70EEDDF9552006")]
		[DataRow(@"00000010000000000000000000000000", @"0000000000000000", 16, @"24F4E317B675336E68A8E2A3A04CA967", @"AB96512ACBA2F832015E9BE03F08830F")]
		[DataRow(@"00000000080000000000000000000000", @"0000000000000000", 16, @"9907DB5E2156427AD15B167BEB0AD445", @"452478AFEE3CF71AE1ED8EAF43E001A1")]
		[DataRow(@"00000000000400000000000000000000", @"0000000000000000", 16, @"A59CE982636F2C8C912B1E8105E2577D", @"9C86861E61FA3BFF757D74CB9EDE6027")]
		[DataRow(@"00000000000002000000000000000000", @"0000000000000000", 16, @"7A8131B777F7FBFD33A06E396FF32D7D", @"8C3CEEE9573F405F98BD6083FE57BAB6")]
		[DataRow(@"00000000000000010000000000000000", @"0000000000000000", 16, @"FE4DF972E982735FFAEC4D66F929403F", @"7246FB5B2794118493DF068CD310DEB6")]
		[DataRow(@"0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D", @"0D74DB42A91077DE", 16, @"F5FAD53F79F9DF58C4AEA0D0ED9A9601", @"F278112CA7180D565B420A48019670EA")]
		[DataRow(@"0558ABFE51A4F74A9DF04396E93C8FE23588DB2E81D4277ACD2073C6196CBF12", @"167DE44BB21980E7", 16, @"3944F6DC9F85B128083879FDF190F7DE", @"E4053A07BC09896D51D0690BD4DA4AC1")]
		[DataRow(@"0A5DB00356A9FC4FA2F5489BEE4194E73A8DE03386D92C7FD22578CB1E71C417", @"1F86ED54BB2289F0", 30, @"3FE85D5BB1960A82480B5E6F4E965A4460D7A54501664F7D60B54B06100A", @"37FFDCF6BDE5CE3F4886BA77DD5B44E95644E40A8AC65801155DB90F0252")]
		[DataRow(@"0F62B5085BAE0154A7FA4DA0F34699EC3F92E5388BDE3184D72A7DD02376C91C", @"288FF65DC42B92F9", 32, @"5E5E71F90199340304ABB22A37B6625BF883FB89CE3B21F54A10B81066EF87DA", @"30B77699AA7379DA595C77DD59542DA208E5954F89E40EB7AA80A84A6176663F")]
		public void Test(string keyHex, string ivHex, int originSize, string hex, string hex2)
		{
			var key = keyHex.FromHex();
			var iv = ivHex.FromHex();
			Test(new BcSalsa20Crypto(key, iv), originSize, hex, hex2);
			Test(new SlowSalsa20Crypto(key, iv), originSize, hex, hex2);
			Test(new IntrinsicsSalsa20Crypto(key, iv), originSize, hex, hex2);
		}
	}
}